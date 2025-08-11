use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{ArgAction, Parser};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use sha2::Sha256;
use serpent::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as SerpentKeyInit};
use serpent::Serpent;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"SRP1";
const FORMAT_VERSION: u8 = 1;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;
const SALT_LEN: usize = 16;
const IV_LEN: usize = BLOCK_SIZE;

// Default Argon2 params (stored in header, so future changes won't break old files)
const DEF_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const DEF_T_COST: u32 = 3;
const DEF_P_LANES: u32 = 1;

const IO_CHUNK: usize = 64 * 1024;

#[derive(Parser, Debug)]
#[command(name = "serpent1", version, about = "Serpent-CBC + HMAC file encryptor")]
struct Cli {
    /// Encrypt (use with -i/-o)
    #[arg(short = 'e', long = "encrypt", conflicts_with = "decrypt")]
    encrypt: bool,

    /// Decrypt (use with -i/-o)
    #[arg(short = 'd', long = "decrypt", conflicts_with = "encrypt")]
    decrypt: bool,

    /// Input file path, or "-" for stdin
    #[arg(short = 'i', long = "in")]
    input: Option<String>,

    /// Output file path, or "-" for stdout
    #[arg(short = 'o', long = "out")]
    output: Option<String>,

    /// Edit the input file in-place (atomic)
    #[arg(long = "in-place", action = ArgAction::SetTrue)]
    in_place: bool,

    /// Overwrite output if it exists
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mode = match (cli.encrypt, cli.decrypt) {
        (true, false) => Mode::Encrypt,
        (false, true) => Mode::Decrypt,
        _ => {
            eprintln!("Specify exactly one of --encrypt or --decrypt.");
            std::process::exit(2);
        }
    };

    let (input, output, in_place) = plan_io(&cli)?;

    // Password (twice if encrypting)
    let password = if matches!(mode, Mode::Encrypt) {
        let mut pw1 = prompt_password("Enter password: ")?;
        let mut pw2 = prompt_password("Confirm password: ")?;
        if pw1 != pw2 {
            pw1.zeroize();
            pw2.zeroize();
            bail!("Passwords do not match.");
        }
        pw2.zeroize();
        pw1
    } else {
        prompt_password("Enter password: ")?
    };

    // Do the work
    let res = match mode {
        Mode::Encrypt => encrypt_path(&input, &output, in_place, &password, cli.force),
        Mode::Decrypt => decrypt_path(&input, &output, in_place, &password, cli.force),
    };

    // Wipe password
    let mut pw = password;
    pw.zeroize();

    res?;

    eprintln!(
        "{}ion successful: {}",
        if matches!(mode, Mode::Encrypt) { "Encrypt" } else { "Decrypt" },
        output
            .as_deref()
            .unwrap_or_else(|| input.as_deref().unwrap_or("-"))
    );

    Ok(())
}

#[derive(Copy, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn plan_io(cli: &Cli) -> Result<(Option<String>, Option<String>, bool)> {
    match (cli.input.as_deref(), cli.output.as_deref(), cli.in_place) {
        (Some("-"), Some("-"), _) => Ok((Some("-".into()), Some("-".into()), false)),
        (Some("-"), None, false) => Ok((Some("-".into()), Some("-".into()), false)),
        (Some("-"), _, true) => bail!("--in-place is not allowed with stdin input"),
        (None, Some("-"), false) => Ok((Some("-".into()), Some("-".into()), false)),
        (None, None, true) => bail!("--in-place requires --in"),
        (Some(inp), None, true) => Ok((Some(inp.into()), None, true)),
        (Some(inp), Some(out), false) => Ok((Some(inp.into()), Some(out.into()), false)),
        (Some(_), Some(_), true) => bail!("--in-place conflicts with --out"),
        (None, Some(_), true) => bail!("--in-place requires --in"),
        (None, None, false) => bail!("Specify at least --in or use - for stdin/stdout"),
        _ => bail!("Invalid input/output/in-place combination"),
    }
}

//
// ----- File format -----
//
// [ magic(4) | version(1) |
//   m_cost_kib(u32 LE) | t_cost(u32 LE) | p_lanes(u32 LE) |
//   salt_len(u8=16) | iv_len(u8=16) |
//   salt(16) | iv(16) |
//   ciphertext(...) | tag(32)
// ]
//

fn write_header<W: Write + ?Sized>(
    w: &mut W,
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    salt: &[u8; SALT_LEN],
    iv: &[u8; IV_LEN],
) -> Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&[FORMAT_VERSION])?;

    w.write_all(&m_cost_kib.to_le_bytes())?;
    w.write_all(&t_cost.to_le_bytes())?;
    w.write_all(&p_lanes.to_le_bytes())?;

    w.write_all(&[SALT_LEN as u8])?;
    w.write_all(&[IV_LEN as u8])?;

    w.write_all(salt)?;
    w.write_all(iv)?;
    Ok(())
}

struct Header {
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    salt: [u8; SALT_LEN],
    iv: [u8; IV_LEN],
    header_len: u64,
}

fn read_header<R: Read>(mut r: R) -> Result<Header> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("Invalid magic; not a SRP1 file");
    }
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver)?;
    if ver[0] != FORMAT_VERSION {
        bail!("Unsupported version: {}", ver[0]);
    }

    let mut u32buf = [0u8; 4];
    r.read_exact(&mut u32buf)?;
    let m_cost_kib = u32::from_le_bytes(u32buf);
    r.read_exact(&mut u32buf)?;
    let t_cost = u32::from_le_bytes(u32buf);
    r.read_exact(&mut u32buf)?;
    let p_lanes = u32::from_le_bytes(u32buf);

    let mut lens = [0u8; 2];
    r.read_exact(&mut lens)?;
    if lens[0] as usize != SALT_LEN || lens[1] as usize != IV_LEN {
        bail!("Unexpected salt/iv length");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    r.read_exact(&mut salt)?;
    r.read_exact(&mut iv)?;

    let header_len = (4 + 1 + 4 + 4 + 4 + 1 + 1 + SALT_LEN + IV_LEN) as u64;

    Ok(Header {
        m_cost_kib,
        t_cost,
        p_lanes,
        salt,
        iv,
        header_len,
    })
}

fn argon2_instance(m_cost_kib: u32, t_cost: u32, p_lanes: u32) -> Result<Argon2<'static>> {
    let params = Params::new(m_cost_kib, t_cost, p_lanes, None)
        .map_err(|e| anyhow!("Invalid Argon2 params: {:?}", e))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn derive_keys(
    argon2: &Argon2<'_>,
    password: &str,
    salt: &[u8; SALT_LEN],
) -> Result<([u8; 32], [u8; 32])> {
    let mut okm = [0u8; 64];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut okm)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc_key.copy_from_slice(&okm[..32]);
    mac_key.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((enc_key, mac_key))
}

fn open_out_file(path: &Path, force: bool) -> Result<File> {
    if path.exists() && !force {
        bail!(
            "Output file exists: {} (use --force to overwrite)",
            path.display()
        );
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600); // secure perms on Unix; ignored on Windows
    }
    opts.open(path)
        .with_context(|| format!("Open output: {}", path.display()))
}

fn atomically_replace(original: &Path, writer: BufWriter<File>, tmp_path: &Path) -> Result<()> {
    writer.into_inner()?.sync_all()?;
    fs::rename(tmp_path, original).with_context(|| "Atomic rename failed")?;
    Ok(())
}

enum IOHandle {
    Stdin(io::Stdin),
    Stdout(io::Stdout),
    Path(PathBuf),
    None,
}

fn path_or_stdio(path: &Option<String>, write: bool) -> Result<IOHandle> {
    match path {
        Some(p) if p == "-" => Ok(if write {
            IOHandle::Stdout(io::stdout())
        } else {
            IOHandle::Stdin(io::stdin())
        }),
        Some(p) => Ok(IOHandle::Path(PathBuf::from(p))),
        None => Ok(IOHandle::None),
    }
}

//
// --------- High-level IO planners ---------
//

fn encrypt_path(
    input: &Option<String>,
    output: &Option<String>,
    in_place: bool,
    password: &str,
    force: bool,
) -> Result<()> {
    match (path_or_stdio(input, false)?, path_or_stdio(output, true)?) {
        (IOHandle::Stdin(stdin), IOHandle::Stdout(mut stdout)) => {
            encrypt_stream(stdin.lock(), &mut stdout, password)
        }
        (IOHandle::Stdin(stdin), IOHandle::Path(outp)) => {
            let mut of = open_out_file(&outp, force)?;
            encrypt_stream(stdin.lock(), &mut of, password)
        }
        (IOHandle::Path(inp), IOHandle::Stdout(mut stdout)) => {
            let f = File::open(&inp).with_context(|| format!("Open input: {}", inp.display()))?;
            encrypt_stream(BufReader::new(f), &mut stdout, password)
        }
        (IOHandle::Path(inp), IOHandle::Path(outp)) => {
            if in_place {
                bail!("--in-place conflicts with explicit --out for encryption");
            }
            let inf = File::open(&inp).with_context(|| format!("Open input: {}", inp.display()))?;
            let mut outf = open_out_file(&outp, force)?;
            encrypt_stream(BufReader::new(inf), &mut outf, password)
        }
        (IOHandle::Path(inp), IOHandle::None) if in_place => {
            // atomic in-place: write to tmp in same dir, then rename
            let inf = File::open(&inp).with_context(|| format!("Open input: {}", inp.display()))?;
            let tmp_path = inp.with_extension("tmp.srp1");
            let tmpf = open_out_file(&tmp_path, true)?;
            let mut writer = BufWriter::new(tmpf);
            encrypt_stream(BufReader::new(inf), &mut writer, password)?;
            atomically_replace(&inp, writer, &tmp_path)
        }
        _ => bail!("Specify output with --out or use --in-place"),
    }
}

fn decrypt_path(
    input: &Option<String>,
    output: &Option<String>,
    in_place: bool,
    password: &str,
    force: bool,
) -> Result<()> {
    match (path_or_stdio(input, false)?, path_or_stdio(output, true)?) {
        // STDIN → STDOUT (no seek): stream ciphertext to temp, verify tag, then decrypt
        (IOHandle::Stdin(stdin), IOHandle::Stdout(mut stdout)) => {
            decrypt_stream_streaming_no_seek(stdin.lock(), &mut stdout, password)
        }
        (IOHandle::Stdin(stdin), IOHandle::Path(outp)) => {
            let mut of = open_out_file(&outp, force)?;
            decrypt_stream_streaming_no_seek(stdin.lock(), &mut of, password)
        }
        // Path → STDOUT (seek available)
        (IOHandle::Path(inp), IOHandle::Stdout(mut stdout)) => {
            let f = File::open(&inp).with_context(|| format!("Open input: {}", inp.display()))?;
            decrypt_stream_verify_then_decrypt(BufReader::new(f), &mut stdout, password)
        }
        // Path → Path (seek available)
        (IOHandle::Path(inp), IOHandle::Path(outp)) => {
            if in_place {
                bail!("--in-place conflicts with explicit --out for decryption");
            }
            let inf = File::open(&inp).with_context(|| format!("Open input: {}", inp.display()))?;
            let mut outf = open_out_file(&outp, force)?;
            decrypt_stream_verify_then_decrypt(BufReader::new(inf), &mut outf, password)
        }
        // In-place decryption (verify first), needs seek
        (IOHandle::Path(inp), IOHandle::None) if in_place => {
            let mut inf = OpenOptions::new()
                .read(true)
                .open(&inp)
                .with_context(|| format!("Open input: {}", inp.display()))?;
            let tmp_path = inp.with_extension("tmp");
            let tmpf = open_out_file(&tmp_path, true)?;
            {
                verify_only(&mut inf, password)?;
                inf.seek(SeekFrom::Start(0))?;
                let mut reader = BufReader::new(inf);
                let mut writer = BufWriter::new(tmpf);
                decrypt_stream_with_verified_header(&mut reader, &mut writer, password)?;
                atomically_replace(&inp, writer, &tmp_path)?;
            }
            Ok(())
        }
        _ => bail!("Specify output with --out or use --in-place"),
    }
}

//
// --------- Encrypt (streaming) ---------
//

fn encrypt_stream<R: Read, W: Write>(mut r: R, w: &mut W, password: &str) -> Result<()> {
    // Prepare header pieces
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let argon2 = argon2_instance(DEF_M_COST_KIB, DEF_T_COST, DEF_P_LANES)?;
    let (mut enc_key, mut mac_key) = derive_keys(&argon2, password, &salt)?;
    let cipher = Serpent::new_from_slice(&enc_key)?;
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&mac_key)
        .context("HMAC init failed")?;

    // Write header (not covered by MAC; we MAC salt|iv|ct)
    write_header(w, DEF_M_COST_KIB, DEF_T_COST, DEF_P_LANES, &salt, &iv)?;

    mac.update(&salt);
    mac.update(&iv);

    // CBC state
    let mut prev_block = iv;

    // Streaming: buffer so we can add PKCS#7 at end
    let mut buf = vec![0u8; IO_CHUNK];
    let mut leftover = Vec::with_capacity(BLOCK_SIZE);

    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut chunk = &buf[..n];

        if !leftover.is_empty() {
            let needed = BLOCK_SIZE - leftover.len();
            if chunk.len() >= needed {
                leftover.extend_from_slice(&chunk[..needed]);
                process_block_encrypt(&cipher, &mut prev_block, &leftover, w, &mut mac)?;
                leftover.clear();
                chunk = &chunk[needed..];
            }
        }

        let full_blocks = chunk.len() / BLOCK_SIZE;
        for i in 0..full_blocks {
            let block = &chunk[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            process_block_encrypt(&cipher, &mut prev_block, block, w, &mut mac)?;
        }
        let rem = &chunk[full_blocks * BLOCK_SIZE..];
        if !rem.is_empty() {
            leftover.extend_from_slice(rem);
        }
    }

    // Final padding
    let pad_len = (BLOCK_SIZE - (leftover.len() % BLOCK_SIZE)) as u8;
    if leftover.is_empty() {
        let block = vec![pad_len; BLOCK_SIZE];
        process_block_encrypt(&cipher, &mut prev_block, &block, w, &mut mac)?;
    } else {
        let mut block = leftover;
        block.extend(std::iter::repeat(pad_len).take((BLOCK_SIZE - block.len()) as usize));
        process_block_encrypt(&cipher, &mut prev_block, &block, w, &mut mac)?;
    }

    // Finalize HMAC
    let tag = mac.finalize().into_bytes();
    w.write_all(&tag)?;

    // Wipe keys
    enc_key.zeroize();
    mac_key.zeroize();

    Ok(())
}

fn process_block_encrypt<W: Write>(
    cipher: &Serpent,
    prev_block: &mut [u8; BLOCK_SIZE],
    plain_block: &[u8],
    w: &mut W,
    mac: &mut HmacSha256,
) -> Result<()> {
    let mut xored = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        xored[i] = plain_block[i] ^ prev_block[i];
    }
    let mut block = Block::<Serpent>::clone_from_slice(&xored);
    cipher.encrypt_block(&mut block);
    let out = block.to_vec();
    *prev_block = out
        .as_slice()
        .try_into()
        .expect("ciphertext block must be 16 bytes");
    w.write_all(&out)?;
    mac.update(&out);
    Ok(())
}

//
// --------- Decrypt (seek-capable; verify then decrypt) ---------
//

fn verify_only<R: Read + Seek>(r: &mut R, password: &str) -> Result<()> {
    // Read header
    let start_pos = r.stream_position()?;
    let hdr = read_header(&mut *r)?;
    let argon2 = argon2_instance(hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
    let (_enc_key, mut mac_key) = derive_keys(&argon2, password, &hdr.salt)?;

    // Determine total length
    let total_len = r.seek(SeekFrom::End(0))?;
    if total_len < hdr.header_len + TAG_SIZE as u64 {
        bail!("Data too short");
    }
    let ct_len = total_len - hdr.header_len - TAG_SIZE as u64;

    // HMAC(salt|iv|ct)
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&mac_key)
        .context("HMAC init failed")?;
    mac.update(&hdr.salt);
    mac.update(&hdr.iv);

    // MAC ciphertext
    r.seek(SeekFrom::Start(hdr.header_len))?;
    let mut remaining = ct_len;
    let mut buf = vec![0u8; IO_CHUNK];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..to_read])?;
        mac.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }

    // Read tag and verify
    r.seek(SeekFrom::Start(hdr.header_len + ct_len))?;
    let mut tag = [0u8; TAG_SIZE];
    r.read_exact(&mut tag)?;
    mac.verify_slice(&tag).context("HMAC verification failed")?;

    // Restore position
    r.seek(SeekFrom::Start(start_pos))?;

    mac_key.zeroize();
    Ok(())
}

fn decrypt_stream_verify_then_decrypt<R: Read + Seek, W: Write>(
    mut r: R,
    w: &mut W,
    password: &str,
) -> Result<()> {
    // First pass: verify MAC
    verify_only(&mut r, password)?;
    // Second pass: actual decryption
    let mut reader = BufReader::new(r);
    decrypt_stream_with_verified_header(&mut reader, w, password)
}

fn decrypt_stream_with_verified_header<R: Read + Seek, W: Write>(
    r: &mut R,
    w: &mut W,
    password: &str,
) -> Result<()> {
    let hdr = read_header(&mut *r)?;
    let argon2 = argon2_instance(hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
    let (mut enc_key, mut _mac_key) = derive_keys(&argon2, password, &hdr.salt)?;

    // Determine total and ct_len
    let total_len = r.seek(SeekFrom::End(0))?;
    if total_len < hdr.header_len + TAG_SIZE as u64 {
        bail!("Data too short");
    }
    let ct_len = total_len - hdr.header_len - TAG_SIZE as u64;
    if ct_len % (BLOCK_SIZE as u64) != 0 {
        bail!("Ciphertext length is not a multiple of block size");
    }

    // Decrypt blocks
    r.seek(SeekFrom::Start(hdr.header_len))?;
    let cipher = Serpent::new_from_slice(&enc_key)?;
    let mut prev_block = hdr.iv;

    let mut remaining = ct_len;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut out_block = [0u8; BLOCK_SIZE];
    let mut last_plain = [0u8; BLOCK_SIZE];
    let mut have_last = false;

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..to_read])?;
        let blocks = to_read / BLOCK_SIZE;
        for i in 0..blocks {
            let ct_block = &buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let mut blk = Block::<Serpent>::clone_from_slice(ct_block);
            cipher.decrypt_block(&mut blk);
            let dec = blk.to_vec();

            for j in 0..BLOCK_SIZE {
                out_block[j] = dec[j] ^ prev_block[j];
            }
            prev_block.copy_from_slice(ct_block);

            if have_last {
                w.write_all(&last_plain)?;
            }
            last_plain.copy_from_slice(&out_block);
            have_last = true;
        }
        remaining -= to_read as u64;
    }

    if !have_last {
        bail!("No ciphertext blocks");
    }

    // Remove PKCS#7 padding
    let pad_len = last_plain[BLOCK_SIZE - 1] as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        bail!("Invalid PKCS#7 padding");
    }
    if !last_plain[BLOCK_SIZE - pad_len..]
        .iter()
        .all(|&b| b as usize == pad_len)
    {
        bail!("Invalid PKCS#7 padding");
    }
    w.write_all(&last_plain[..BLOCK_SIZE - pad_len])?;

    // Wipe keys
    enc_key.zeroize();

    Ok(())
}

//
// --------- Decrypt (no-seek, e.g., stdin): stream to temp, verify, decrypt ---------
//

fn decrypt_stream_streaming_no_seek<R: Read, W: Write>(
    mut r: R,
    w: &mut W,
    password: &str,
) -> Result<()> {
    // Read header from stream
    let hdr = read_header(&mut r)?;
    let argon2 = argon2_instance(hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
    let (mut enc_key, mut mac_key) = derive_keys(&argon2, password, &hdr.salt)?;

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&mac_key)
        .context("HMAC init failed")?;
    mac.update(&hdr.salt);
    mac.update(&hdr.iv);

    // Temp file for ciphertext (since stdin can't seek)
    let tmp_path = make_temp_path()?;
    let mut tmpf = open_out_file(&tmp_path, true)?;

    // Keep the last TAG_SIZE bytes in memory (the tag); MAC and write everything before that.
    let mut ring: Vec<u8> = Vec::with_capacity(TAG_SIZE + IO_CHUNK);
    let mut buf = vec![0u8; IO_CHUNK];

    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ring.extend_from_slice(&buf[..n]);

        if ring.len() > TAG_SIZE {
            let emit = ring.len() - TAG_SIZE;
            tmpf.write_all(&ring[..emit])?;
            mac.update(&ring[..emit]);
            ring.drain(0..emit);
        }
    }

    if ring.len() != TAG_SIZE {
        fs::remove_file(&tmp_path).ok();
        bail!("Data too short (missing tag)");
    }
    let tag = ring; // exactly TAG_SIZE

    // Verify MAC over ciphertext
    mac.verify_slice(&tag).context("HMAC verification failed")?;
    tmpf.sync_all().ok();

    // Ensure ciphertext length is multiple of block size
    let ct_len = tmpf.metadata()?.len();
    if ct_len % (BLOCK_SIZE as u64) != 0 {
        fs::remove_file(&tmp_path).ok();
        bail!("Ciphertext length is not a multiple of block size");
    }

    // Decrypt ciphertext from the temp file
    tmpf.flush().ok();
    drop(tmpf); // close for re-open
    let ct_file = File::open(&tmp_path)?;
    let mut ct_reader = BufReader::new(ct_file);
    decrypt_ct_stream_no_seek(&mut ct_reader, w, &enc_key, &hdr.iv)?;

    // cleanup
    fs::remove_file(&tmp_path).ok();
    enc_key.zeroize();
    mac_key.zeroize();
    Ok(())
}

fn decrypt_ct_stream_no_seek<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    enc_key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<()> {
    let cipher = Serpent::new_from_slice(enc_key)?;
    let mut prev_block = *iv;

    let mut buf = vec![0u8; IO_CHUNK];
    let mut out_block = [0u8; BLOCK_SIZE];
    let mut last_plain = [0u8; BLOCK_SIZE];
    let mut have_last = false;

    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n % BLOCK_SIZE != 0 {
            bail!("Ciphertext chunk not aligned to block size");
        }
        let blocks = n / BLOCK_SIZE;
        for i in 0..blocks {
            let ct_block = &buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let mut blk = Block::<Serpent>::clone_from_slice(ct_block);
            cipher.decrypt_block(&mut blk);
            let dec = blk.to_vec();

            for j in 0..BLOCK_SIZE {
                out_block[j] = dec[j] ^ prev_block[j];
            }
            prev_block.copy_from_slice(ct_block);

            if have_last {
                w.write_all(&last_plain)?;
            }
            last_plain.copy_from_slice(&out_block);
            have_last = true;
        }
    }

    if !have_last {
        bail!("No ciphertext blocks");
    }

    // Strip PKCS#7 padding
    let pad_len = last_plain[BLOCK_SIZE - 1] as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        bail!("Invalid PKCS#7 padding");
    }
    if !last_plain[BLOCK_SIZE - pad_len..]
        .iter()
        .all(|&b| b as usize == pad_len)
    {
        bail!("Invalid PKCS#7 padding");
    }
    w.write_all(&last_plain[..BLOCK_SIZE - pad_len])?;

    Ok(())
}

fn make_temp_path() -> Result<PathBuf> {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut name = String::from("serpent1_tmp_");
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0x0f;
        name.push(hex_digit(hi));
        name.push(hex_digit(lo));
    }
    let mut p = std::env::temp_dir();
    p.push(name);
    Ok(p)
}

fn hex_digit(nybble: u8) -> char {
    match nybble {
        0..=9 => (b'0' + nybble) as char,
        10..=15 => (b'a' + (nybble - 10)) as char,
        _ => '?',
    }
}
