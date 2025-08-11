use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt; // for .mode(0o600) on Unix
use std::path::{Path, PathBuf};

use anyhow::{Result, Context, bail};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha512;
use tempfile::{Builder as TempBuilder, NamedTempFile};
use threefish::cipher::BlockEncrypt;
use threefish::Threefish1024;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"TF1024\0\x01";
const VERSION: u16 = 1;

// header layout sizes
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 2 + 2 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + 8;
const TAG_LEN: usize = 32;

// limits / defaults
const MIN_CHUNK: usize = 128;                     // one Threefish block
const MAX_CHUNK: usize = 8 * 1024 * 1024;         // 8 MiB cap to bound memory
const DEFAULT_CHUNK: usize = 1 * 1024 * 1024;     // 1 MiB

// key schedule sizes (per-file subkeys)
const ENC_KEY_LEN: usize = 128; // Threefish-1024 key
const MAC_KEY_LEN: usize = 64;  // HMAC-SHA512 key (full 64 bytes, we truncate tag to 32)

// ids
const KDF_ID_HKDF_SHA512: u8 = 0x01;
const MAC_ID_LEGACY: u8 = 0x01; // header || aad || ct (no framing)
const MAC_ID_FRAMED: u8 = 0x02; // header || "domain" || aad_len_le64 || aad || ct
const AAD_FRAMING_DOMAIN: &[u8] = b"tf1024/aad-len-le64";

type HmacSha512 = Hmac<Sha512>;

#[derive(Parser, Debug)]
#[command(name="tf1024", about="Threefish-1024 file encryption (HKDF+EtM, key-file based)")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a random key file
    GenKey {
        /// Path to write the key file (binary). Default: tf1024.key
        #[arg(short='o', long, default_value="tf1024.key")]
        out: PathBuf,
        /// Number of random bytes to generate (recommended: 128)
        #[arg(short='n', long, default_value_t=128)]
        bytes: usize,
        /// Refuse to overwrite existing file
        #[arg(long)]
        no_overwrite: bool,
    },

    /// Encrypt a file
    Encrypt {
        /// Master key file path (binary)
        #[arg(short='k', long)]
        key: PathBuf,
        /// Input file to encrypt
        #[arg(short='i', long)]
        input: PathBuf,
        /// Output file (omit with --inplace)
        #[arg(short='o', long)]
        output: Option<PathBuf>,
        /// Optional AAD file to authenticate (not encrypted)
        #[arg(long)]
        aad: Option<PathBuf>,
        /// Chunk size in KiB (must be multiple of 128 bytes). Default 1024 KiB
        #[arg(long, default_value_t=DEFAULT_CHUNK / 1024)]
        chunk_kib: usize,
        /// Encrypt in place (atomic replace via tmp file)
        #[arg(long)]
        inplace: bool,
        /// Allow overwriting output file
        #[arg(long)]
        overwrite: bool,
    },

    /// Decrypt a file
    Decrypt {
        /// Master key file path (binary)
        #[arg(short='k', long)]
        key: PathBuf,
        /// Input file to decrypt
        #[arg(short='i', long)]
        input: PathBuf,
        /// Output file (omit with --inplace)
        #[arg(short='o', long)]
        output: Option<PathBuf>,
        /// Optional AAD file (must match what was used at encryption)
        #[arg(long)]
        aad: Option<PathBuf>,
        /// Decrypt in place (atomic replace via tmp file)
        #[arg(long)]
        inplace: bool,
        /// Allow overwriting output file
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Clone, Copy)]
struct Header {
    version: u16,
    flags: u16,
    kdf_id: u8,
    mac_id: u8,
    chunk_size: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn new(chunk_size: usize) -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        Header {
            version: VERSION,
            flags: 0,
            kdf_id: KDF_ID_HKDF_SHA512, // HKDF-SHA512
            mac_id: MAC_ID_FRAMED,      // use framed AAD by default
            chunk_size: chunk_size as u32,
            salt,
            nonce,
        }
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&[self.kdf_id])?;
        w.write_all(&[self.mac_id])?;
        w.write_all(&self.chunk_size.to_le_bytes())?;
        w.write_all(&self.salt)?;
        w.write_all(&self.nonce)?;
        w.write_all(&[0u8; 8])?; // reserved
        Ok(())
    }

    fn read<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC { bail!("bad magic"); }

        let mut v = [0u8; 2];
        r.read_exact(&mut v)?;
        let version = u16::from_le_bytes(v);
        if version != VERSION { bail!("unsupported version {}", version); }

        let mut flags_b = [0u8; 2];
        r.read_exact(&mut flags_b)?;
        let flags = u16::from_le_bytes(flags_b);
        if flags != 0 { bail!("unsupported flags: {:#x}", flags); }

        let mut kdf_id_b = [0u8; 1]; r.read_exact(&mut kdf_id_b)?;
        let kdf_id = kdf_id_b[0];
        if kdf_id != KDF_ID_HKDF_SHA512 { bail!("unsupported kdf_id {}", kdf_id); }

        let mut mac_id_b = [0u8; 1]; r.read_exact(&mut mac_id_b)?;
        let mac_id = mac_id_b[0];
        if mac_id != MAC_ID_LEGACY && mac_id != MAC_ID_FRAMED {
            bail!("unsupported mac_id {}", mac_id);
        }

        let mut cs = [0u8; 4]; r.read_exact(&mut cs)?;
        let chunk_size = u32::from_le_bytes(cs) as usize;
        validate_chunk_size(chunk_size)?;

        let mut salt = [0u8; SALT_LEN]; r.read_exact(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN]; r.read_exact(&mut nonce)?;

        // reserved
        let mut reserved = [0u8; 8]; r.read_exact(&mut reserved)?;
        if reserved != [0u8; 8] { bail!("reserved bytes not zero"); }

        Ok(Header {
            version,
            flags,
            kdf_id,
            mac_id,
            chunk_size: chunk_size as u32,
            salt,
            nonce,
        })
    }
}

fn validate_chunk_size(chunk: usize) -> Result<()> {
    if chunk < MIN_CHUNK || chunk > MAX_CHUNK || (chunk % 128) != 0 {
        bail!("invalid chunk size: {} (must be 128..{} and multiple of 128)",
              chunk, MAX_CHUNK);
    }
    Ok(())
}

/// Derive per-file subkeys from a master key and header salt.
fn derive_subkeys(master_key: &[u8], salt: &[u8; SALT_LEN])
    -> Result<([u8; ENC_KEY_LEN], [u8; MAC_KEY_LEN])>
{
    if master_key.len() < 32 {
        bail!("master key file must be at least 32 bytes (recommended: 128)");
    }
    let hk = Hkdf::<Sha512>::new(Some(salt), master_key);

    let mut enc_key = [0u8; ENC_KEY_LEN];
    hk.expand(b"tf1024/v1 enc key", &mut enc_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand enc_key failed"))?;

    let mut mac_key = [0u8; MAC_KEY_LEN];
    hk.expand(b"tf1024/v1 mac key", &mut mac_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand mac_key failed"))?;

    Ok((enc_key, mac_key))
}

/// Build a keystream block by encrypting a structured 128-byte counter block.
#[inline]
fn keystream_block(cipher: &Threefish1024, nonce: &[u8; NONCE_LEN], block_index: u64) -> [u8; 128] {
    let mut ctr = [0u8; 128];
    // Layout:
    // [ 0..16 )  : nonce
    // [16..24 )  : block_index (LE)
    // [24..128)  : zeros
    ctr[..NONCE_LEN].copy_from_slice(nonce);
    ctr[16..24].copy_from_slice(&block_index.to_le_bytes());
    let mut ga = ctr.into();
    cipher.encrypt_block(&mut ga);
    ga.into()
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Command::GenKey{ out, bytes, no_overwrite } => gen_key(&out, bytes, no_overwrite),
        Command::Encrypt{ key, input, output, aad, chunk_kib, inplace, overwrite } => {
            let chunk_size = chunk_kib * 1024;
            validate_chunk_size(chunk_size)?;
            encrypt_file(&key, &input, output.as_ref(), aad.as_ref(), chunk_size, inplace, overwrite)
        }
        Command::Decrypt{ key, input, output, aad, inplace, overwrite } => {
            decrypt_file(&key, &input, output.as_ref(), aad.as_ref(), inplace, overwrite)
        }
    }
}

fn gen_key(out: &Path, bytes: usize, no_overwrite: bool) -> Result<()> {
    if bytes < 32 {
        bail!("key size must be at least 32 bytes (recommended: 128)");
    }

    let mut builder = OpenOptions::new();
    builder.write(true);
    if no_overwrite {
        builder.create_new(true);
    } else {
        builder.create(true).truncate(true);
    }
    #[cfg(unix)]
    { builder.mode(0o600); }

    let mut f = builder
        .open(out)
        .with_context(|| format!("create key {}", out.display()))?;
    let mut key = vec![0u8; bytes];
    OsRng.fill_bytes(&mut key);
    f.write_all(&key)?;
    f.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))?;
    }
    // Zeroize the buffer now that it's written.
    key.zeroize();
    eprintln!("Wrote {} random bytes to {}", bytes, out.display());
    Ok(())
}

fn read_entire(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

/// Update HMAC with header and, depending on mac_id, with (framed) AAD contents.
fn mac_update_header_and_aad(
    mac: &mut HmacSha512,
    hdr: &Header,
    aad_path: Option<&Path>,
) -> Result<()> {
    mac.update(&serialize_header_for_mac(hdr));

    match hdr.mac_id {
        MAC_ID_LEGACY => {
            if let Some(path) = aad_path {
                let mut r = BufReader::new(File::open(path)
                    .with_context(|| format!("open AAD {}", path.display()))?);
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 { break; }
                    mac.update(&buf[..n]);
                }
            }
        }
        MAC_ID_FRAMED => {
            mac.update(AAD_FRAMING_DOMAIN);
            let len: u64 = if let Some(path) = aad_path {
                let md = fs::metadata(path)
                    .with_context(|| format!("stat AAD {}", path.display()))?;
                if !md.is_file() {
                    bail!("AAD must be a regular file: {}", path.display());
                }
                md.len()
            } else {
                0
            };
            mac.update(&len.to_le_bytes());
            if let Some(path) = aad_path {
                let mut r = BufReader::new(File::open(path)
                    .with_context(|| format!("open AAD {}", path.display()))?);
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 { break; }
                    mac.update(&buf[..n]);
                }
            }
        }
        other => bail!("unsupported mac_id {}", other),
    }

    Ok(())
}

fn encrypt_file(
    key_path: &Path,
    input_path: &Path,
    output_path: Option<&PathBuf>,
    aad_path: Option<&PathBuf>,
    chunk_size: usize,
    inplace: bool,
    overwrite: bool,
) -> Result<()> {
    if inplace && output_path.is_some() {
        bail!("--inplace and --output are mutually exclusive");
    }

    // Read master key into an auto-zeroizing buffer.
    let master_key = Zeroizing::new(read_entire(key_path)?);

    // Determine destination and temp dir (use destination's parent for atomicity).
    let dest_path: PathBuf = if inplace {
        input_path.to_path_buf()
    } else if let Some(out_path) = output_path {
        out_path.to_path_buf()
    } else {
        // default output path: input + ".tf"
        let mut outp = input_path.to_path_buf();
        let appended = format!("{}.tf", input_path.file_name().unwrap().to_string_lossy());
        outp.set_file_name(appended);
        outp
    };
    let parent = dest_path.parent().unwrap_or(Path::new("."));

    // Prepare IO
    let in_f = File::open(input_path).with_context(|| format!("open {}", input_path.display()))?;
    let mut tmp: NamedTempFile = TempBuilder::new().prefix(".tf1024~").tempfile_in(parent)?;
    let mut out = BufWriter::new(tmp.as_file_mut());

    // Header + per-file keys
    let hdr = Header::new(chunk_size);
    let (mut enc_key, mut mac_key) = derive_subkeys(&master_key, &hdr.salt)?;

    let cipher = Threefish1024::new_with_tweak((&enc_key).into(), &hdr.nonce);

    // Write header
    hdr.write(&mut out)?;

    // Initialize HMAC over (header || [framed aad] || ciphertext)
    let mut mac = HmacSha512::new_from_slice(&mac_key)
        .map_err(|_| anyhow::anyhow!("failed to init HMAC"))?;
    mac_update_header_and_aad(&mut mac, &hdr, aad_path.map(|p| p.as_path()))?;

    // Stream-encrypt
    let mut rdr = BufReader::new(in_f);
    let mut buf = vec![0u8; chunk_size];
    let mut block_index: u64 = 0;
    loop {
        let read_n = read_full_chunk_or_eof(&mut rdr, &mut buf)?;
        if read_n == 0 { break; }
        let mut off = 0usize;
        while off < read_n {
            let take = (read_n - off).min(128);
            let ks = keystream_block(&cipher, &hdr.nonce, block_index);
            for i in 0..take {
                buf[off + i] ^= ks[i];
            }
            off += take;
            block_index = block_index.wrapping_add(1);
        }
        out.write_all(&buf[..read_n])?;
        mac.update(&buf[..read_n]);
    }

    // Final tag (truncate to 32)
    let tag_full = mac.finalize().into_bytes(); // 64 bytes
    out.write_all(&tag_full[..TAG_LEN])?;
    out.flush()?; // flush BufWriter before syncing & moving
    drop(out);

    // Zeroize sensitive
    enc_key.zeroize();
    mac_key.zeroize();
    // master_key is auto-zeroized on drop

    // Finalize output atomically (handles Windows/Unix differences)
    finish_tmp(tmp, &dest_path, overwrite)?;

    Ok(())
}

fn decrypt_file(
    key_path: &Path,
    input_path: &Path,
    output_path: Option<&PathBuf>,
    aad_path: Option<&PathBuf>,
    inplace: bool,
    overwrite: bool,
) -> Result<()> {
    if inplace && output_path.is_some() {
        bail!("--inplace and --output are mutually exclusive");
    }

    // Read master key into an auto-zeroizing buffer.
    let master_key = Zeroizing::new(read_entire(key_path)?);

    // Determine destination and temp dir (use destination's parent for atomicity).
    let dest_path: PathBuf = if inplace {
        input_path.to_path_buf()
    } else if let Some(out_path) = output_path {
        out_path.to_path_buf()
    } else {
        // default output path: strip trailing ".tf" if present; else add ".dec"
        let mut outp = input_path.to_path_buf();
        let stem = input_path.file_name().unwrap().to_string_lossy();
        let default = if let Some(stripped) = stem.strip_suffix(".tf") {
            stripped.to_string()
        } else {
            format!("{}.dec", stem)
        };
        outp.set_file_name(default);
        outp
    };
    let parent = dest_path.parent().unwrap_or(Path::new("."));

    // Prepare IO
    let mut in_f = File::open(input_path).with_context(|| format!("open {}", input_path.display()))?;
    let mut tmp: NamedTempFile = TempBuilder::new().prefix(".tf1024~").tempfile_in(parent)?;
    let mut out = BufWriter::new(tmp.as_file_mut());

    // Read header
    let hdr = Header::read(&mut in_f)?;
    let (mut enc_key, mut mac_key) = derive_subkeys(&master_key, &hdr.salt)?;

    // File length sanity
    let file_len = in_f.metadata()?.len(); // u64
    let header_and_tag = (HEADER_LEN + TAG_LEN) as u64;
    let ct_len_u64 = file_len.checked_sub(header_and_tag)
        .ok_or_else(|| anyhow::anyhow!("file too short"))?;

    // Read tag (last 32 bytes)
    let mut tag = [0u8; TAG_LEN];
    in_f.seek(SeekFrom::End(-(TAG_LEN as i64)))?;
    in_f.read_exact(&mut tag)?;

    // MAC verify over (header || [framed aad] || ciphertext)
    let mut mac = HmacSha512::new_from_slice(&mac_key)
        .map_err(|_| anyhow::anyhow!("failed to init HMAC"))?;
    mac_update_header_and_aad(&mut mac, &hdr, aad_path.map(|p| p.as_path()))?;

    // Stream the ciphertext into MAC
    let mut rdr = BufReader::new(File::open(input_path)?);
    rdr.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut buf = vec![0u8; hdr.chunk_size as usize];
    let mut remaining = ct_len_u64;
    while remaining > 0 {
        let to_read = if remaining > buf.len() as u64 {
            buf.len()
        } else {
            remaining as usize
        };
        rdr.read_exact(&mut buf[..to_read])?;
        mac.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }
    // Compute full HMAC and constant-time compare the first TAG_LEN bytes
    let calc_full = mac.finalize().into_bytes(); // 64 bytes
    if !ct_eq(&calc_full[..TAG_LEN], &tag) {
        bail!("authentication failed");
    }

    // If we got here, MAC is valid; now decrypt
    let cipher = Threefish1024::new_with_tweak((&enc_key).into(), &hdr.nonce);
    let mut rdr_dec = BufReader::new(File::open(input_path)?);
    rdr_dec.seek(SeekFrom::Start(HEADER_LEN as u64))?;

    let mut block_index: u64 = 0;
    let mut left = ct_len_u64;
    while left > 0 {
        let to_read = if left > buf.len() as u64 {
            buf.len()
        } else {
            left as usize
        };
        rdr_dec.read_exact(&mut buf[..to_read])?;
        let mut off = 0usize;
        while off < to_read {
            let take = (to_read - off).min(128);
            let ks = keystream_block(&cipher, &hdr.nonce, block_index);
            for i in 0..take {
                buf[off + i] ^= ks[i];
            }
            off += take;
            block_index = block_index.wrapping_add(1);
        }
        out.write_all(&buf[..to_read])?;
        left -= to_read as u64;
    }

    out.flush()?; // flush BufWriter before syncing & moving
    drop(out);

    // Zeroize sensitive
    enc_key.zeroize();
    mac_key.zeroize();
    // master_key is auto-zeroized on drop

    // Finalize output
    finish_tmp(tmp, &dest_path, overwrite)?;

    Ok(())
}

/// Serialize exactly what we MAC from the header (identical fields written).
fn serialize_header_for_mac(h: &Header) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN);
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&h.version.to_le_bytes());
    v.extend_from_slice(&h.flags.to_le_bytes());
    v.push(h.kdf_id);
    v.push(h.mac_id);
    v.extend_from_slice(&h.chunk_size.to_le_bytes());
    v.extend_from_slice(&h.salt);
    v.extend_from_slice(&h.nonce);
    v.extend_from_slice(&[0u8; 8]); // reserved
    debug_assert_eq!(v.len(), HEADER_LEN);
    v
}

/// Read at most buf.len() bytes; returns 0 at EOF.
fn read_full_chunk_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        match r.read(&mut buf[done..])? {
            0 => break,
            n => done += n,
        }
    }
    Ok(done)
}

/// Constant-time equality for tags.
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Atomically move a completed temp file into place.
/// - fsyncs file first
/// - on Windows: deletes destination if overwriting, then `persist`
/// - on Unix: atomic `rename` and disarm temp-path drop; fsync parent dir (best-effort)
fn finish_tmp(mut tmp: NamedTempFile, final_path: &Path, overwrite: bool) -> Result<()> {
    // ensure data hits disk first
    tmp.as_file().sync_all().context("sync temp file")?;

    #[cfg(target_os = "windows")]
    {
        if overwrite && final_path.exists() {
            fs::remove_file(final_path).ok();
        }
        tmp.persist(final_path)
            .with_context(|| format!("persist to {}", final_path.display()))?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        if final_path.exists() && !overwrite {
            bail!("output file exists: {} (use --overwrite)", final_path.display());
        }
        let tpath = tmp.into_temp_path();
        fs::rename(&tpath, final_path)
            .with_context(|| format!("replace {}", final_path.display()))?;
        // Disarm deletion of the (now-stale) temp path to avoid TOCTOU deletes.
        let _ = tpath.keep();
        // Best-effort: fsync parent directory so the rename is durable.
        if let Some(dir) = final_path.parent() {
            if let Ok(dirf) = File::open(dir) {
                let _ = dirf.sync_all();
            }
        }
    }

    Ok(())
}
