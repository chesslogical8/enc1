#![forbid(unsafe_code)]

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256GcmSiv,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use filetime::FileTime;
use fs2::FileExt;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use tempfile::{Builder, NamedTempFile};
use zeroize::{Zeroize, Zeroizing};

use std::{
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    thread,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ---- Constants -------------------------------------------------------------

const KEY_FILE_DEFAULT: &str = "key.key";

const V2_MAGIC: &[u8] = b"AESGCM-SIV"; // [10]
const V2_VERSION: u8 = 2u8;
const ALG_AES256_GCM_SIV: u8 = 1u8;

const NONCE_LEN: usize = 12;
const BASE_NONCE_LEN: usize = 8;
const SALT_LEN: usize = 16;

const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

const V2_HEADER_LEN: usize = 64;
const FLAG_KEY_SOURCE_ARGON2: u16 = 0x0001;

const ARGON2_M_COST_KIB: u32 = 256 * 1024; // 256 MiB
const ARGON2_T_COST: u32 = 2;

// ---- CLI -------------------------------------------------------------------

#[derive(Parser)]
#[command(author, version, about, disable_help_subcommand = true)]
struct Opts {
    /// Force encryption (overrides auto-detection)
    #[arg(long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Force decryption (overrides auto-detection)
    #[arg(long, conflicts_with = "encrypt")]
    decrypt: bool,

    /// Target file
    file: PathBuf,

    /// Write output to this path instead of overwriting the input
    #[arg(long)]
    out: Option<PathBuf>,

    /// Use this key file (must be exactly 32 bytes)
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Derive key from an interactive password prompt (Argon2id) for ENCRYPTION.
    /// (For decryption, the tool auto-detects from header and will prompt if needed.)
    #[arg(long)]
    password: bool,

    /// Chunk size (e.g., 4M, 8M, 1M). Max 64M.
    #[arg(long)]
    chunk_size: Option<String>,

    /// Suppress progress output
    #[arg(long)]
    quiet: bool,

    /// Assume "yes" for prompts that would overwrite outputs
    #[arg(long)]
    yes: bool,
}

#[derive(Copy, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

// ---- Utilities -------------------------------------------------------------

fn parse_size(s: &str) -> Result<usize> {
    let s = s.trim().to_lowercase();
    let (num, mult) = if let Some(rest) = s.strip_suffix('k') {
        (rest, 1024)
    } else if let Some(rest) = s.strip_suffix("kb") {
        (rest, 1024)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix("mb") {
        (rest, 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };
    let n: usize = num.parse().map_err(|_| anyhow!("invalid size: {}", s))?;
    Ok(n.saturating_mul(mult))
}

fn strict_key_perms(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let meta = fs::metadata(_path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o177 != 0 {
            bail!(
                "key file '{}' must not be group/world accessible (suggest 0600)",
                _path.display()
            );
        }
    }
    Ok(())
}

fn derive_key_from_password_raw(
    password: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    lanes: u32,
) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_cost_kib, t_cost, lanes, Some(32))
        .map_err(|e| anyhow!("{:?}", e))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 failure: {:?}", e))?;
    Ok(out)
}

fn read_exact_into<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| anyhow!(e)).map(|_| ())
}

// ---- Header (v2) -----------------------------------------------------------

struct V2Header {
    alg: u8,
    flags: u16,
    chunk_size: u32,
    file_size: u64,
    base_nonce8: [u8; BASE_NONCE_LEN],
    salt16: [u8; SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    lanes: u32,
}

impl V2Header {
    fn to_bytes(&self) -> [u8; V2_HEADER_LEN] {
        let mut buf = [0u8; V2_HEADER_LEN];
        buf[..V2_MAGIC.len()].copy_from_slice(V2_MAGIC);
        let mut off = V2_MAGIC.len();

        buf[off] = V2_VERSION;
        off += 1;
        buf[off] = self.alg;
        off += 1;

        buf[off..off + 2].copy_from_slice(&self.flags.to_le_bytes());
        off += 2;

        buf[off..off + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        off += 4;

        buf[off..off + 8].copy_from_slice(&self.file_size.to_le_bytes());
        off += 8;

        buf[off..off + BASE_NONCE_LEN].copy_from_slice(&self.base_nonce8);
        off += BASE_NONCE_LEN;

        buf[off..off + SALT_LEN].copy_from_slice(&self.salt16);
        off += SALT_LEN;

        buf[off..off + 4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.t_cost.to_le_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.lanes.to_le_bytes());

        buf
    }

    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < V2_HEADER_LEN {
            bail!("v2 header truncated");
        }
        if &buf[..V2_MAGIC.len()] != V2_MAGIC {
            bail!("not a v2 file: bad magic");
        }
        let mut off = V2_MAGIC.len();
        let ver = buf[off];
        off += 1;
        if ver != V2_VERSION {
            bail!("unsupported v2 version: {}", ver);
        }

        let alg = buf[off];
        off += 1;
        if alg != ALG_AES256_GCM_SIV {
            bail!("unsupported algorithm id: {}", alg);
        }

        let flags = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        off += 2;
        let chunk_size = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let file_size = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        off += 8;

        let mut base_nonce8 = [0u8; BASE_NONCE_LEN];
        base_nonce8.copy_from_slice(&buf[off..off + BASE_NONCE_LEN]);
        off += BASE_NONCE_LEN;

        let mut salt16 = [0u8; SALT_LEN];
        salt16.copy_from_slice(&buf[off..off + SALT_LEN]);
        off += SALT_LEN;

        let m_cost_kib = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let t_cost = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let lanes = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());

        Ok(Self {
            alg,
            flags,
            chunk_size,
            file_size,
            base_nonce8,
            salt16,
            m_cost_kib,
            t_cost,
            lanes,
        })
    }
}

// ---- Main ------------------------------------------------------------------

fn main() -> Result<()> {
    let opt = Opts::parse();
    let path = &opt.file;

    // decide mode (auto after peek)
    let mut mode = if opt.encrypt {
        Mode::Encrypt
    } else if opt.decrypt {
        Mode::Decrypt
    } else {
        Mode::Encrypt
    };

    // sanity checks on source path
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat '{}'", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to operate on a symlink: {}", path.display());
    }
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }

    // exclusive lock on source
    let mut locked = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open '{}'", path.display()))?;
    locked
        .try_lock_exclusive()
        .with_context(|| format!("failed to lock '{}'", path.display()))?;

    // snapshot perms/mtime (restore later)
    let orig_perm = meta.permissions();
    let orig_mtime = FileTime::from_last_modification_time(&meta);

    // peek header to auto-detect v2/plaintext
    let mut head = [0u8; V2_HEADER_LEN];
    let head_read: usize;
    {
        let mut rdr = BufReader::new(&mut locked);
        head_read = rdr.read(&mut head).unwrap_or(0);
    }
    // reset cursor so both paths start from offset 0
    locked.seek(SeekFrom::Start(0))?;

    if !opt.encrypt && !opt.decrypt {
        if head_read >= V2_MAGIC.len()
            && head[..V2_MAGIC.len()].ct_eq(V2_MAGIC).unwrap_u8() == 1
        {
            mode = Mode::Decrypt;
        } else {
            mode = Mode::Encrypt;
        }
    }

    // resolve output path and do safety checks
    let out_path = opt.out.as_ref().unwrap_or(path);
    // refuse to write to an existing symlink path
    if let Some(outp) = &opt.out {
        if let Ok(m) = fs::symlink_metadata(outp) {
            if m.file_type().is_symlink() {
                bail!("refusing to write to a symlink output: {}", outp.display());
            }
        }
    }
    // confirm overwrite if writing to a different existing file and --yes not set
    if out_path != path && out_path.exists() && !opt.yes {
        eprint!("Output file '{}' exists. Overwrite? [y/N] ", out_path.display());
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("failed to read confirmation")?;
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            bail!("refusing to overwrite existing output without --yes");
        }
    }

    // create temp in the OUTPUT directory (so rename/persist stays on same fs)
    let dir = out_path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = Builder::new()
        .prefix(".aes-tmp-")
        .tempfile_in(dir)
        .context("failed to create temp file")?;
    let tmp_path = tmp.path().to_owned();

    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("failed to set 0600 on temp file")?;

    // progress bar
    let file_len = meta.len();
    let pb = if opt.quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(file_len);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner} {bytes}/{total_bytes} [{bar:40}] {elapsed}/{eta} {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb
    };

    // key material (filled differently per mode)
    let mut key = [0u8; 32];
    let mut base_nonce8 = [0u8; BASE_NONCE_LEN];
    let mut salt16 = [0u8; SALT_LEN];
    let mut flags: u16 = 0;
    let mut used_password = false;
    let mut used_lanes: u32 = 0;

    match mode {
        Mode::Encrypt => {
            // ENCRYPTION: choose key now
            if let Some(kp) = &opt.keyfile {
                strict_key_perms(kp)?;
                let kb = fs::read(kp)
                    .with_context(|| format!("failed to read key file '{}'", kp.display()))?;
                if kb.len() != 32 {
                    bail!("key file '{}' must be exactly 32 bytes", kp.display());
                }
                key.copy_from_slice(&kb);
            } else if opt.password || std::env::var("AES_PASSWORD").is_ok() {
                used_password = true;

                // dynamic lanes: clamp 1..=4, persist in header
                let lanes = thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1)
                    .clamp(1, 4);
                used_lanes = lanes;

                let password = if let Ok(env_pw) = std::env::var("AES_PASSWORD") {
                    Zeroizing::new(env_pw)
                } else {
                    Zeroizing::new(prompt_password("Password: ").context("failed to read password")?)
                };
                OsRng.fill_bytes(&mut salt16);
                let derived = Zeroizing::new(derive_key_from_password_raw(
                    &password,
                    &salt16,
                    ARGON2_M_COST_KIB,
                    ARGON2_T_COST,
                    lanes,
                )?);
                key.copy_from_slice(&*derived);
                flags |= FLAG_KEY_SOURCE_ARGON2;
            } else {
                let default_key_path =
                    path.parent().unwrap_or_else(|| Path::new(".")).join(KEY_FILE_DEFAULT);
                let kb = fs::read(&default_key_path).with_context(|| {
                    format!("failed to read '{}'", default_key_path.display())
                })?;
                if kb.len() != 32 {
                    bail!("{} must be exactly 32 bytes", default_key_path.display());
                }
                strict_key_perms(&default_key_path)?;
                key.copy_from_slice(&kb);
            }

            // build cipher and run encryption
            let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));

            // refuse to double-encrypt unless explicitly forced
            if head_read >= V2_MAGIC.len()
                && head[..V2_MAGIC.len()].ct_eq(V2_MAGIC).unwrap_u8() == 1
                && !opt.encrypt
            {
                bail!("file already appears to be encrypted – use --encrypt to force");
            }

            OsRng.fill_bytes(&mut base_nonce8);
            let chunk_size = match &opt.chunk_size {
                Some(s) => {
                    let n = parse_size(s)?;
                    if n == 0 || n > MAX_CHUNK_SIZE {
                        bail!("chunk size must be between 1 and {} bytes", MAX_CHUNK_SIZE);
                    }
                    n
                }
                None => DEFAULT_CHUNK_SIZE,
            };

            encrypt_v2(
                &mut locked,
                &mut tmp,
                &cipher,
                &mut key,
                &pb,
                &EncryptionParams {
                    flags,
                    chunk_size: chunk_size as u32,
                    base_nonce8,
                    salt16: if used_password { salt16 } else { [0u8; SALT_LEN] },
                    m_cost_kib: if used_password { ARGON2_M_COST_KIB } else { 0 },
                    t_cost: if used_password { ARGON2_T_COST } else { 0 },
                    lanes: if used_password { used_lanes } else { 0 },
                },
            )?;
        }

        Mode::Decrypt => {
            // DECRYPTION: look at header to decide key source BEFORE loading anything
            if head_read < V2_HEADER_LEN
                || head[..V2_MAGIC.len()].ct_eq(V2_MAGIC).unwrap_u8() == 0
            {
                bail!("file is not in recognised v2 format");
            }
            let hdr_peek = V2Header::parse(&head)?; // sanity parse

            // If key-file encrypted: load keyfile now (either --keyfile or default next to data)
            // If Argon2 flag is set, we DON'T derive here; decrypt_v2 will prompt/derive from header.salt.
            if (hdr_peek.flags & FLAG_KEY_SOURCE_ARGON2) == 0 {
                if let Some(kp) = &opt.keyfile {
                    strict_key_perms(kp)?;
                    let kb = fs::read(kp)
                        .with_context(|| format!("failed to read key file '{}'", kp.display()))?;
                    if kb.len() != 32 {
                        bail!("key file '{}' must be exactly 32 bytes", kp.display());
                    }
                    key.copy_from_slice(&kb);
                } else {
                    let default_key_path =
                        path.parent().unwrap_or_else(|| Path::new(".")).join(KEY_FILE_DEFAULT);
                    let kb = fs::read(&default_key_path).with_context(|| {
                        format!("failed to read '{}'", default_key_path.display())
                    })?;
                    if kb.len() != 32 {
                        bail!("{} must be exactly 32 bytes", default_key_path.display());
                    }
                    strict_key_perms(&default_key_path)?;
                    key.copy_from_slice(&kb);
                }
            }
            decrypt_v2(&mut locked, &mut tmp, &mut key, &pb)?;
        }
    }

    pb.finish_and_clear();

    // ensure data on disk
    tmp.as_file().sync_all()?;

    // On Windows, drop the lock/handle before replacing the target.
    #[cfg(windows)]
    {
        drop(locked);
    }

    // atomic rename/move
    #[cfg(unix)]
    tmp.persist_overwrite(out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    #[cfg(not(unix))]
    {
        // best-effort remove existing target, then persist
        let _ = fs::remove_file(out_path);
        tmp.persist(out_path)
            .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    }

    // best-effort: remove any leftover temp path (in case of partial failures)
    let _ = fs::remove_file(&tmp_path);

    // fsync target & dir
    OpenOptions::new()
        .write(true)
        .open(out_path)?
        .sync_all()?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;

    // restore original permissions / mtime
    fs::set_permissions(out_path, orig_perm)?;
    filetime::set_file_mtime(out_path, orig_mtime)?;

    // wipe key material
    key.zeroize();

    println!(
        "✅ {} → {}",
        match mode {
            Mode::Encrypt => "Encrypted",
            Mode::Decrypt => "Decrypted",
        },
        out_path.display()
    );

    Ok(())
}

// ---- v2 Encrypt/Decrypt ----------------------------------------------------

struct EncryptionParams {
    flags: u16,
    chunk_size: u32,
    base_nonce8: [u8; BASE_NONCE_LEN],
    salt16: [u8; SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    lanes: u32,
}

fn make_chunk_nonce(base: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn encrypt_v2(
    src_locked: &mut File,
    tmp: &mut NamedTempFile,
    cipher: &Aes256GcmSiv,
    key: &mut [u8; 32],
    pb: &ProgressBar,
    p: &EncryptionParams,
) -> Result<()> {
    let file_size = src_locked.metadata()?.len();
    let hdr = V2Header {
        alg: ALG_AES256_GCM_SIV,
        flags: p.flags,
        chunk_size: p.chunk_size,
        file_size,
        base_nonce8: p.base_nonce8,
        salt16: p.salt16,
        m_cost_kib: p.m_cost_kib,
        t_cost: p.t_cost,
        lanes: p.lanes,
    };
    let hdr_bytes = hdr.to_bytes();
    let aad = hdr_bytes.as_slice();

    // write header
    tmp.as_file_mut().write_all(&hdr_bytes)?;

    let chunk_size = p.chunk_size as usize;
    let mut reader = BufReader::new(src_locked);
    reader.seek(SeekFrom::Start(0))?;
    let mut writer = BufWriter::new(tmp.as_file_mut());

    let mut buf = vec![0u8; chunk_size];
    let mut counter: u32 = 0;
    let mut processed: u64 = 0;

    loop {
        // *** FIXED-SIZE CHUNKING ***
        let mut filled = 0usize;
        while filled < chunk_size {
            let n = reader.read(&mut buf[filled..chunk_size])?;
            if n == 0 {
                break; // EOF
            }
            filled += n;
        }
        if filled == 0 {
            break; // no more data
        }

        processed = processed.saturating_add(filled as u64);

        let nonce = make_chunk_nonce(&p.base_nonce8, counter);
        let nonce_ga = GenericArray::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_ga, Payload { msg: &buf[..filled], aad })
            .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

        // Store nonce (deterministic) + ciphertext
        writer.write_all(&nonce)?;
        writer.write_all(&ciphertext)?;
        pb.set_position(processed);

        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    writer.flush()?;
    buf.zeroize();
    key.zeroize(); // paranoia: wipe key post-encrypt

    Ok(())
}

fn decrypt_v2(
    src_locked: &mut File,
    tmp: &mut NamedTempFile,
    key: &mut [u8; 32],
    pb: &ProgressBar,
) -> Result<()> {
    // 1) Read & parse header
    let mut hdr_buf = [0u8; V2_HEADER_LEN];
    {
        let mut r = BufReader::new(&mut *src_locked);
        read_exact_into(&mut r, &mut hdr_buf)?;
    }
    let hdr = V2Header::parse(&hdr_buf)?;
    let aad = &hdr_buf[..];

    // Validate header fields
    if hdr.chunk_size == 0 || hdr.chunk_size as usize > MAX_CHUNK_SIZE {
        bail!("invalid chunk size in header");
    }
    if hdr.flags & !FLAG_KEY_SOURCE_ARGON2 != 0 {
        bail!("unsupported flags in header: 0x{:04x}", hdr.flags);
    }

    // Optional: structural size sanity check vs file length
    let total_len = src_locked.metadata()?.len();
    let chunk_plain = hdr.chunk_size as u64;
    let full_chunks = hdr.file_size / chunk_plain;
    let last_plain = hdr.file_size % chunk_plain;
    let chunks = full_chunks + if last_plain > 0 { 1 } else { 0 };
    let body_len =
        chunks * (NONCE_LEN as u64 + 16) + full_chunks * chunk_plain + last_plain;
    let expected_total = V2_HEADER_LEN as u64 + body_len;
    if total_len != expected_total {
        bail!(
            "encrypted file length ({}) does not match expected structure ({})",
            total_len,
            expected_total
        );
    }

    // 2) If Argon2 was used, derive key now from password+salt in header
    if (hdr.flags & FLAG_KEY_SOURCE_ARGON2) != 0 {
        let password = if let Ok(env_pw) = std::env::var("AES_PASSWORD") {
            Zeroizing::new(env_pw)
        } else {
            Zeroizing::new(prompt_password("Password: ").context("failed to read password")?)
        };
        let derived = Zeroizing::new(derive_key_from_password_raw(
            &password,
            &hdr.salt16,
            hdr.m_cost_kib,
            hdr.t_cost,
            hdr.lanes,
        )?);
        key.copy_from_slice(&*derived);
    }
    // Build cipher using the (possibly re-derived) key
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&*key));

    // 3) Begin reading body right after the header
    let mut rdr = BufReader::new(&mut *src_locked);
    rdr.seek(SeekFrom::Start(V2_HEADER_LEN as u64))?;
    let mut wtr = BufWriter::new(tmp.as_file_mut());

    let total_plain = hdr.file_size;
    let chunk_plain_max = hdr.chunk_size as usize;
    let mut processed: u64 = 0;
    let mut counter: u32 = 0;

    pb.set_length(total_plain);

    loop {
        if processed >= total_plain {
            break;
        }

        // per-chunk nonce
        let mut nonce_on_disk = [0u8; NONCE_LEN];
        match rdr.read_exact(&mut nonce_on_disk) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                bail!("encrypted file truncated or corrupt (missing chunk nonce)");
            }
            Err(e) => return Err(anyhow!(e)).context("failed reading nonce"),
        }

        // Bind chunk order: expected nonce must match base_nonce8||counter
        let expected = make_chunk_nonce(&hdr.base_nonce8, counter);
        if nonce_on_disk
            .as_slice()
            .ct_eq(expected.as_slice())
            .unwrap_u8()
            != 1
        {
            bail!(
                "chunk {} has unexpected nonce (possible reordering/tampering)",
                counter
            );
        }

        // expected sizes
        let remaining_plain = (total_plain - processed) as usize;
        let expect_plain = std::cmp::min(remaining_plain, chunk_plain_max);
        let expect_ct = expect_plain + 16; // GCM-SIV tag

        let mut ct = vec![0u8; expect_ct];
        read_exact_into(&mut rdr, &mut ct)?;

        // decrypt (use the expected nonce)
        let nonce_ga = GenericArray::from_slice(&expected);
        let mut plaintext = cipher
            .decrypt(nonce_ga, Payload { msg: &ct, aad })
            .map_err(|_| anyhow!("decryption failed – wrong key/password or data corrupted"))?;

        wtr.write_all(&plaintext)?;
        processed += plaintext.len() as u64;
        pb.set_position(processed);

        plaintext.zeroize();
        ct.zeroize();

        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    // ensure no trailing garbage (should already be checked by size sanity)
    let mut extra_probe = [0u8; 1];
    match rdr.read(&mut extra_probe) {
        Ok(0) => {}
        Ok(_) => bail!("trailing data after last chunk (file corrupt or wrong format)"),
        Err(e) => return Err(anyhow!(e)).context("error after final chunk"),
    }

    wtr.flush()?;
    key.zeroize();
    Ok(())
}
