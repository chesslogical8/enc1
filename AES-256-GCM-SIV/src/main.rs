#![forbid(unsafe_code)]

use aes_gcm_siv::{
    aead::{AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use filetime::FileTime;
use fs2::FileExt;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use std::{
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rand::{rngs::OsRng, RngCore};
use atomic_write_file::AtomicWriteFile;

// ---- Constants -------------------------------------------------------------

const KEY_FILE_DEFAULT: &str = "key.key";

const MAGIC: &[u8] = b"AESGCM-SIV"; // 10 bytes
const V2_VERSION: u8 = 2u8;
const V3_VERSION: u8 = 3u8;
const ALG_AES256_GCM_SIV: u8 = 1u8;

const NONCE_LEN: usize = 12;
const BASE_NONCE_LEN: usize = 8;
const SALT_LEN: usize = 16;

const TAG_SIZE: usize = 16;

const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

const HEADER_LEN: usize = 64;
const FLAG_KEY_SOURCE_ARGON2: u16 = 0x0001;

// Strong Argon2id defaults
const ARGON2_DEFAULT_M_COST_KIB: u32 = 256 * 1024; // 256 MiB
const ARGON2_DEFAULT_T_COST: u32 = 3;
const ARGON2_DEFAULT_LANES: u32 = 1;

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
    /// For decryption, we auto-detect from header and prompt if needed.
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
    mut password: String,
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
    password.zeroize();
    Ok(out)
}

fn read_exact_into<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| anyhow!(e)).map(|_| ())
}

// ---- Header (v2 / v3 share the same 64-byte size) --------------------------

#[derive(Clone, Debug)]
struct Header {
    version: u8,
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

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        // 64 bytes total (2 bytes reserved at the end)
        let mut buf = [0u8; HEADER_LEN];
        buf[..MAGIC.len()].copy_from_slice(MAGIC);
        let mut off = MAGIC.len();

        buf[off] = self.version; off += 1;
        buf[off] = self.alg;     off += 1;

        buf[off..off + 2].copy_from_slice(&self.flags.to_le_bytes()); off += 2;
        buf[off..off + 4].copy_from_slice(&self.chunk_size.to_le_bytes()); off += 4;
        buf[off..off + 8].copy_from_slice(&self.file_size.to_le_bytes()); off += 8;

        buf[off..off + BASE_NONCE_LEN].copy_from_slice(&self.base_nonce8); off += BASE_NONCE_LEN;
        buf[off..off + SALT_LEN].copy_from_slice(&self.salt16); off += SALT_LEN;

        buf[off..off + 4].copy_from_slice(&self.m_cost_kib.to_le_bytes()); off += 4;
        buf[off..off + 4].copy_from_slice(&self.t_cost.to_le_bytes()); off += 4;
        buf[off..off + 4].copy_from_slice(&self.lanes.to_le_bytes()); // off += 4;

        buf
    }

    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN { bail!("header truncated"); }
        if &buf[..MAGIC.len()] != MAGIC { bail!("bad magic"); }

        let mut off = MAGIC.len();
        let version = buf[off]; off += 1;
        if version != V2_VERSION && version != V3_VERSION {
            bail!("unsupported version: {}", version);
        }
        let alg = buf[off]; off += 1;
        if alg != ALG_AES256_GCM_SIV {
            bail!("unsupported algorithm id: {}", alg);
        }

        let flags = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()); off += 2;
        let chunk_size = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()); off += 4;
        let file_size  = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;

        let mut base_nonce8 = [0u8; BASE_NONCE_LEN];
        base_nonce8.copy_from_slice(&buf[off..off + BASE_NONCE_LEN]); off += BASE_NONCE_LEN;

        let mut salt16 = [0u8; SALT_LEN];
        salt16.copy_from_slice(&buf[off..off + SALT_LEN]); off += SALT_LEN;

        let m_cost_kib = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()); off += 4;
        let t_cost     = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()); off += 4;
        let lanes      = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());

        Ok(Self {
            version, alg, flags, chunk_size, file_size,
            base_nonce8, salt16, m_cost_kib, t_cost, lanes
        })
    }
}

fn make_chunk_nonce(base: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

// ---- Main ------------------------------------------------------------------

fn main() -> Result<()> {
    let opt = Opts::parse();
    let path = &opt.file;

    // choose mode (auto after header peek)
    let mut mode = if opt.encrypt { Mode::Encrypt } else if opt.decrypt { Mode::Decrypt } else { Mode::Encrypt };

    // sanity checks
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat '{}'", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to operate on a symlink: {}", path.display());
    }
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }

    // exclusive lock
    let mut locked = OpenOptions::new()
        .read(true).write(true)
        .open(path)
        .with_context(|| format!("failed to open '{}'", path.display()))?;
    locked.try_lock_exclusive()
        .with_context(|| format!("failed to lock '{}'", path.display()))?;

    // snapshot perms/mtime (restore later)
    let orig_perm = meta.permissions();
    let orig_mtime = FileTime::from_last_modification_time(&meta);

    // peek header to auto-detect v2/v3/plaintext
    let mut head = [0u8; HEADER_LEN];
    let head_read: usize;
    {
        let mut rdr = BufReader::new(&mut locked);
        head_read = rdr.read(&mut head).unwrap_or(0);
    }
    locked.seek(SeekFrom::Start(0))?;

    if !opt.encrypt && !opt.decrypt {
        if head_read >= MAGIC.len() && head[..MAGIC.len()].ct_eq(MAGIC).unwrap_u8() == 1 {
            mode = Mode::Decrypt;
        } else {
            mode = Mode::Encrypt;
        }
    }

    // resolve output path & overwrite policy
    let out_path = opt.out.as_ref().unwrap_or(path);
    if out_path != path && out_path.exists() && !opt.yes {
        bail!("output '{}' exists (use --yes to overwrite)", out_path.display());
    }

    // progress bar
    let file_len = meta.len();
    let pb = if opt.quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(file_len);
        pb.set_style(
            ProgressStyle::with_template("{spinner} {bytes}/{total_bytes} [{bar:40}] {elapsed}/{eta}")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb
    };

    // key material
    let mut key = [0u8; 32];

    match mode {
        Mode::Encrypt => encrypt_v3(&opt, &mut locked, path, out_path, file_len, &pb, &mut key, orig_perm, orig_mtime)?,
        Mode::Decrypt => decrypt_auto(&opt, &mut locked, path, out_path, file_len, &pb, &mut key, orig_perm, orig_mtime)?,
    }

    pb.finish_and_clear();
    Ok(())
}

// ---- Encrypt (v3 format) ---------------------------------------------------

fn encrypt_v3(
    opt: &Opts,
    src_locked: &mut File,
    in_path: &Path,
    out_path: &Path,
    file_len: u64,
    pb: &ProgressBar,
    key: &mut [u8; 32],
    orig_perm: fs::Permissions,
    orig_mtime: FileTime,
) -> Result<()> {
    // refuse to double-encrypt unless explicitly forced
    {
        let mut head = [0u8; HEADER_LEN];
        let n = {
            let mut r = BufReader::new(&mut *src_locked); // reborrow (no move)
            r.read(&mut head).unwrap_or(0)
        };
        src_locked.seek(SeekFrom::Start(0))?;
        if !opt.encrypt && n >= MAGIC.len() && head[..MAGIC.len()].ct_eq(MAGIC).unwrap_u8() == 1 {
            bail!("file already appears encrypted – use --encrypt to force");
        }
    }

    // choose key source
    let mut flags: u16 = 0;
    let mut salt16 = [0u8; SALT_LEN];

    if let Some(kp) = &opt.keyfile {
        strict_key_perms(kp)?;
        let kb = fs::read(kp)
            .with_context(|| format!("failed to read key file '{}'", kp.display()))?;
        if kb.len() != 32 { bail!("key file '{}' must be exactly 32 bytes", kp.display()); }
        key.copy_from_slice(&kb);
    } else if opt.password || std::env::var("AES_PASSWORD").is_ok() {
        let password = if let Ok(env_pw) = std::env::var("AES_PASSWORD") { env_pw }
                       else { prompt_password("Password: ").context("failed to read password")? };
        OsRng.fill_bytes(&mut salt16);
        let derived = derive_key_from_password_raw(
            password,
            &salt16,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_LANES,
        )?;
        key.copy_from_slice(&derived);
        flags |= FLAG_KEY_SOURCE_ARGON2;
    } else {
        let default_key_path = in_path.parent().unwrap_or_else(|| Path::new(".")).join(KEY_FILE_DEFAULT);
        strict_key_perms(&default_key_path)?;
        let kb = fs::read(&default_key_path).with_context(|| {
            format!("failed to read '{}'", default_key_path.display())
        })?;
        if kb.len() != 32 { bail!("{} must be exactly 32 bytes", default_key_path.display()); }
        key.copy_from_slice(&kb);
    }

    // chunk size
    let chunk_size = match &opt.chunk_size {
        Some(s) => {
            let n = parse_size(s)?;
            if n == 0 || n > MAX_CHUNK_SIZE { bail!("chunk size must be between 1 and {} bytes", MAX_CHUNK_SIZE); }
            n
        },
        None => DEFAULT_CHUNK_SIZE,
    };

    // ensure counter fits u32
    let chunks = if chunk_size == 0 { 0 } else { (file_len + (chunk_size as u64 - 1)) / chunk_size as u64 };
    if chunks > u32::MAX as u64 {
        bail!("file too large for 32-bit chunk counter with chosen chunk size");
    }

    // header v3
    let mut base_nonce8 = [0u8; BASE_NONCE_LEN];
    OsRng.fill_bytes(&mut base_nonce8);

    let hdr = Header {
        version: V3_VERSION,
        alg: ALG_AES256_GCM_SIV,
        flags,
        chunk_size: chunk_size as u32,
        file_size: file_len,
        base_nonce8,
        salt16,
        m_cost_kib: if flags & FLAG_KEY_SOURCE_ARGON2 != 0 { ARGON2_DEFAULT_M_COST_KIB } else { 0 },
        t_cost:     if flags & FLAG_KEY_SOURCE_ARGON2 != 0 { ARGON2_DEFAULT_T_COST } else { 0 },
        lanes:      if flags & FLAG_KEY_SOURCE_ARGON2 != 0 { ARGON2_DEFAULT_LANES } else { 0 },
    };
    let header_bytes = hdr.to_bytes();
    let aad = header_bytes.as_slice();

    // cipher
    let cipher = Aes256GcmSiv::new_from_slice(&*key).expect("valid key len");

    // atomic writer for out path
    let mut out = AtomicWriteFile::options()
        .open(out_path)
        .with_context(|| format!("prepare atomic writer for {}", out_path.display()))?;

    // write header
    out.write_all(&header_bytes)?;

    // stream encrypt
    let mut reader = BufReader::new(&mut *src_locked); // reborrow (no move)
    reader.seek(SeekFrom::Start(0))?;

    let mut buf = vec![0u8; chunk_size];
    let mut counter: u32 = 0;
    let mut processed: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }

        let nonce_bytes = make_chunk_nonce(&base_nonce8, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..n])
            .map_err(|_| anyhow!("encryption failed"))?;

        // Body in v3: ciphertext || tag (no per-chunk nonce stored)
        out.write_all(&buf[..n])?;
        out.write_all(tag.as_slice())?;

        processed = processed.saturating_add(n as u64);
        pb.set_position(processed);

        counter = counter.checked_add(1).ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    // fsync and atomic replace
    out.flush()?;
    out.commit().context("atomic commit failed")?;

    // restore metadata & fsync results
    OpenOptions::new().write(true).open(out_path)?.sync_all()?;
    #[cfg(unix)]
    File::open(out_path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    fs::set_permissions(out_path, orig_perm)?;
    filetime::set_file_mtime(out_path, orig_mtime)?;

    // wipe key
    key.zeroize();
    println!("✅ Encrypted → {}", out_path.display());
    Ok(())
}

// ---- Decrypt (auto v2 or v3) -----------------------------------------------

fn decrypt_auto(
    opt: &Opts,
    src_locked: &mut File,
    in_path: &Path,
    out_path: &Path,
    _file_len: u64,
    pb: &ProgressBar,
    key: &mut [u8; 32],
    orig_perm: fs::Permissions,
    orig_mtime: FileTime,
) -> Result<()> {
    // read & parse header
    let mut hdr_buf = [0u8; HEADER_LEN];
    {
        let mut r = BufReader::new(&mut *src_locked);
        read_exact_into(&mut r, &mut hdr_buf)?;
    }
    let hdr = Header::parse(&hdr_buf)?;
    let aad = &hdr_buf[..];

    // determine key source
    if (hdr.flags & FLAG_KEY_SOURCE_ARGON2) != 0 {
        let password = if let Ok(env_pw) = std::env::var("AES_PASSWORD") {
            env_pw
        } else {
            prompt_password("Password: ").context("failed to read password")?
        };
        let derived = derive_key_from_password_raw(password, &hdr.salt16, hdr.m_cost_kib, hdr.t_cost, hdr.lanes)?;
        key.copy_from_slice(&derived);
    } else {
        // key-file mode: explicit --keyfile or default next to data
        if let Some(kp) = &opt.keyfile {
            strict_key_perms(kp)?;
            let kb = fs::read(kp)
                .with_context(|| format!("failed to read key file '{}'", kp.display()))?;
            if kb.len() != 32 { bail!("key file '{}' must be exactly 32 bytes", kp.display()); }
            key.copy_from_slice(&kb);
        } else {
            let default_key_path = in_path.parent().unwrap_or_else(|| Path::new(".")).join(KEY_FILE_DEFAULT);
            strict_key_perms(&default_key_path)?;
            let kb = fs::read(&default_key_path).with_context(|| {
                format!(
                    "missing key file '{}'; supply --keyfile or use AES_PASSWORD for password-based files",
                    default_key_path.display()
                )
            })?;
            if kb.len() != 32 { bail!("{} must be exactly 32 bytes", default_key_path.display()); }
            key.copy_from_slice(&kb);
        }
    }

    let cipher = Aes256GcmSiv::new_from_slice(&*key).expect("valid key len");

    // atomic writer for out path
    let mut out = AtomicWriteFile::options()
        .open(out_path)
        .with_context(|| format!("prepare atomic writer for {}", out_path.display()))?;

    // stream-decrypt according to version
    match hdr.version {
        V3_VERSION => decrypt_body_v3(src_locked, &mut out, &cipher, &hdr, aad, pb)?,
        V2_VERSION => {
            // Backward-compatible: v2 body was [nonce(12) || ciphertext(tag-appended)] per chunk.
            // NOTE: v2 format is susceptible to chunk-reordering attacks.
            decrypt_body_v2(src_locked, &mut out, &cipher, &hdr, aad, pb)?
        }
        _ => bail!("unsupported version {}", hdr.version),
    }

    out.flush()?;
    out.commit().context("atomic commit failed")?;

    OpenOptions::new().write(true).open(out_path)?.sync_all()?;
    #[cfg(unix)]
    File::open(out_path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    fs::set_permissions(out_path, orig_perm)?;
    filetime::set_file_mtime(out_path, orig_mtime)?;

    key.zeroize();
    println!("✅ Decrypted → {}", out_path.display());
    Ok(())
}

fn decrypt_body_v3(
    src_locked: &mut File,
    out: &mut AtomicWriteFile,
    cipher: &Aes256GcmSiv,
    hdr: &Header,
    aad: &[u8],
    pb: &ProgressBar,
) -> Result<()> {
    let mut rdr = BufReader::new(&mut *src_locked);
    rdr.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let chunk_plain_max = hdr.chunk_size as usize;
    let total_plain = hdr.file_size;

    pb.set_length(total_plain);
    let mut processed: u64 = 0;
    let mut counter: u32 = 0;

    // reuse a buffer sized for max ciphertext + tag
    let mut ct_buf = vec![0u8; chunk_plain_max + TAG_SIZE];

    while processed < total_plain {
        let this_plain = std::cmp::min((total_plain - processed) as usize, chunk_plain_max);
        let this_ct = this_plain + TAG_SIZE;

        // read ciphertext+tag directly
        read_exact_into(&mut rdr, &mut ct_buf[..this_ct])?;

        // split into ct and tag for in-place decryption
        let (ct_part, tag_part) = ct_buf[..this_ct].split_at_mut(this_plain);
        let tag = aes_gcm_siv::Tag::from_slice(tag_part); // <-- fixed: no generics

        let nonce_bytes = make_chunk_nonce(&hdr.base_nonce8, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt_in_place_detached(nonce, aad, ct_part, tag)
            .map_err(|_| anyhow!("decryption failed – wrong key/password or data corrupted"))?;

        out.write_all(ct_part)?;
        processed += this_plain as u64;
        pb.set_position(processed);

        counter = counter.checked_add(1).ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    Ok(())
}

fn decrypt_body_v2(
    src_locked: &mut File,
    out: &mut AtomicWriteFile,
    cipher: &Aes256GcmSiv,
    hdr: &Header,
    aad: &[u8],
    pb: &ProgressBar,
) -> Result<()> {
    let mut rdr = BufReader::new(&mut *src_locked);
    rdr.seek(SeekFrom::Start(HEADER_LEN as u64))?;

    let chunk_plain_max = hdr.chunk_size as usize;
    let total_plain = hdr.file_size;
    pb.set_length(total_plain);

    let mut processed: u64 = 0;

    while processed < total_plain {
        // per-chunk nonce was stored in v2
        let mut nonce = [0u8; NONCE_LEN];
        match rdr.read_exact(&mut nonce) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => bail!("truncated v2 body (missing nonce)"),
            Err(e) => return Err(anyhow!(e)).context("failed reading v2 nonce"),
        }

        let this_plain = std::cmp::min((total_plain - processed) as usize, chunk_plain_max);
        let this_ct = this_plain + TAG_SIZE;

        let mut ct = vec![0u8; this_ct];
        read_exact_into(&mut rdr, &mut ct)?;

        let nonce = Nonce::from_slice(&nonce);
        let mut plaintext = ct; // decrypt in-place by aliasing
        let (pt, tag_part) = plaintext.split_at_mut(this_plain);
        let tag = aes_gcm_siv::Tag::from_slice(tag_part); // <-- fixed

        cipher
            .decrypt_in_place_detached(nonce, aad, pt, tag)
            .map_err(|_| anyhow!("decryption failed – wrong key/password or corrupt v2 file"))?;

        out.write_all(pt)?;
        processed += pt.len() as u64;
        pb.set_position(processed);
    }

    // ensure no trailing garbage
    let mut probe = [0u8; 1];
    match rdr.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => bail!("trailing data after last v2 chunk (file corrupt)"),
        Err(e) => return Err(anyhow!(e)).context("error after final chunk"),
    }

    Ok(())
}
