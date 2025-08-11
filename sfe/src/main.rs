use anyhow::{anyhow, bail, ensure, Context, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use std::cmp::min;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder as TempBuilder;
use zeroize::{Zeroize, Zeroizing};
use subtle::ConstantTimeEq;
use fs2::FileExt;

use argon2::{Algorithm, Argon2, Params, Version};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    ReplaceFileW, REPLACEFILE_IGNORE_MERGE_ERRORS, REPLACEFILE_WRITE_THROUGH,
};

const MAGIC: &[u8; 4] = b"SFE1";
const VERSION: u8 = 1;

// Algorithm IDs (reserved for future upgrades).
const ALG_XCHACHA20POLY1305: u8 = 1;
// KDF IDs
const KDF_ARGON2ID: u8 = 1;

// Fixed sizes.
const SALT_LEN: usize = 16;
const NONCE_SEED_LEN: usize = 16; // first 16 bytes of the 24-byte XChaCha nonce
const AEAD_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16; // Poly1305 tag length (fixed)
const HEADER_MAC_LEN: usize = 32;

// Derived header sizes.
const HEADER_FIXED_LEN: usize = 64; // bytes without MAC
const HEADER_LEN: usize = HEADER_FIXED_LEN + HEADER_MAC_LEN;

// Sensible default chunk size: balance I/O and memory.
const DEFAULT_CHUNK_SIZE: usize = 1 << 20; // 1 MiB
// Hard cap for chunk size accepted from files (defense-in-depth).
const MAX_CHUNK_SIZE: usize = 64 << 20; // 64 MiB

// Argon2id defaults (tunable via env).
const DEFAULT_ARGON2_M_KIB: u32 = 256 * 1024; // 256 MiB
const DEFAULT_ARGON2_T_COST: u32 = 3;
// Decryption safety caps (overridable via env SFE_MAX_*).
const DEFAULT_MAX_ARGON2_M_KIB: u32 = 1_048_576; // 1 GiB
const DEFAULT_MAX_ARGON2_T: u32 = 10;
const DEFAULT_MAX_ARGON2_P: u32 = 32;

#[derive(Copy, Clone, Debug)]
struct HeaderV1 {
    // 4 + 1 + 1 + 1 + 1
    magic: [u8; 4],
    version: u8,
    alg_id: u8,
    kdf_id: u8,
    reserved: u8,

    // 4 + 4 + 4
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,

    // 16 + 16
    salt: [u8; SALT_LEN],
    nonce_seed: [u8; NONCE_SEED_LEN],

    // 4 + 8
    chunk_size: u32,
    plaintext_len: u64,

    // 32
    header_mac: [u8; HEADER_MAC_LEN],
}

impl HeaderV1 {
    fn new_placeholder() -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            alg_id: ALG_XCHACHA20POLY1305,
            kdf_id: KDF_ARGON2ID,
            reserved: 0,
            m_cost_kib: DEFAULT_ARGON2_M_KIB,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: min(num_cpus::get() as u32, 8),
            salt: [0u8; SALT_LEN],
            nonce_seed: [0u8; NONCE_SEED_LEN],
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
            plaintext_len: 0,
            header_mac: [0u8; HEADER_MAC_LEN],
        }
    }

    fn to_bytes_without_mac(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_FIXED_LEN);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.push(self.alg_id);
        buf.push(self.kdf_id);
        buf.push(self.reserved);

        buf.extend_from_slice(&self.m_cost_kib.to_le_bytes());
        buf.extend_from_slice(&self.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.p_cost.to_le_bytes());

        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce_seed);

        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf.extend_from_slice(&self.plaintext_len.to_le_bytes());
        debug_assert_eq!(buf.len(), HEADER_FIXED_LEN);
        buf
    }

    fn write_all<W: Write>(&self, mut w: W) -> Result<()> {
        let without_mac = self.to_bytes_without_mac();
        w.write_all(&without_mac)?;
        w.write_all(&self.header_mac)?;
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut fixed = [0u8; HEADER_FIXED_LEN]; // bytes without MAC
        r.read_exact(&mut fixed).context("read fixed header")?;
        let mut mac = [0u8; HEADER_MAC_LEN];
        r.read_exact(&mut mac).context("read header MAC")?;

        let mut idx = 0usize;

        let magic = fixed
            .get(idx..idx + 4)
            .ok_or_else(|| anyhow!("malformed header (magic)"))?;
        let magic = <[u8; 4]>::try_from(magic).map_err(|_| anyhow!("malformed magic"))?;
        idx += 4;

        let version = *fixed.get(idx).ok_or_else(|| anyhow!("malformed version"))?;
        idx += 1;
        let alg_id = *fixed.get(idx).ok_or_else(|| anyhow!("malformed alg_id"))?;
        idx += 1;
        let kdf_id = *fixed.get(idx).ok_or_else(|| anyhow!("malformed kdf_id"))?;
        idx += 1;
        let reserved = *fixed.get(idx).ok_or_else(|| anyhow!("malformed reserved"))?;
        idx += 1;

        if &magic != MAGIC {
            bail!("bad magic");
        }
        if version != VERSION {
            bail!("unsupported version: {}", version);
        }

        let m_cost_kib = fixed
            .get(idx..idx + 4)
            .ok_or_else(|| anyhow!("malformed m_cost_kib"))?;
        let m_cost_kib = u32::from_le_bytes(m_cost_kib.try_into().unwrap());
        idx += 4;

        let t_cost = fixed
            .get(idx..idx + 4)
            .ok_or_else(|| anyhow!("malformed t_cost"))?;
        let t_cost = u32::from_le_bytes(t_cost.try_into().unwrap());
        idx += 4;

        let p_cost = fixed
            .get(idx..idx + 4)
            .ok_or_else(|| anyhow!("malformed p_cost"))?;
        let p_cost = u32::from_le_bytes(p_cost.try_into().unwrap());
        idx += 4;

        let salt_slice = fixed
            .get(idx..idx + SALT_LEN)
            .ok_or_else(|| anyhow!("malformed salt"))?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(salt_slice);
        idx += SALT_LEN;

        let nonce_slice = fixed
            .get(idx..idx + NONCE_SEED_LEN)
            .ok_or_else(|| anyhow!("malformed nonce_seed"))?;
        let mut nonce_seed = [0u8; NONCE_SEED_LEN];
        nonce_seed.copy_from_slice(nonce_slice);
        idx += NONCE_SEED_LEN;

        let chunk_size = fixed
            .get(idx..idx + 4)
            .ok_or_else(|| anyhow!("malformed chunk_size"))?;
        let chunk_size = u32::from_le_bytes(chunk_size.try_into().unwrap());
        idx += 4;

        let plaintext_len = fixed
            .get(idx..idx + 8)
            .ok_or_else(|| anyhow!("malformed plaintext_len"))?;
        let plaintext_len = u64::from_le_bytes(plaintext_len.try_into().unwrap());
        idx += 8;

        debug_assert_eq!(idx, fixed.len());

        Ok(Self {
            magic,
            version,
            alg_id,
            kdf_id,
            reserved,
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
            nonce_seed,
            chunk_size,
            plaintext_len,
            header_mac: mac,
        })
    }
}

// --------- platform atomic replace ----------
#[cfg(unix)]
fn atomic_replace(src: &Path, dest: &Path) -> Result<()> {
    fs::rename(src, dest).with_context(|| format!("rename {:?} -> {:?}", src, dest))?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(src: &Path, dest: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    fn to_w(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    // Replace *dest* with *src*
    let replaced = to_w(dest);
    let replacement = to_w(src);

    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_IGNORE_MERGE_ERRORS | REPLACEFILE_WRITE_THROUGH, // stronger durability
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        bail!(
            "ReplaceFileW failed replacing {:?} with {:?}",
            dest,
            src
        );
    }
    Ok(())
}

fn fsync_file(f: &File) -> Result<()> {
    f.sync_all().context("sync file")
}

#[cfg(unix)]
fn fsync_dir_of(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dirf = File::open(parent).with_context(|| format!("open dir {:?}", parent))?;
        dirf.sync_all().context("sync dir")?;
    }
    Ok(())
}

#[cfg(windows)]
fn fsync_dir_of(_path: &Path) -> Result<()> {
    // ReplaceFileW with WRITE_THROUGH handles metadata flush atomically.
    Ok(())
}

// --------- symlink / reparse-point refusal & no-follow open ----------
#[cfg(unix)]
fn refuse_symlink(path: &Path) -> Result<()> {
    // Early refusal (best-effort); O_NOFOLLOW open will be the hard check.
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {:?}", path))?;
    ensure!(!meta.file_type().is_symlink(), "refusing symlink: {:?}", path);
    ensure!(meta.is_file(), "path is not a regular file: {:?}", path);
    Ok(())
}

#[cfg(unix)]
fn open_file_nofollow_read(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open(no-follow) {:?}", path))?;
    let meta = f.metadata()?;
    ensure!(meta.is_file(), "not a regular file: {:?}", path);
    Ok(f)
}

#[cfg(windows)]
fn refuse_symlink(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {:?}", path))?;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let attrs = meta.file_attributes();
    ensure!(
        attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing reparse point: {:?}",
        path
    );
    ensure!(meta.is_file(), "path is not a regular file: {:?}", path);
    Ok(())
}

#[cfg(windows)]
fn open_file_nofollow_read(path: &Path) -> Result<File> {
    // Windows doesn't have O_NOFOLLOW in the same sense; rely on reparse-point refusal above.
    let f = File::open(path).with_context(|| format!("open {:?}", path))?;
    let meta = f.metadata()?;
    ensure!(meta.is_file(), "not a regular file: {:?}", path);
    Ok(f)
}

// Copy basic permissions (best-effort).
#[cfg(unix)]
fn copy_perms(from: &Path, to_file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(from)?.permissions().mode();
    let mut perms = to_file.metadata()?.permissions();
    perms.set_mode(mode);
    to_file.set_permissions(perms)?;
    Ok(())
}

#[cfg(windows)]
fn copy_perms(from: &Path, to_file: &File) -> Result<()> {
    // Preserve read-only bit at least
    let ro = fs::metadata(from)?.permissions().readonly();
    let mut perms = to_file.metadata()?.permissions();
    perms.set_readonly(ro);
    to_file.set_permissions(perms)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_temp_file_perms(file: &File) -> Result<()> {
    // Make tmp files private ASAP to avoid plaintext exposure windows.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600);
    file.set_permissions(perms)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_temp_file_perms(_file: &File) -> Result<()> {
    // On Windows, tempfile inherits secure defaults/ACLs; nothing extra to do.
    Ok(())
}

fn read_passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let p1 = Zeroizing::new(prompt_password("Passphrase: ")?);
    if p1.is_empty() {
        bail!("empty passphrase refused");
    }
    if confirm {
        let p2 = Zeroizing::new(prompt_password("Confirm passphrase: ")?);
        if *p1 != *p2 {
            bail!("passphrases did not match");
        }
    }
    Ok(p1)
}

// Derive 64 bytes (32 for AEAD, 32 for header MAC key)
fn derive_keys(
    pass: &Zeroizing<String>,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(64))
        .map_err(|e| anyhow!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut out[..])
        .map_err(|e| anyhow!("argon2: {}", e))?;
    let mut k_enc = Zeroizing::new([0u8; 32]);
    let mut k_hdr = Zeroizing::new([0u8; 32]);
    k_enc.copy_from_slice(&out[..32]);
    k_hdr.copy_from_slice(&out[32..64]);
    Ok((k_enc, k_hdr))
}

fn make_chunk_nonce(nonce_seed16: &[u8; NONCE_SEED_LEN], counter: u64) -> XNonce {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[..NONCE_SEED_LEN].copy_from_slice(nonce_seed16);
    nonce[NONCE_SEED_LEN..].copy_from_slice(&counter.to_le_bytes());
    XNonce::from_slice(&nonce).to_owned()
}

fn compute_header_mac(header_without_mac: &[u8], header_key: &[u8; 32]) -> [u8; HEADER_MAC_LEN] {
    let out = blake3::keyed_hash(header_key, header_without_mac);
    let mut mac = [0u8; HEADER_MAC_LEN];
    mac.copy_from_slice(out.as_bytes());
    mac
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn desired_chunk_size() -> usize {
    let mut cs = env_or("SFE_CHUNK_SIZE", DEFAULT_CHUNK_SIZE);
    if cs == 0 {
        cs = DEFAULT_CHUNK_SIZE;
    }
    cs = cs.min(MAX_CHUNK_SIZE);
    cs
}

fn encrypt_in_place(path: &Path) -> Result<()> {
    refuse_symlink(path)?;

    // Open source safely and lock it exclusively to reduce concurrent-writer races.
    let in_f = open_file_nofollow_read(path)?;
    in_f.lock_exclusive().context("lock source file")?;
    let meta = in_f.metadata()?;
    let plaintext_len = meta.len();

    let pass = read_passphrase(true)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_seed = [0u8; NONCE_SEED_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_seed);

    let m_cost = env_or("SFE_ARGON2_M_KIB", DEFAULT_ARGON2_M_KIB);
    let t_cost = env_or("SFE_ARGON2_T", DEFAULT_ARGON2_T_COST).max(1);
    let p_env = env_or("SFE_ARGON2_P", min(num_cpus::get() as u32, 8));
    let p_cost = p_env.clamp(1, DEFAULT_MAX_ARGON2_P);
    let chunk_size = desired_chunk_size();

    let (k_enc, k_hdr) = derive_keys(&pass, &salt, m_cost, t_cost, p_cost)?;
    drop(pass); // zeroized on drop

    let mut header = HeaderV1::new_placeholder();
    header.m_cost_kib = m_cost;
    header.t_cost = t_cost;
    header.p_cost = p_cost;
    header.salt = salt;
    header.nonce_seed = nonce_seed;
    header.chunk_size = chunk_size as u32;
    header.plaintext_len = plaintext_len;

    let header_without_mac = header.to_bytes_without_mac();
    header.header_mac = compute_header_mac(&header_without_mac, &*k_hdr);

    // Create temp file in same dir
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("no parent directory"))?;
    let mut tmp = TempBuilder::new()
        .prefix(".sfe-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .context("create tmp")?;
    restrict_temp_file_perms(tmp.as_file())?;

    // Write header first
    header.write_all(tmp.as_file_mut())?;

    let key = Key::from_slice(&*k_enc);
    let aead = XChaCha20Poly1305::new(key);

    // AAD binds chunks to this file instance.
    let aad_base = header.header_mac; // 32 bytes

    // Encrypt streaming (in-place, detached tag)
    // NOTE: avoid BufReader for plaintext: no extra plaintext copy persists in memory.
    let mut reader = in_f;
    let mut writer = BufWriter::with_capacity(chunk_size, tmp.as_file_mut());
    let mut buf = Zeroizing::new(vec![0u8; chunk_size]);

    let mut remaining: u64 = plaintext_len;
    let mut index: u64 = 0;

    while remaining > 0 {
        // 32-bit safe: compute on u64 first.
        let want_u64 = std::cmp::min(remaining, chunk_size as u64);
        let want = want_u64 as usize;

        reader.read_exact(&mut buf[..want])?;

        let nonce = make_chunk_nonce(&nonce_seed, index);
        let mut aad = [0u8; HEADER_MAC_LEN + 8];
        aad[..HEADER_MAC_LEN].copy_from_slice(&aad_base);
        aad[HEADER_MAC_LEN..].copy_from_slice(&index.to_le_bytes());

        // Encrypt in-place and get detached tag
        let tag: Tag = aead
            .encrypt_in_place_detached(&nonce, &aad, &mut buf[..want])
            .map_err(|_| anyhow!("encryption failure (chunk {})", index))?;

        // Write ciphertext body + tag
        writer.write_all(&buf[..want])?;
        writer.write_all(tag.as_slice())?;

        // Wipe plaintext (now ciphertext) window
        buf[..want].zeroize();

        index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
        remaining = remaining
            .checked_sub(want_u64)
            .ok_or_else(|| anyhow!("underflow tracking remaining bytes"))?;
    }

    // Finish buffered I/O, then drop the writer BEFORE touching tmp.as_file() again.
    writer.flush()?;
    drop(writer);

    // Copy perms late (safer on Windows), then fsync and swap
    copy_perms(path, tmp.as_file())?;
    fsync_file(tmp.as_file())?;

    // Close tmp file handle and turn into a persistent path we can atomically swap in.
    let (tmp_file, tmp_path) = tmp.keep().map_err(|e| anyhow!("persist tmp: {}", e))?;
    drop(tmp_file); // close handle before replace
    drop(reader); // close source handle (important on Windows)

    // Windows ReplaceFileW wants the original existing; POSIX rename replaces.
    if let Err(e) = atomic_replace(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    // On success, tmp_path no longer points to a valid file. Sync dir to make rename durable.
    fsync_dir_of(path)?;

    Ok(())
}

fn decrypt_in_place(path: &Path) -> Result<()> {
    refuse_symlink(path)?;

    // Open encrypted file safely, lock it, then get its size from the file handle.
    let in_f = open_file_nofollow_read(path)?;
    in_f.lock_exclusive().context("lock source file")?;
    let meta = in_f.metadata()?;
    ensure!(meta.len() >= HEADER_LEN as u64, "file too small to be an SFE file");

    // IMPORTANT: single BufReader for both header and body to avoid losing read-ahead bytes.
    let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE + AEAD_TAG_LEN, in_f);

    // Read header
    let header = HeaderV1::read_from(&mut reader).context("read SFE header")?;
    if header.alg_id != ALG_XCHACHA20POLY1305 || header.kdf_id != KDF_ARGON2ID {
        bail!("unsupported algorithm/KDF");
    }
    ensure!(header.chunk_size > 0, "invalid header: zero chunk size");
    ensure!(
        (header.chunk_size as usize) <= MAX_CHUNK_SIZE,
        "chunk size {} exceeds safety cap {}",
        header.chunk_size,
        MAX_CHUNK_SIZE
    );

    // Safety caps on Argon2 params
    let max_m = env_or("SFE_MAX_M_KIB", DEFAULT_MAX_ARGON2_M_KIB);
    let max_t = env_or("SFE_MAX_T", DEFAULT_MAX_ARGON2_T);
    let max_p = env_or("SFE_MAX_P", DEFAULT_MAX_ARGON2_P);
    ensure!(header.m_cost_kib <= max_m, "file requires Argon2 memory {} KiB > allowed {} KiB (override with SFE_MAX_M_KIB)", header.m_cost_kib, max_m);
    ensure!(header.t_cost >= 1 && header.t_cost <= max_t, "file requires Argon2 time cost {} outside allowed 1..={}", header.t_cost, max_t);
    ensure!(header.p_cost >= 1 && header.p_cost <= max_p, "file requires Argon2 parallelism {} outside allowed 1..={}", header.p_cost, max_p);

    let header_without_mac = header.to_bytes_without_mac();

    let pass = read_passphrase(false)?;
    let (k_enc, k_hdr) = derive_keys(&pass, &header.salt, header.m_cost_kib, header.t_cost, header.p_cost)?;
    drop(pass);

    // Verify header MAC before writing anything
    let expect = compute_header_mac(&header_without_mac, &*k_hdr);
    if expect.ct_eq(&header.header_mac).unwrap_u8() != 1 {
        bail!("header authentication failed (wrong passphrase or corrupted file)");
    }

    // Sanity check: ciphertext size matches expectations (overflow-safe)
    let total_len = meta.len();
    let header_len = HEADER_LEN as u64;
    let body_len = total_len.checked_sub(header_len).ok_or_else(|| anyhow!("ciphertext truncated"))?;
    let cs = header.chunk_size as u64;
    let total_chunks = if header.plaintext_len == 0 { 0 } else { ((header.plaintext_len - 1) / cs) + 1 };
    let tags = (AEAD_TAG_LEN as u64).checked_mul(total_chunks).ok_or_else(|| anyhow!("overflow computing expected ciphertext size"))?;
    let expected_body = header.plaintext_len.checked_add(tags).ok_or_else(|| anyhow!("overflow computing expected ciphertext size"))?;
    ensure!(body_len == expected_body, "ciphertext length mismatch (expected {}, found {})", expected_body, body_len);

    let key = Key::from_slice(&*k_enc);
    let aead = XChaCha20Poly1305::new(key);
    let aad_base = header.header_mac;

    // Create temp output
    let parent = path.parent().ok_or_else(|| anyhow!("no parent directory"))?;
    let mut tmp = TempBuilder::new().prefix(".sfe-").suffix(".tmp").tempfile_in(parent)?;
    restrict_temp_file_perms(tmp.as_file())?;
    let mut writer = BufWriter::with_capacity(header.chunk_size as usize, tmp.as_file_mut());

    // Decrypt streaming (in-place) using the SAME `reader`
    let mut remaining_plain = header.plaintext_len;
    let mut index: u64 = 0;
    let mut buf = Zeroizing::new(vec![0u8; header.chunk_size as usize]);

    while index < total_chunks {
        let this_plain_u64 = std::cmp::min(remaining_plain, header.chunk_size as u64);
        let this_plain = this_plain_u64 as usize;

        // Read ciphertext body then its 16-byte tag
        reader.read_exact(&mut buf[..this_plain]).context("read ciphertext chunk")?;
        let mut tag_bytes = [0u8; AEAD_TAG_LEN];
        reader.read_exact(&mut tag_bytes).context("read ciphertext tag")?;
        let tag = Tag::from_slice(&tag_bytes);

        let nonce = make_chunk_nonce(&header.nonce_seed, index);
        let mut aad = [0u8; HEADER_MAC_LEN + 8];
        aad[..HEADER_MAC_LEN].copy_from_slice(&aad_base);
        aad[HEADER_MAC_LEN..].copy_from_slice(&index.to_le_bytes());

        aead.decrypt_in_place_detached(&nonce, &aad, &mut buf[..this_plain], tag)
            .map_err(|_| anyhow!("decryption failed: wrong passphrase or corrupted chunk {}", index))?;

        writer.write_all(&buf[..this_plain])?;
        buf[..this_plain].zeroize();

        remaining_plain = remaining_plain
            .checked_sub(this_plain_u64)
            .ok_or_else(|| anyhow!("underflow tracking plaintext remaining"))?;
        index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    writer.flush()?;
    drop(writer);

    copy_perms(path, tmp.as_file())?;
    fsync_file(tmp.as_file())?;

    let (tmp_file, tmp_path) = tmp.keep().map_err(|e| anyhow!("persist tmp: {}", e))?;
    drop(tmp_file);
    drop(reader); // close encrypted source before replacement (important on Windows)

    if let Err(e) = atomic_replace(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fsync_dir_of(path)?;

    Ok(())
}

fn verify_only(path: &Path) -> Result<()> {
    // Like decrypt, but only authenticates header + all chunk tags without writing output.
    refuse_symlink(path)?;

    let in_f = open_file_nofollow_read(path)?;
    in_f.lock_exclusive().context("lock source file")?;
    let meta = in_f.metadata()?;
    ensure!(meta.len() >= HEADER_LEN as u64, "file too small to be an SFE file");

    let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE + AEAD_TAG_LEN, in_f);
    let header = HeaderV1::read_from(&mut reader).context("read SFE header")?;
    if header.alg_id != ALG_XCHACHA20POLY1305 || header.kdf_id != KDF_ARGON2ID {
        bail!("unsupported algorithm/KDF");
    }
    ensure!(header.chunk_size > 0 && (header.chunk_size as usize) <= MAX_CHUNK_SIZE, "invalid or unsafe chunk size");

    let max_m = env_or("SFE_MAX_M_KIB", DEFAULT_MAX_ARGON2_M_KIB);
    let max_t = env_or("SFE_MAX_T", DEFAULT_MAX_ARGON2_T);
    let max_p = env_or("SFE_MAX_P", DEFAULT_MAX_ARGON2_P);
    ensure!(header.m_cost_kib <= max_m && header.t_cost >= 1 && header.t_cost <= max_t && header.p_cost >= 1 && header.p_cost <= max_p, "file requires Argon2 params outside allowed caps");

    let header_without_mac = header.to_bytes_without_mac();

    let pass = read_passphrase(false)?;
    let (k_enc, k_hdr) = derive_keys(&pass, &header.salt, header.m_cost_kib, header.t_cost, header.p_cost)?;
    drop(pass);

    let expect = compute_header_mac(&header_without_mac, &*k_hdr);
    if expect.ct_eq(&header.header_mac).unwrap_u8() != 1 {
        bail!("header authentication failed (wrong passphrase or corrupted file)");
    }

    // Size check
    let total_len = meta.len();
    let body_len = total_len.checked_sub(HEADER_LEN as u64).ok_or_else(|| anyhow!("ciphertext truncated"))?;
    let cs = header.chunk_size as u64;
    let chunks = if header.plaintext_len == 0 { 0 } else { ((header.plaintext_len - 1) / cs) + 1 };
    let tags = (AEAD_TAG_LEN as u64).checked_mul(chunks).ok_or_else(|| anyhow!("overflow computing expected size"))?;
    let expected_body = header.plaintext_len.checked_add(tags).ok_or_else(|| anyhow!("overflow computing expected size"))?;
    ensure!(body_len == expected_body, "ciphertext length mismatch (expected {}, found {})", expected_body, body_len);

    // Auth all chunks
    let key = Key::from_slice(&*k_enc);
    let aead = XChaCha20Poly1305::new(key);
    let aad_base = header.header_mac;
    let mut remaining_plain = header.plaintext_len;
    let mut index: u64 = 0;
    let mut buf = Zeroizing::new(vec![0u8; header.chunk_size as usize]);

    while index < chunks {
        let this_plain_u64 = std::cmp::min(remaining_plain, header.chunk_size as u64);
        let this_plain = this_plain_u64 as usize;

        reader.read_exact(&mut buf[..this_plain]).context("read ciphertext chunk")?;
        let mut tag_bytes = [0u8; AEAD_TAG_LEN];
        reader.read_exact(&mut tag_bytes).context("read ciphertext tag")?;
        let tag = Tag::from_slice(&tag_bytes);

        let nonce = make_chunk_nonce(&header.nonce_seed, index);
        let mut aad = [0u8; HEADER_MAC_LEN + 8];
        aad[..HEADER_MAC_LEN].copy_from_slice(&aad_base);
        aad[HEADER_MAC_LEN..].copy_from_slice(&index.to_le_bytes());

        // Decrypt-in-place to verify tag; output is discarded.
        aead.decrypt_in_place_detached(&nonce, &aad, &mut buf[..this_plain], tag)
            .map_err(|_| anyhow!("verification failed: corrupted chunk {}", index))?;

        buf[..this_plain].zeroize();
        remaining_plain = remaining_plain.checked_sub(this_plain_u64).unwrap();
        index += 1;
    }

    println!("OK (verified)");
    Ok(())
}

fn usage() -> ! {
    eprintln!("Usage:\n  sfe E <path>   # Encrypt in place\n  sfe D <path>   # Decrypt in place\n  sfe V <path>   # Verify only (no output)");
    std::process::exit(2);
}

fn main() {
    if std::env::args_os().len() != 3 {
        usage();
    }
    let op = std::env::args().nth(1).unwrap();
    let path = PathBuf::from(std::env::args_os().nth(2).unwrap());

    let res = match op.as_str() {
        "E" | "e" => encrypt_in_place(&path),
        "D" | "d" => decrypt_in_place(&path),
        "V" | "v" => verify_only(&path),
        _ => {
            usage();
        }
    };

    match res {
        Ok(()) => {
            println!("OK");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("ERROR: {:#}", e);
            std::process::exit(1);
        }
    }
}
