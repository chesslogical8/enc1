use anyhow::{anyhow, bail, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use std::cmp::min;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder as TempBuilder;
use zeroize::Zeroizing;

use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_IGNORE_MERGE_ERRORS};

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
const AEAD_TAG_LEN: usize = 16;
const HEADER_MAC_LEN: usize = 32;

// Sensible default chunk size: balance I/O and memory.
const DEFAULT_CHUNK_SIZE: usize = 1 << 20; // 1 MiB

// Argon2id defaults (tunable via env).
const DEFAULT_ARGON2_M_KIB: u32 = 256 * 1024; // 256 MiB
const DEFAULT_ARGON2_T_COST: u32 = 3;

#[derive(Clone, Debug)]
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
        let mut buf = Vec::with_capacity(64);
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
        buf
    }

    fn write_all<W: Write>(&self, mut w: W) -> Result<()> {
        let without_mac = self.to_bytes_without_mac();
        w.write_all(&without_mac)?;
        w.write_all(&self.header_mac)?;
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut fixed = [0u8; 64]; // bytes without MAC
        r.read_exact(&mut fixed)?;
        let mut mac = [0u8; HEADER_MAC_LEN];
        r.read_exact(&mut mac)?;

        let mut idx = 0usize;
        let magic = <[u8; 4]>::try_from(&fixed[idx..idx + 4]).unwrap(); idx += 4;
        let version = fixed[idx]; idx += 1;
        let alg_id = fixed[idx]; idx += 1;
        let kdf_id = fixed[idx]; idx += 1;
        let reserved = fixed[idx]; idx += 1;

        if &magic != MAGIC { bail!("bad magic"); }
        if version != VERSION { bail!("unsupported version: {}", version); }

        let m_cost_kib = u32::from_le_bytes(fixed[idx..idx + 4].try_into().unwrap()); idx += 4;
        let t_cost     = u32::from_le_bytes(fixed[idx..idx + 4].try_into().unwrap()); idx += 4;
        let p_cost     = u32::from_le_bytes(fixed[idx..idx + 4].try_into().unwrap()); idx += 4;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&fixed[idx..idx + SALT_LEN]); idx += SALT_LEN;

        let mut nonce_seed = [0u8; NONCE_SEED_LEN];
        nonce_seed.copy_from_slice(&fixed[idx..idx + NONCE_SEED_LEN]); idx += NONCE_SEED_LEN;

        let chunk_size = u32::from_le_bytes(fixed[idx..idx + 4].try_into().unwrap()); idx += 4;
        let plaintext_len = u64::from_le_bytes(fixed[idx..idx + 8].try_into().unwrap()); idx += 8;
        debug_assert_eq!(idx, fixed.len());

        Ok(Self {
            magic, version, alg_id, kdf_id, reserved,
            m_cost_kib, t_cost, p_cost, salt, nonce_seed,
            chunk_size, plaintext_len, header_mac: mac,
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
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    // Replace *dest* with *src*
    let replaced = to_w(dest);
    let replacement = to_w(src);

    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_IGNORE_MERGE_ERRORS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        bail!("ReplaceFileW failed replacing {:?} with {:?}", dest, src);
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
    // There isn't a simple, portable directory sync on Windows; ReplaceFileW handles metadata atomically.
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {:?}", path))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to operate on a symlink: {:?}", path);
    }
    if !meta.is_file() {
        bail!("path is not a regular file: {:?}", path);
    }
    Ok(())
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

fn read_passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let p1 = Zeroizing::new(prompt_password("Passphrase: ")?);
    if p1.is_empty() { bail!("empty passphrase refused"); }
    if confirm {
        let p2 = Zeroizing::new(prompt_password("Confirm passphrase: ")?);
        if *p1 != *p2 {
            bail!("passphrases did not match");
        }
    }
    Ok(p1)
}

// Derive 64 bytes (32 for AEAD, 32 for header MAC key)
fn derive_keys(pass: &Zeroizing<String>, salt: &[u8; SALT_LEN], m_cost: u32, t_cost: u32, p_cost: u32)
    -> Result<(Zeroizing<[u8;32]>, Zeroizing<[u8;32]>)>
{
    let params = Params::new(m_cost, t_cost, p_cost, Some(64))
        .map_err(|e| anyhow!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut out[..])
        .map_err(|e| anyhow!("argon2: {}", e))?;
    let mut k_enc = Zeroizing::new([0u8;32]);
    let mut k_hdr = Zeroizing::new([0u8;32]);
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

fn compute_header_mac(header_without_mac: &[u8], header_key: &[u8;32]) -> [u8; HEADER_MAC_LEN] {
    let out = blake3::keyed_hash(header_key, header_without_mac);
    let mut mac = [0u8; HEADER_MAC_LEN];
    mac.copy_from_slice(out.as_bytes());
    mac
}

fn encrypt_in_place(path: &Path) -> Result<()> {
    refuse_symlink(path)?;
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        bail!("{:?} is not a regular file", path);
    }
    let plaintext_len = meta.len();
    let pass = read_passphrase(true)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_seed = [0u8; NONCE_SEED_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_seed);

    let m_cost = std::env::var("SFE_ARGON2_M_KIB").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_ARGON2_M_KIB);
    let t_cost = std::env::var("SFE_ARGON2_T").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_ARGON2_T_COST);
    let p_cost = min(std::env::var("SFE_ARGON2_P").ok().and_then(|v| v.parse().ok()).unwrap_or(min(num_cpus::get() as u32, 8)), 32);

    let (k_enc, k_hdr) = derive_keys(&pass, &salt, m_cost, t_cost, p_cost)?;
    drop(pass); // zeroized on drop

    let mut header = HeaderV1::new_placeholder();
    header.m_cost_kib = m_cost;
    header.t_cost = t_cost;
    header.p_cost = p_cost;
    header.salt = salt;
    header.nonce_seed = nonce_seed;
    header.chunk_size = DEFAULT_CHUNK_SIZE as u32;
    header.plaintext_len = plaintext_len;

    let header_without_mac = header.to_bytes_without_mac();
    header.header_mac = compute_header_mac(&header_without_mac, &k_hdr);

    // Open source for reading
    let in_f = File::open(path)?;
    let mut reader = BufReader::new(in_f);

    // Create temp file in same dir
    let parent = path.parent().ok_or_else(|| anyhow!("no parent directory"))?;
    let mut tmp = TempBuilder::new()
        .prefix(".sfe-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .context("create tmp")?;
    {
        // Write header first
        header.write_all(tmp.as_file_mut())?;
        fsync_file(tmp.as_file())?;
        copy_perms(path, tmp.as_file())?;
    }

    let key = Key::from_slice(&*k_enc);
    let aead = XChaCha20Poly1305::new(key);

    // AAD binds chunks to this file instance.
    let aad_base = header.header_mac; // 32 bytes

    // Encrypt streaming
    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
    let mut remaining = plaintext_len;
    let mut index: u64 = 0;
    let mut writer = BufWriter::new(tmp.as_file_mut());

    while remaining > 0 {
        let want = min(remaining as usize, DEFAULT_CHUNK_SIZE);
        reader.read_exact(&mut buf[..want])?;
        let nonce = make_chunk_nonce(&nonce_seed, index);
        let mut aad = [0u8; HEADER_MAC_LEN + 8];
        aad[..HEADER_MAC_LEN].copy_from_slice(&aad_base);
        aad[HEADER_MAC_LEN..].copy_from_slice(&index.to_le_bytes());

        let ct = aead
            .encrypt(&nonce, Payload { msg: &buf[..want], aad: &aad })
            .map_err(|_| anyhow!("encryption failure (chunk {})", index))?;
        writer.write_all(&ct)?;
        index += 1;
        remaining -= want as u64;
    }

    // Finish buffered I/O, then drop the writer BEFORE touching tmp.as_file() again.
    writer.flush()?;
    drop(writer);
    fsync_file(tmp.as_file())?;

    // Close tmp file handle and turn into a persistent path we can atomically swap in.
    let (tmp_file, tmp_path) = tmp.keep().map_err(|e| anyhow!("persist tmp: {}", e))?;
    drop(tmp_file); // close handle before replace
    drop(reader);   // close source handle (important on Windows)

    // Windows ReplaceFileW wants the original existing; POSIX rename replaces.
    atomic_replace(&tmp_path, path)?;
    // On success, tmp_path no longer points to a valid file. Sync dir to make rename durable.
    fsync_dir_of(path)?;

    Ok(())
}

fn decrypt_in_place(path: &Path) -> Result<()> {
    refuse_symlink(path)?;

    // Basic size check before reading header
    let meta = fs::metadata(path)?;
    ensure!(meta.len() >= 96, "file too small to be an SFE file");

    // Open source for reading header first
    let in_f = File::open(path)?;
    let mut reader = BufReader::new(in_f);

    // Read header
    let header = HeaderV1::read_from(&mut reader)?;
    if header.alg_id != ALG_XCHACHA20POLY1305 || header.kdf_id != KDF_ARGON2ID {
        bail!("unsupported algorithm/KDF");
    }
    ensure!(header.chunk_size > 0, "invalid header: zero chunk size");

    let header_without_mac = {
        let mut h = header.clone();
        h.header_mac = [0u8; HEADER_MAC_LEN];
        h.to_bytes_without_mac()
    };

    let pass = read_passphrase(false)?;
    let (k_enc, k_hdr) = derive_keys(&pass, &header.salt, header.m_cost_kib, header.t_cost, header.p_cost)?;
    drop(pass);

    // Verify header MAC before writing anything
    let expect = compute_header_mac(&header_without_mac, &k_hdr);
    if expect != header.header_mac {
        bail!("header authentication failed (wrong passphrase or corrupted file)");
    }

    // Sanity check: ciphertext size matches expectations
    let total_len = meta.len();
    let header_len = 96u64;
    let body_len = total_len.checked_sub(header_len).ok_or_else(|| anyhow!("ciphertext truncated"))?;
    let cs = header.chunk_size as u64;
    let total_chunks = if header.plaintext_len == 0 { 0 } else { ((header.plaintext_len - 1) / cs) + 1 };
    let expected_body = header.plaintext_len + (total_chunks * AEAD_TAG_LEN as u64);
    ensure!(body_len == expected_body, "ciphertext length mismatch (expected {}, found {})", expected_body, body_len);

    let key = Key::from_slice(&*k_enc);
    let aead = XChaCha20Poly1305::new(key);
    let aad_base = header.header_mac;

    // Create temp output
    let parent = path.parent().ok_or_else(|| anyhow!("no parent directory"))?;
    let mut tmp = TempBuilder::new().prefix(".sfe-").suffix(".tmp").tempfile_in(parent)?;
    copy_perms(path, tmp.as_file())?;

    // We will write plaintext (no header).
    let mut writer = BufWriter::new(tmp.as_file_mut());

    // Decrypt streaming
    let mut remaining_plain = header.plaintext_len;
    let mut index: u64 = 0;

    while index < total_chunks {
        let this_plain = min(remaining_plain as usize, header.chunk_size as usize);
        let this_ct_len = this_plain + AEAD_TAG_LEN;

        let mut ct = vec![0u8; this_ct_len];
        reader.read_exact(&mut ct[..])?;

        let nonce = make_chunk_nonce(&header.nonce_seed, index);
        let mut aad = [0u8; HEADER_MAC_LEN + 8];
        aad[..HEADER_MAC_LEN].copy_from_slice(&aad_base);
        aad[HEADER_MAC_LEN..].copy_from_slice(&index.to_le_bytes());

        let pt = aead
            .decrypt(&nonce, Payload { msg: &ct[..], aad: &aad })
            .map_err(|_| anyhow!("decryption failed: wrong passphrase or corrupted chunk {}", index))?;

        writer.write_all(&pt)?;
        remaining_plain -= this_plain as u64;
        index += 1;
    }

    // Finish buffered I/O, drop writer, then fsync via the temp file handle.
    writer.flush()?;
    drop(writer);
    fsync_file(tmp.as_file())?;

    // Close & persist temp, then atomic replace original
    let (tmp_file, tmp_path) = tmp.keep().map_err(|e| anyhow!("persist tmp: {}", e))?;
    drop(tmp_file);
    drop(reader); // close encrypted source before replacement (important on Windows)

    atomic_replace(&tmp_path, path)?;
    fsync_dir_of(path)?;

    Ok(())
}

fn usage() -> ! {
    eprintln!("Usage:\n  sfe E <path>   # Encrypt in place\n  sfe D <path>   # Decrypt in place");
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
        _ => { usage(); }
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
