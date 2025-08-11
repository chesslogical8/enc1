use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use threefish::Threefish1024;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"TF3Fv002"; // format tag
const VERSION: u8 = 2;
const MODE_CTR_ETM_BLAKE3: u8 = 1;

const SALT_LEN: usize = 16;
const TWEAK_LEN: usize = 16;
const NONCE_LEN: usize = 112; // fills words 0..13 in the 16-word block
const TAG_LEN: usize = 32;    // BLAKE3 tag size

// header: magic(8) + ver(1) + mode(1) + m(4) + t(4) + p(4) + salt(16) + tweak(16) + nonce(112) = 166
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + TWEAK_LEN + NONCE_LEN;

const CHUNK: usize = 8 * 1024 * 1024; // 8 MiB streaming

fn main() -> Result<()> {
    let mut args = std::env::args_os();
    let _exe = args.next();
    let op = args.next().ok_or_else(|| anyhow!("usage: E <path> | D <path>"))?;
    let path = args.next().ok_or_else(|| anyhow!("missing file path"))?;
    if args.next().is_some() {
        bail!("usage: E <path> | D <path>");
    }

    match op.to_string_lossy().chars().next().unwrap_or('?') {
        'E' | 'e' => encrypt_in_place(&PathBuf::from(path)),
        'D' | 'd' => decrypt_in_place(&PathBuf::from(path)),
        _ => bail!("usage: E <path> | D <path>"),
    }
}

fn encrypt_in_place(path: &Path) -> Result<()> {
    // Quick guard: refuse to encrypt if it already looks like our format.
    {
        if let Ok(mut f) = File::open(path) {
            let mut m = [0u8; 8];
            if f.read(&mut m).unwrap_or(0) == 8 && &m == MAGIC {
                bail!("file already appears to be encrypted by this format");
            }
        }
    }

    // Passphrase (double prompt)
    let pass1 = rpassword::prompt_password("Enter passphrase: ")?;
    let pass2 = rpassword::prompt_password("Re-enter passphrase: ")?;
    if pass1 != pass2 {
        bail!("passphrases do not match");
    }
    let mut pass = pass1;

    // Argon2id parameters (tunable via env)
    let (m_mib, t_cost, p_cost) = kdf_params_from_env();
    let mut salt = [0u8; SALT_LEN];
    let mut tweak = [0u8; TWEAK_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut tweak);
    OsRng.fill_bytes(&mut nonce);

    // Derive 160 bytes: 128 for Threefish key, 32 for BLAKE3 MAC key
    let (mut tf_key, mut mac_key) =
        derive_keys(pass.as_bytes(), &salt, m_mib, t_cost, p_cost)?;
    pass.zeroize(); // wipe passphrase ASAP

    let header = serialize_header(m_mib, t_cost, p_cost, &salt, &tweak, &nonce);

    // Prepare Threefish-1024 with tweak
    let cipher = Threefish1024::new_with_tweak(&tf_key, &tweak);

    // I/O
    let in_file = File::open(path).with_context(|| format!("open input {}", path.display()))?;
    let in_len = in_file.metadata()?.len();

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = NamedTempFile::new_in(parent).context("create temp file")?;

    // --- Start a scope so writer drops before we persist() ---
    {
        let out_f = tmp.as_file();
        // Preallocate: header + ciphertext + tag (best-effort)
        let out_len = HEADER_LEN as u64 + in_len + TAG_LEN as u64;
        let _ = out_f.set_len(out_len);

        let mut writer = BufWriter::new(out_f);
        writer.write_all(&header)?;

        // MAC over header (no tag yet)
        let mut mac = blake3::Hasher::new_keyed(&mac_key);
        mac.update(&header);

        let mut reader = BufReader::with_capacity(CHUNK, &in_file);
        let mut in_buf = vec![0u8; CHUNK];
        let mut out_buf = vec![0u8; CHUNK];

        let mut ctr: u128 = 0;
        loop {
            let n = reader.read(&mut in_buf)?;
            if n == 0 { break; }
            apply_threefish_ctr(&cipher, &nonce, ctr, &in_buf[..n], &mut out_buf[..n]);
            ctr = ctr.checked_add(((n + 127) / 128) as u128).unwrap();
            writer.write_all(&out_buf[..n])?;
            mac.update(&out_buf[..n]);
        }

        // finalize tag, append to file
        let tag = mac.finalize();
        writer.write_all(tag.as_bytes())?;
        writer.flush()?;
        writer.get_ref().sync_all()?; // fsync temp
    } // writer (and borrow of tmp) drops here

    // Best-effort directory sync
    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }

    // 🔑 Important on Windows: close the original before replacing it
    drop(in_file);

    // Atomically replace original (with retry for transient AV/indexer locks)
    persist_atomic_with_retry(tmp, path)?;

    // Zeroize secrets
    tf_key.zeroize();
    mac_key.zeroize();
    salt.zeroize();
    tweak.zeroize();
    nonce.zeroize();

    println!("Encrypted {}", path.display());
    Ok(())
}

fn decrypt_in_place(path: &Path) -> Result<()> {
    let pass = rpassword::prompt_password("Enter passphrase: ")?;
    let mut in_file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let total_len = in_file.metadata()?.len();
    if total_len < (HEADER_LEN + TAG_LEN) as u64 {
        bail!("file too small to be valid ciphertext");
    }

    // Read and parse header
    let mut header = [0u8; HEADER_LEN];
    in_file.read_exact(&mut header)?;
    validate_magic(&header)?;
    let (m_mib, t_cost, p_cost, mut salt, mut tweak, mut nonce) = parse_header(&header)?;

    // Derive keys
    let (mut tf_key, mut mac_key) = derive_keys(pass.as_bytes(), &salt, m_mib, t_cost, p_cost)?;
    let cipher = Threefish1024::new_with_tweak(&tf_key, &tweak);

    // Verify MAC BEFORE decrypting
    let ct_len = total_len - HEADER_LEN as u64 - TAG_LEN as u64;

    // Compute MAC(header + ciphertext)
    let mut mac = blake3::Hasher::new_keyed(&mac_key);
    mac.update(&header);

    let mut reader = BufReader::with_capacity(CHUNK, &in_file);
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = ct_len;
    let mut read_total = 0u64;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, CHUNK as u64) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 { break; }
        mac.update(&buf[..n]);
        remaining -= n as u64;
        read_total += n as u64;
    }
    if read_total != ct_len {
        bail!("truncated ciphertext");
    }

    // Read stored tag and constant-time compare
    let mut stored_tag = [0u8; TAG_LEN];
    in_file.seek(SeekFrom::Start(HEADER_LEN as u64 + ct_len))?;
    in_file.read_exact(&mut stored_tag)?;
    let computed = mac.finalize();
    if stored_tag.ct_eq(computed.as_bytes()).unwrap_u8() != 1 {
        bail!("authentication failed: wrong passphrase or corrupted file");
    }

    // All good: decrypt to temp, then atomic replace
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = NamedTempFile::new_in(parent)?;
    {
        let out_f = tmp.as_file();
        let _ = out_f.set_len(ct_len);
        let mut writer = BufWriter::new(out_f);

        // Reset reader to start of ciphertext
        in_file.seek(SeekFrom::Start(HEADER_LEN as u64))?;
        let mut ct_reader = BufReader::with_capacity(CHUNK, &in_file);
        let mut in_buf = vec![0u8; CHUNK];
        let mut out_buf = vec![0u8; CHUNK];
        let mut ctr: u128 = 0;

        let mut remaining_dec = ct_len;
        while remaining_dec > 0 {
            let to_read = std::cmp::min(remaining_dec, CHUNK as u64) as usize;
            let n = ct_reader.read(&mut in_buf[..to_read])?;
            if n == 0 { break; }
            apply_threefish_ctr(&cipher, &nonce, ctr, &in_buf[..n], &mut out_buf[..n]);
            ctr = ctr.checked_add(((n + 127) / 128) as u128).unwrap();
            writer.write_all(&out_buf[..n])?;
            remaining_dec -= n as u64;
        }

        writer.flush()?;
        writer.get_ref().sync_all()?;
    } // drop writer

    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }

    // 🔑 Close the original before the replace
    drop(in_file);

    // Replace original (with retry)
    persist_atomic_with_retry(tmp, path)?;

    // Zeroize secrets
    salt.zeroize();
    tweak.zeroize();
    nonce.zeroize();
    tf_key.zeroize();
    mac_key.zeroize();

    println!("Decrypted {}", path.display());
    Ok(())
}

fn kdf_params_from_env() -> (u32, u32, u32) {
    let m_mib = std::env::var("TF_M_MIB").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    let t_cost = std::env::var("TF_T").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let p_cost = std::env::var("TF_P").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    (m_mib, t_cost, p_cost)
}

fn derive_keys(
    pass: &[u8],
    salt: &[u8; SALT_LEN],
    m_mib: u32,
    t: u32,
    p: u32,
) -> Result<([u8; 128], [u8; 32])> {
    // Argon2 wants memory in KiB blocks (1 MiB = 1024 blocks)
    let params = Params::new(m_mib * 1024, t, p, Some(160))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = [0u8; 160];
    argon
        .hash_password_into(pass, salt, &mut okm)
        .map_err(|e| anyhow!("argon2 KDF failed: {e}"))?;

    let mut tf_key = [0u8; 128];
    let mut mac_key = [0u8; 32];
    tf_key.copy_from_slice(&okm[..128]);
    mac_key.copy_from_slice(&okm[128..160]);
    okm.zeroize();
    Ok((tf_key, mac_key))
}

fn serialize_header(
    m_mib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8; SALT_LEN],
    tweak: &[u8; TWEAK_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut hdr = [0u8; HEADER_LEN];
    let mut off = 0usize;
    hdr[off..off + 8].copy_from_slice(MAGIC); off += 8;
    hdr[off] = VERSION; off += 1;
    hdr[off] = MODE_CTR_ETM_BLAKE3; off += 1;
    hdr[off..off + 4].copy_from_slice(&(m_mib).to_le_bytes()); off += 4;
    hdr[off..off + 4].copy_from_slice(&(t_cost).to_le_bytes()); off += 4;
    hdr[off..off + 4].copy_from_slice(&(p_cost).to_le_bytes()); off += 4;
    hdr[off..off + SALT_LEN].copy_from_slice(salt); off += SALT_LEN;
    hdr[off..off + TWEAK_LEN].copy_from_slice(tweak); off += TWEAK_LEN;
    hdr[off..off + NONCE_LEN].copy_from_slice(nonce);
    debug_assert_eq!(8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + TWEAK_LEN + NONCE_LEN, HEADER_LEN);
    hdr
}

#[allow(clippy::type_complexity)]
fn parse_header(hdr: &[u8; HEADER_LEN]) -> Result<(u32,u32,u32,[u8;SALT_LEN],[u8;TWEAK_LEN],[u8;NONCE_LEN])> {
    let mut off = 0usize;
    if &hdr[off..off + 8] != MAGIC { bail!("bad magic"); }
    off += 8;
    if hdr[off] != VERSION { bail!("unsupported version"); }
    off += 1;
    if hdr[off] != MODE_CTR_ETM_BLAKE3 { bail!("unsupported mode"); }
    off += 1;
    let m_mib = u32::from_le_bytes(hdr[off..off + 4].try_into().unwrap()); off += 4;
    let t_cost = u32::from_le_bytes(hdr[off..off + 4].try_into().unwrap()); off += 4;
    let p_cost = u32::from_le_bytes(hdr[off..off + 4].try_into().unwrap()); off += 4;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&hdr[off..off + SALT_LEN]); off += SALT_LEN;
    let mut tweak = [0u8; TWEAK_LEN];
    tweak.copy_from_slice(&hdr[off..off + TWEAK_LEN]); off += TWEAK_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hdr[off..off + NONCE_LEN]);
    Ok((m_mib, t_cost, p_cost, salt, tweak, nonce))
}

fn validate_magic(hdr: &[u8; HEADER_LEN]) -> Result<()> {
    if &hdr[0..8] != MAGIC { bail!("not a TF3Fv002 file"); }
    Ok(())
}

// XOR-CTR: keystream block = Threefish1024( nonce||counter )
// nonce occupies the first 112 bytes (words 0..13), counter fills words 14..15 as LE u128
fn apply_threefish_ctr(
    cipher: &Threefish1024,
    nonce: &[u8; NONCE_LEN],
    start_counter: u128,
    input: &[u8],
    output: &mut [u8],
) {
    debug_assert_eq!(input.len(), output.len());
    let mut ctr = start_counter;
    let mut off = 0usize;
    while off < input.len() {
        let mut block_words = [0u64; 16];
        // load nonce (14 words)
        for i in 0..14 {
            let base = i * 8;
            block_words[i] = u64::from_le_bytes([
                nonce[base + 0], nonce[base + 1], nonce[base + 2], nonce[base + 3],
                nonce[base + 4], nonce[base + 5], nonce[base + 6], nonce[base + 7],
            ]);
        }
        // counter into words 14..15 (LE)
        let ctr_lo = (ctr & 0xFFFF_FFFF_FFFF_FFFFu128) as u64;
        let ctr_hi = (ctr >> 64) as u64;
        block_words[14] = ctr_lo;
        block_words[15] = ctr_hi;

        let mut ks = block_words;
        cipher.encrypt_block_u64(&mut ks);

        // xor up to 128 bytes
        let mut ks_bytes = [0u8; 128];
        for i in 0..16 {
            ks_bytes[i * 8..(i + 1) * 8].copy_from_slice(&ks[i].to_le_bytes());
        }

        let take = std::cmp::min(128, input.len() - off);
        for i in 0..take {
            output[off + i] = input[off + i] ^ ks_bytes[i];
        }
        off += take;
        ctr = ctr.wrapping_add(1);
    }
}

// Robust atomic replace that retries briefly (helpful on Windows if AV/indexer touches the file)
fn persist_atomic_with_retry(mut tmp: NamedTempFile, path: &Path) -> Result<()> {
    let mut delay = std::time::Duration::from_millis(20);
    for _ in 0..10 {
        match tmp.persist(path) {
            Ok(_) => return Ok(()),
            Err(e) => {
                // recover the temp file and try again
                tmp = e.file;
                std::thread::sleep(delay);
                delay = std::cmp::min(delay * 2, std::time::Duration::from_millis(500));
            }
        }
    }
    // Final attempt: bubble up a clear error including the underlying I/O error
    tmp.persist(path)
        .map(|_| ())
        .map_err(|e| anyhow!("atomic rename (persist) failed: {}", e.error))
}
