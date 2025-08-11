use std::fs::{File, rename, remove_file};
use std::io::{Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, Context};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use argon2::{Argon2, Algorithm, Version, Params};
use hmac::Mac;
use hmac::SimpleHmac;
use skein::{Skein512, consts::U32};
use threefish::cipher::BlockEncrypt;
use threefish::Threefish1024;
use tempfile::Builder as TempBuilder;

const MAGIC: &[u8; 8] = b"TF1024\0\0";
const VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const ENC_KEY_LEN: usize = 128;
const MAC_KEY_LEN: usize = 64;
const MAC_TAG_LEN: usize = 32;

const KDF_MEM_MIB: u32 = 512;
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 1;
const CHUNK_KIB: usize = 1024;

type HmacSkein256 = SimpleHmac<Skein512<U32>>;

#[derive(Parser, Debug)]
#[command(name = "tfish", version, about = "Threefish-1024 (SIV) auto encrypt/decrypt in place")]
struct Cli {
    path: PathBuf,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let kdf = KdfParams { mem_mib: KDF_MEM_MIB, iters: KDF_ITERS, lanes: KDF_LANES };
    let chunk_size = CHUNK_KIB * 1024;
    match detect_mode(&args.path)? {
        Mode::Decrypt => decrypt_in_place(&args.path, kdf, chunk_size)?,
        Mode::Encrypt => encrypt_in_place_siv(&args.path, kdf, chunk_size)?,
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct KdfParams { mem_mib: u32, iters: u32, lanes: u32 }
enum Mode { Encrypt, Decrypt }

fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 8];
    let n = f.read(&mut magic)?;
    if n == 8 && &magic == MAGIC { Ok(Mode::Decrypt) } else { Ok(Mode::Encrypt) }
}

fn encrypt_in_place_siv(path: &Path, kdf: KdfParams, chunk_size: usize) -> Result<()> {
    let mut in_file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = TempBuilder::new().prefix(".tfish~").tempfile_in(parent)?;
    let mut out = BufWriter::new(tmp.as_file_mut());

    let chunk_size = chunk_size.max(128);
    if chunk_size % 128 != 0 { bail!("chunk size must be multiple of 128 bytes"); }

    let mut salt = [0u8; SALT_LEN]; OsRng.fill_bytes(&mut salt);

    let (mut enc_key, mac_key) = derive_keys_from_password(&salt, kdf)?;
    let aad = header_aad_bytes(kdf, &salt, chunk_size);

    let mut siv_mac = <HmacSkein256 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    Mac::update(&mut siv_mac, &aad);
    let mut rdr1 = BufReader::new(&in_file);
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = read_exact_or_eof(&mut rdr1, &mut buf)?;
        if n == 0 { break; }
        Mac::update(&mut siv_mac, &buf[..n]);
    }
    let siv_iv_full = siv_mac.finalize().into_bytes();
    let mut siv_iv = [0u8; NONCE_LEN];
    siv_iv.copy_from_slice(&siv_iv_full[..NONCE_LEN]);

    write_full_header(&mut out, &salt, &siv_iv, kdf, chunk_size)?;

    let mut mac = <HmacSkein256 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    let mut full_hdr = Vec::new();
    write_full_header(&mut full_hdr, &salt, &siv_iv, kdf, chunk_size)?;
    Mac::update(&mut mac, &full_hdr);

    let cipher = Threefish1024::new_with_tweak((&enc_key).into(), &siv_iv);

    in_file.seek(SeekFrom::Start(0))?;
    let mut rdr2 = BufReader::new(&in_file);

    let mut chunk_index: u64 = 0;
    loop {
        let n = read_exact_or_eof(&mut rdr2, &mut buf)?;
        if n == 0 { break; }
        let mut offset = 0usize;
        let mut block_counter: u64 = 0;
        while offset < n {
            let take = (n - offset).min(128);
            let mut ctr_block = [0u8; 128];
            ctr_block[..16].copy_from_slice(&siv_iv);
            ctr_block[16..24].copy_from_slice(&chunk_index.to_le_bytes());
            ctr_block[24..32].copy_from_slice(&block_counter.to_le_bytes());
            let mut ks = ctr_block.into();
            cipher.encrypt_block(&mut ks);
            for i in 0..take { buf[offset + i] ^= ks[i]; }
            Mac::update(&mut mac, &buf[offset..offset + take]);
            offset += take;
            block_counter = block_counter.wrapping_add(1);
        }
        out.write_all(&buf[..n])?;
        chunk_index = chunk_index.wrapping_add(1);
    }

    let tag = mac.finalize().into_bytes();
    out.write_all(&tag[..MAC_TAG_LEN])?;
    out.flush()?;

    enc_key.zeroize();

    drop(out);
    let tmp_path = tmp.into_temp_path();
    replace_file(tmp_path.as_ref(), path)?;
    Ok(())
}

fn decrypt_in_place(path: &Path, _kdf: KdfParams, _chunk_size: usize) -> Result<()> {
    let mut in_file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = TempBuilder::new().prefix(".tfish~").tempfile_in(parent)?;
    let mut out = BufWriter::new(tmp.as_file_mut());

    let _start_pos = 0u64;
    let (salt, siv_iv, kdf, chunk_size, header_len) = read_full_header(&mut in_file)?;
    let (mut enc_key, mac_key) = derive_keys_from_password(&salt, kdf)?;

    let mut mac = <HmacSkein256 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    {
        let mut hdr_bytes = Vec::new();
        write_full_header(&mut hdr_bytes, &salt, &siv_iv, kdf, chunk_size)?;
        Mac::update(&mut mac, &hdr_bytes);
    }

    let mut rdr_mac = BufReader::new(File::open(path)?);
    rdr_mac.seek(SeekFrom::Start(header_len as u64))?;
    let mut tail = vec![0u8; MAC_TAG_LEN];
    let mut tail_filled = 0usize;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = read_exact_or_eof(&mut rdr_mac, &mut buf)?;
        if n == 0 { break; }
        let block = &buf[..n];
        let mut i = 0usize;
        while i < block.len() {
            if tail_filled < MAC_TAG_LEN {
                let take = (MAC_TAG_LEN - tail_filled).min(block.len() - i);
                tail[tail_filled .. tail_filled + take].copy_from_slice(&block[i..i+take]);
                tail_filled += take;
                i += take;
                continue;
            }
            Mac::update(&mut mac, &tail[0..1]);
            tail.rotate_left(1);
            tail[MAC_TAG_LEN - 1] = block[i];
            i += 1;
        }
    }
    mac.verify_slice(&tail).context("MAC verification failed")?;

    let cipher = Threefish1024::new_with_tweak((&enc_key).into(), &siv_iv);

    let mut rdr_dec = BufReader::new(File::open(path)?);
    rdr_dec.seek(SeekFrom::Start(header_len as u64))?;
    let file_len = rdr_dec.get_ref().metadata()?.len();
    let ct_len = (file_len - header_len as u64).saturating_sub(MAC_TAG_LEN as u64) as usize;

    let mut remaining = ct_len;
    let mut chunk_index: u64 = 0;
    while remaining > 0 {
        let to_read = remaining.min(chunk_size);
        rdr_dec.read_exact(&mut buf[..to_read])?;
        let mut off = 0usize;
        let mut block_counter: u64 = 0;
        while off < to_read {
            let take = (to_read - off).min(128);
            let mut ctr_block = [0u8; 128];
            ctr_block[..16].copy_from_slice(&siv_iv);
            ctr_block[16..24].copy_from_slice(&chunk_index.to_le_bytes());
            ctr_block[24..32].copy_from_slice(&block_counter.to_le_bytes());
            let mut ks = ctr_block.into();
            cipher.encrypt_block(&mut ks);
            for j in 0..take { buf[off + j] ^= ks[j]; }
            off += take;
            block_counter = block_counter.wrapping_add(1);
        }
        out.write_all(&buf[..to_read])?;
        remaining -= to_read;
        chunk_index = chunk_index.wrapping_add(1);
    }

    out.flush()?;
    enc_key.zeroize();

    drop(out);
    let tmp_path = tmp.into_temp_path();
    replace_file(tmp_path.as_ref(), path)?;
    Ok(())
}

fn header_aad_bytes(kdf: KdfParams, salt: &[u8; SALT_LEN], chunk_size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 2 + 12 + SALT_LEN + 4);
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&VERSION.to_le_bytes());
    v.extend_from_slice(&(kdf.mem_mib).to_le_bytes());
    v.extend_from_slice(&(kdf.iters).to_le_bytes());
    v.extend_from_slice(&(kdf.lanes).to_le_bytes());
    v.extend_from_slice(salt);
    v.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    v
}

fn write_full_header<W: Write>(mut w: W, salt: &[u8; SALT_LEN], siv_iv: &[u8; NONCE_LEN], kdf: KdfParams, chunk_size: usize) -> Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    w.write_all(&(kdf.mem_mib).to_le_bytes())?;
    w.write_all(&(kdf.iters).to_le_bytes())?;
    w.write_all(&(kdf.lanes).to_le_bytes())?;
    w.write_all(salt)?;
    w.write_all(siv_iv)?;
    w.write_all(&(chunk_size as u32).to_le_bytes())?;
    Ok(())
}

fn read_full_header<R: Read>(mut r: R) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], KdfParams, usize, usize)> {
    let mut magic = [0u8; 8]; r.read_exact(&mut magic)?;
    if &magic != MAGIC { bail!("bad magic"); }
    let mut v = [0u8; 2]; r.read_exact(&mut v)?;
    let version = u16::from_le_bytes(v);
    if version != VERSION { bail!("unsupported version {}", version); }
    let mut m = [0u8; 4]; r.read_exact(&mut m)?;
    let mem = u32::from_le_bytes(m);
    let mut it = [0u8; 4]; r.read_exact(&mut it)?;
    let iters = u32::from_le_bytes(it);
    let mut ln = [0u8; 4]; r.read_exact(&mut ln)?;
    let lanes = u32::from_le_bytes(ln);
    let mut salt = [0u8; SALT_LEN]; r.read_exact(&mut salt)?;
    let mut siv_iv = [0u8; NONCE_LEN]; r.read_exact(&mut siv_iv)?;
    let mut cs = [0u8; 4]; r.read_exact(&mut cs)?;
    let chunk = u32::from_le_bytes(cs) as usize;
    let header_len = 8 + 2 + 12 + SALT_LEN + NONCE_LEN + 4;
    Ok((salt, siv_iv, KdfParams { mem_mib: mem.max(8), iters: iters.max(1), lanes: lanes.max(1) }, chunk.max(128), header_len))
}

fn derive_keys_from_password(salt: &[u8; SALT_LEN], params: KdfParams) -> Result<([u8; ENC_KEY_LEN], [u8; MAC_KEY_LEN])> {
    let pass = rpassword::prompt_password("Password: ")?;
    let out = derive_keys(pass.as_bytes(), salt, params)?;
    Ok(out)
}

fn derive_keys(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<([u8; ENC_KEY_LEN], [u8; MAC_KEY_LEN])> {
    let out_len = ENC_KEY_LEN + MAC_KEY_LEN;
    let p = Params::new(params.mem_mib.max(8) * 1024, params.iters.max(1), params.lanes.max(1), Some(out_len))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut okm = vec![0u8; out_len];
    argon.hash_password_into(password, salt, &mut okm).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut enc_key = [0u8; ENC_KEY_LEN];
    let mut mac_key = [0u8; MAC_KEY_LEN];
    enc_key.copy_from_slice(&okm[..ENC_KEY_LEN]);
    mac_key.copy_from_slice(&okm[ENC_KEY_LEN..]);
    okm.zeroize();
    Ok((enc_key, mac_key))
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut read = 0usize;
    while read < buf.len() {
        match r.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

fn replace_file(temp_path: &Path, target: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if target.exists() { remove_file(target).ok(); }
        rename(temp_path, target).with_context(|| format!("replace {}", target.display()))?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        rename(temp_path, target).with_context(|| format!("replace {}", target.display()))?;
        Ok(())
    }
}

