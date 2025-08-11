// src/main.rs

use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use log::{info, warn};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use std::{fs, path::PathBuf};

use serpent::Serpent;

// Cipher crate imports: padding, CBC init, and the pad/depad traits.
use cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

// --- Types & aliases ---
type HmacSha256 = Hmac<Sha256>;
type SerpentCbcEnc = cbc::Encryptor<Serpent>;
type SerpentCbcDec = cbc::Decryptor<Serpent>;

// --- Constants ---
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const TAG_LEN: usize = 32;

// Simple on-disk header to allow evolution later.
// Layout (little-endian):
// magic[4] = b"SRP2"
// version[u16] = 1
// kdf_id[u8] = 1 (Argon2id)
// argon2_m_kib[u32], argon2_t[u32], argon2_p[u32]
// salt[16]
// iv[16]
// ciphertext[..]
// tag[32]
const MAGIC: &[u8; 4] = b"SRP2";
const VERSION: u16 = 1;
const KDF_ID_ARGON2ID: u8 = 1;

// Default Argon2id parameters for new files:
const ARGON2_M_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

// computed header sizes
const HEADER_FIXED_NO_SALT_IV: usize = 4 + 2 + 1 + 4 + 4 + 4; // magic + version + kdf + m + t + p
const HEADER_LEN: usize = HEADER_FIXED_NO_SALT_IV + SALT_LEN + IV_LEN;
const MIN_FILE_LEN: usize = HEADER_LEN + TAG_LEN; // (plus at least 1 block of ct checked later)

// --- CLI ---
#[derive(Parser)]
#[command(name = "serpent2", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite output if it exists
        #[arg(long)]
        force: bool,
    },
    /// Decrypt a file
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite output if it exists
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Encrypt { input, output, force } => {
            info!("Encrypting {:?}", input);
            let pwd = prompt_password("Enter password: ")?;
            let confirm = prompt_password("Confirm password: ")?;
            if pwd != confirm {
                anyhow::bail!("passwords did not match");
            }

            let salt = random_bytes(SALT_LEN);
            let master = derive_key_with_params(&pwd, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)?;
            let (k_enc, k_auth) = derive_subkeys(&master)?;

            let data = fs::read(&input).context("reading input file")?;
            let iv = random_bytes(IV_LEN);

            // Encrypt (CBC + PKCS7 in-place)
            let mut buf = data.clone();
            let msg_len = buf.len();
            // Reserve room for PKCS#7 padding (up to one block)
            let block = IV_LEN;
            let pad_len = block - (msg_len % block);
            buf.resize(msg_len + pad_len, 0u8);

            let ct = SerpentCbcEnc::new_from_slices(k_enc.expose_secret(), &iv)
                .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?
                .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
                .map_err(|e| anyhow::anyhow!("padding/encrypt failed: {e}"))?;

            // Build header (magic..iv), then MAC over (header || ct)
            let header = build_header(ARGON2_M_KIB, ARGON2_T, ARGON2_P, &salt, &iv);
            let tag = compute_tag(k_auth.expose_secret(), &header, ct)?;

            // Write: header || ct || tag
            let mut out_bytes = Vec::with_capacity(header.len() + ct.len() + TAG_LEN);
            out_bytes.extend_from_slice(&header);
            out_bytes.extend_from_slice(ct);
            out_bytes.extend_from_slice(&tag);

            let out_path = output.unwrap_or_else(|| input.with_extension("enc"));
            ensure_can_write(&out_path, force)?;
            fs::write(&out_path, out_bytes).context("writing output file")?;
            info!("Written to {:?}", out_path);
            Ok(())
        }
        Commands::Decrypt { input, output, force } => {
            info!("Decrypting {:?}", input);
            let pwd = prompt_password("Enter password: ")?;
            let blob = fs::read(&input).context("reading input file")?;
            if blob.len() < MIN_FILE_LEN + IV_LEN {
                // need at least one block of ct
                anyhow::bail!("file too short or not a valid SRP2 container");
            }

            // Parse header
            let header = &blob[..HEADER_LEN];
            parse_and_validate_header(header)?; // checks magic/version/kdf
            let (m_kib, t, p) = parse_kdf_params(header);
            let salt = &header[HEADER_FIXED_NO_SALT_IV..HEADER_FIXED_NO_SALT_IV + SALT_LEN];
            let iv = &header[HEADER_FIXED_NO_SALT_IV + SALT_LEN..HEADER_LEN];

            // Split ct/tag
            if blob.len() < HEADER_LEN + TAG_LEN + IV_LEN {
                anyhow::bail!("file too short for ciphertext/tag");
            }
            let tag = &blob[blob.len() - TAG_LEN..];
            let ct = &blob[HEADER_LEN..blob.len() - TAG_LEN];

            // Derive keys based on header KDF params
            let master = derive_key_with_params(&pwd, salt, m_kib, t, p)?;
            let (k_enc, k_auth) = derive_subkeys(&master)?;

            // Verify MAC over (header || ct)
            let mut mac = <HmacSha256 as Mac>::new_from_slice(k_auth.expose_secret())
                .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
            mac.update(header);
            mac.update(ct);
            mac.verify_slice(tag).context("HMAC mismatch")?;

            // Decrypt in-place and validate PKCS#7 padding
            let mut buf = ct.to_vec();
            let pt = SerpentCbcDec::new_from_slices(k_enc.expose_secret(), iv)
                .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| anyhow::anyhow!("invalid padding"))?;

            let out_path = output.unwrap_or_else(|| input.with_extension("dec"));
            ensure_can_write(&out_path, force)?;
            fs::write(&out_path, pt).context("writing output file")?;
            info!("Written to {:?}", out_path);
            Ok(())
        }
    }
}

// --- Helpers ---

fn ensure_can_write(path: &PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        warn!("Output file exists: {:?}", path);
        anyhow::bail!("refusing to overwrite existing file (use --force)");
    }
    Ok(())
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn derive_key_with_params(pw: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Secret<[u8; 32]>> {
    let params = Params::new(m_kib, t, p, None)
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;
    let salt_str = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("salt encoding failed: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(pw.as_bytes(), &salt_str)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    let digest = hash
        .hash
        .ok_or_else(|| anyhow::anyhow!("Argon2 digest missing"))?;
    let raw = digest.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[..32]);
    Ok(Secret::new(key))
}

fn derive_subkeys(master: &Secret<[u8; 32]>) -> Result<(Secret<[u8; 32]>, Secret<[u8; 32]>)> {
    let hk = Hkdf::<Sha256>::new(None, master.expose_secret());
    let mut k_enc = [0u8; 32];
    let mut k_auth = [0u8; 32];
    hk.expand(b"enc", &mut k_enc)
        .map_err(|e| anyhow::anyhow!("HKDF expand(enc) failed: {e}"))?;
    hk.expand(b"auth", &mut k_auth)
        .map_err(|e| anyhow::anyhow!("HKDF expand(auth) failed: {e}"))?;
    Ok((Secret::new(k_enc), Secret::new(k_auth)))
}

fn build_header(m_kib: u32, t: u32, p: u32, salt: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(KDF_ID_ARGON2ID);
    out.extend_from_slice(&m_kib.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&p.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(iv);
    out
}

fn parse_and_validate_header(header: &[u8]) -> Result<()> {
    if header.len() < HEADER_LEN {
        anyhow::bail!("header too short");
    }
    if &header[0..4] != MAGIC {
        anyhow::bail!("bad magic (not an SRP2 container)");
    }
    let ver = u16::from_le_bytes([header[4], header[5]]);
    if ver != VERSION {
        anyhow::bail!("unsupported version: {}", ver);
    }
    let kdf_id = header[6];
    if kdf_id != KDF_ID_ARGON2ID {
        anyhow::bail!("unsupported KDF id: {}", kdf_id);
    }
    Ok(())
}

fn parse_kdf_params(header: &[u8]) -> (u32, u32, u32) {
    let m_off = 7;
    let t_off = m_off + 4;
    let p_off = t_off + 4;
    let m_kib = u32::from_le_bytes(header[m_off..m_off + 4].try_into().unwrap());
    let t = u32::from_le_bytes(header[t_off..t_off + 4].try_into().unwrap());
    let p = u32::from_le_bytes(header[p_off..p_off + 4].try_into().unwrap());
    (m_kib, t, p)
}

fn compute_tag(k_auth: &[u8], header: &[u8], ct: &[u8]) -> Result<[u8; TAG_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_auth)
        .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    mac.update(header);
    mac.update(ct);
    let tag_vec = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&tag_vec);
    Ok(tag)
}
