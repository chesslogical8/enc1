use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::{fs, path::PathBuf};
use zeroize::Zeroizing;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

const MAGIC: &[u8; 4] = b"ENC1";
const VERSION: u8 = 1;
const ALG_XCHACHA20_POLY1305: u8 = 1;

#[derive(Parser, Debug)]
#[command(name = "lockr", version, about = "Password-based file encryption with Argon2id + XChaCha20-Poly1305")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt a file to ciphertext
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Output encrypted file
        output: PathBuf,

        /// Argon2 memory (MiB)
        #[arg(long = "mem", default_value_t = 256)]
        mem_mib: u32,
        /// Argon2 iterations (time cost)
        #[arg(long = "iters", default_value_t = 3)]
        time_cost: u32,
        /// Argon2 lanes (parallelism)
        #[arg(long = "lanes", default_value_t = 1)]
        lanes: u32,

        /// Skip password confirmation prompt
        #[arg(long)]
        no_confirm: bool,
    },

    /// Decrypt a ciphertext back to the original bytes
    Decrypt {
        /// Input encrypted file
        input: PathBuf,
        /// Output plaintext file
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encrypt {
            input,
            output,
            mem_mib,
            time_cost,
            lanes,
            no_confirm,
        } => encrypt_cmd(input, output, mem_mib, time_cost, lanes, no_confirm),
        Cmd::Decrypt { input, output } => decrypt_cmd(input, output),
    }
}

fn encrypt_cmd(
    input: PathBuf,
    output: PathBuf,
    mem_mib: u32,
    time_cost: u32,
    lanes: u32,
    no_confirm: bool,
) -> Result<()> {
    if input == output {
        bail!("Input and output paths must differ");
    }

    let plaintext = fs::read(&input).with_context(|| format!("Reading {}", input.display()))?;

    // Get password (hidden)
    let pass1: Zeroizing<String> = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    if !no_confirm {
        let pass2: Zeroizing<String> =
            Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if *pass1 != *pass2 {
            bail!("Passwords did not match");
        }
    }

    // Random salt (32 bytes) and nonce (24 bytes for XChaCha20)
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Derive 256-bit key with Argon2id
    let key_bytes = derive_key(pass1.as_bytes(), &salt, mem_mib, time_cost, lanes)?;
    drop(pass1);

    // Header (authenticated as AAD)
    let mut header = Vec::with_capacity(4 + 1 + 1 + 4 * 3 + 1 + 1 + salt.len() + nonce_bytes.len());
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(ALG_XCHACHA20_POLY1305);
    header.extend_from_slice(&(mem_mib as u32).to_le_bytes());
    header.extend_from_slice(&(time_cost as u32).to_le_bytes());
    header.extend_from_slice(&(lanes as u32).to_le_bytes());
    header.push(salt.len() as u8);
    header.push(nonce_bytes.len() as u8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    // Encrypt
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Write header || ciphertext
    let mut out = header;
    out.extend_from_slice(&ciphertext);
    fs::write(&output, out).with_context(|| format!("Writing {}", output.display()))?;

    // Best-effort wipe of plaintext buffer
    use zeroize::Zeroize;
    let mut pt = plaintext;
    pt.as_mut_slice().zeroize();

    println!("Encrypted → {}", output.display());
    Ok(())
}

fn decrypt_cmd(input: PathBuf, output: PathBuf) -> Result<()> {
    if input == output {
        bail!("Input and output paths must differ");
    }
    let data = fs::read(&input).with_context(|| format!("Reading {}", input.display()))?;
    if data.len() < 4 + 1 + 1 + 12 + 1 + 1 {
        bail!("File too short / not a valid lockr file");
    }

    // Parse header
    let mut idx = 0usize;
    if &data[idx..idx + 4] != MAGIC {
        bail!("Bad magic: not a lockr file");
    }
    idx += 4;

    let version = data[idx];
    idx += 1;
    if version != VERSION {
        bail!("Unsupported format version: {}", version);
    }

    let alg = data[idx];
    idx += 1;
    if alg != ALG_XCHACHA20_POLY1305 {
        bail!("Unsupported algorithm id: {}", alg);
    }

    let mem_mib = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap());
    idx += 4;
    let time_cost = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap());
    idx += 4;
    let lanes = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap());
    idx += 4;

    let salt_len = data[idx] as usize;
    idx += 1;
    let nonce_len = data[idx] as usize;
    idx += 1;

    if data.len() < idx + salt_len + nonce_len + 16 {
        bail!("Truncated file");
    }

    let salt = &data[idx..idx + salt_len];
    idx += salt_len;
    let nonce_bytes = &data[idx..idx + nonce_len];
    idx += nonce_len;

    let ciphertext = &data[idx..];

    // Ask password
    let pass: Zeroizing<String> = Zeroizing::new(rpassword::prompt_password("Password: ")?);

    // Derive key with the stored params
    let key_bytes = derive_key(pass.as_bytes(), salt, mem_mib, time_cost, lanes)?;
    drop(pass);

    // Decrypt using the exact header as AAD (everything before ciphertext)
    let aad = &data[..idx];
    let key = Key::from_slice(&key_bytes);
    if nonce_len != 24 {
        bail!("Unexpected nonce length (expected 24 for XChaCha20)");
    }
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("Decryption failed (wrong password or corrupted file)"))?;

    fs::write(&output, plaintext).with_context(|| format!("Writing {}", output.display()))?;
    println!("Decrypted → {}", output.display());
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    mem_mib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<[u8; 32]> {
    if salt.len() < 16 {
        bail!("Salt too short");
    }
    // Argon2 params: memory cost is in KiB
    let m_cost_kib: u32 = mem_mib
        .checked_mul(1024)
        .context("Argon2 memory parameter overflows")?;

    let params = Params::new(m_cost_kib, time_cost, lanes, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;
    Ok(key)
}
