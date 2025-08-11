use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use std::{
    fs::{self, File},
   io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};
use zeroize::{Zeroize, Zeroizing};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

const MAGIC: &[u8; 4] = b"ENC2";
const VERSION: u8 = 2;
const ALG_XCHACHA20_POLY1305: u8 = 1;

const TAG_SIZE: usize = 16;
const NONCE_PREFIX_LEN: usize = 16; // 128-bit random prefix
const NONCE_LEN: usize = 24;        // XChaCha20-Poly1305
const DEFAULT_CHUNK_MIB: u32 = 1;   // 1 MiB
const MAX_CHUNK_MIB: u32 = 64;      // safety cap for header tampering protection

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Profile {
    /// ~64 MiB RAM, 2 iters (fast-ish)
    Interactive,
    /// ~256 MiB RAM, 3 iters (balanced)
    Moderate,
    /// ~1024 MiB RAM, 4 iters (default)
    Paranoid,
}

#[derive(Parser, Debug)]
#[command(name = "lockr", version, about = "Streaming, password-based file encryption (Argon2id + XChaCha20-Poly1305)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt a file to ciphertext (streaming)
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Output encrypted file
        output: PathBuf,

        /// Key-stretching profile (default: paranoid)
        #[arg(long, value_enum, default_value_t = Profile::Paranoid)]
        profile: Profile,

        /// Chunk size in MiB (default: 1)
        #[arg(long = "chunk-mib", default_value_t = DEFAULT_CHUNK_MIB)]
        chunk_mib: u32,

        /// Skip password confirmation prompt
        #[arg(long)]
        no_confirm: bool,
    },

    /// Decrypt a ciphertext back to the original bytes (streaming)
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
            profile,
            chunk_mib,
            no_confirm,
        } => encrypt_cmd(input, output, profile, chunk_mib, no_confirm),
        Cmd::Decrypt { input, output } => decrypt_cmd(input, output),
    }
}

fn encrypt_cmd(
    input: PathBuf,
    output: PathBuf,
    profile: Profile,
    chunk_mib: u32,
    no_confirm: bool,
) -> Result<()> {
    if input == output {
        bail!("Input and output paths must differ");
    }

    // Resolve profile → Argon2 parameters
    let (mem_mib, time_cost, lanes) = profile_params(profile);

    // Safety bounds for chunk size (prevents malicious header DoS)
    if chunk_mib == 0 || chunk_mib > MAX_CHUNK_MIB {
        bail!("Invalid --chunk-mib (1..={MAX_CHUNK_MIB})");
    }
    let chunk_size: usize = (chunk_mib as usize) * 1024 * 1024;

    // Gather plaintext size (stored in header; enables strict integrity checks)
    let total_len = fs::metadata(&input)
        .with_context(|| format!("stat {}", input.display()))?
        .len();

    // Password (hidden)
    let pass1: Zeroizing<String> = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    if !no_confirm {
        let pass2: Zeroizing<String> =
            Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if *pass1 != *pass2 {
            bail!("Passwords did not match");
        }
    }

    // Random salt (32 bytes) and a 128-bit nonce prefix (used with an ever-increasing counter)
    let mut salt = [0u8; 32];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);

    // Derive 256-bit key with Argon2id
    let key_bytes = derive_key(pass1.as_bytes(), &salt, mem_mib, time_cost, lanes)?;
    drop(pass1);

    // Build header (authenticated as AAD for every chunk)
    let header = build_header_v2(
        mem_mib,
        time_cost,
        lanes,
        chunk_size as u32,
        total_len,
        &salt,
        &nonce_prefix,
    );

    // IO setup
    let mut reader = BufReader::new(File::open(&input).with_context(|| format!("open {}", input.display()))?);
    let mut writer =
        BufWriter::new(File::create(&output).with_context(|| format!("create {}", output.display()))?);

    // Write header first
    writer.write_all(&header).with_context(|| format!("write header to {}", output.display()))?;

    // Crypto setup
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // Streaming encryption
    let mut buf = vec![0u8; chunk_size];
    let mut remaining = total_len as u128; // avoid underflow worries
    let mut idx: u64 = 0;

    while remaining > 0 {
        let this_pt_len = usize::try_from(remaining.min(chunk_size as u128)).unwrap();
        reader
            .read_exact(&mut buf[..this_pt_len])
            .with_context(|| format!("read plaintext chunk {idx} from {}", input.display()))?;

        // Per-chunk nonce = 16-byte random prefix || 8-byte little-endian chunk index
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        nonce_bytes[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_le_bytes());
        let nonce = XNonce::from_slice(&nonce_bytes);

        // AAD binds header + chunk index + "is last" + exact pt_len
        let last = (remaining as usize) == this_pt_len;
        let aad = aad_for_chunk(&header, idx, last, this_pt_len as u32);

        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buf[..this_pt_len],
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("Encryption failed for chunk {idx}"))?;

        writer
            .write_all(&ct)
            .with_context(|| format!("write ciphertext chunk {idx} to {}", output.display()))?;

        remaining -= this_pt_len as u128;
        idx += 1;
    }

    writer.flush().with_context(|| format!("flush {}", output.display()))?;

    // Wipe buffers
    buf.zeroize();

    println!(
        "Encrypted (profile={:?}, chunk={} MiB) → {}",
        profile,
        chunk_mib,
        output.display()
    );
    Ok(())
}

fn decrypt_cmd(input: PathBuf, output: PathBuf) -> Result<()> {
    if input == output {
        bail!("Input and output paths must differ");
    }
    let mut reader =
        BufReader::new(File::open(&input).with_context(|| format!("open {}", input.display()))?);

    // Read & parse fixed header
    // Layout (little-endian):
    // magic(4) | version(1)=2 | alg(1)=1 |
    // mem_mib(u32) | time(u32) | lanes(u32) | chunk_size(u32) | total_len(u64) |
    // salt_len(u8) | nonce_prefix_len(u8) | salt | nonce_prefix
    let mut fixed = [0u8; 32];
    reader
        .read_exact(&mut fixed)
        .with_context(|| format!("read header from {}", input.display()))?;

    let mut header = fixed.to_vec();

    if &fixed[0..4] != MAGIC {
        bail!("Bad magic: not a lockr ENC2 file");
    }
    if fixed[4] != VERSION {
        bail!("Unsupported format version: {}", fixed[4]);
    }
    if fixed[5] != ALG_XCHACHA20_POLY1305 {
        bail!("Unsupported algorithm id: {}", fixed[5]);
    }

    let mem_mib = u32::from_le_bytes(fixed[6..10].try_into().unwrap());
    let time_cost = u32::from_le_bytes(fixed[10..14].try_into().unwrap());
    let lanes = u32::from_le_bytes(fixed[14..18].try_into().unwrap());
    let chunk_size = u32::from_le_bytes(fixed[18..22].try_into().unwrap()) as usize;
    let total_len = u64::from_le_bytes(fixed[22..30].try_into().unwrap());
    let salt_len = fixed[30] as usize;
    let nonce_prefix_len = fixed[31] as usize;

    // Additional header fields
    if salt_len < 16 || salt_len > 64 {
        bail!("Suspicious salt length in header");
    }
    if nonce_prefix_len != NONCE_PREFIX_LEN {
        bail!("Unexpected nonce prefix length (expected {NONCE_PREFIX_LEN})");
    }
    if chunk_size == 0 || chunk_size > (MAX_CHUNK_MIB as usize) * 1024 * 1024 {
        bail!("Chunk size in header exceeds safety limit");
    }

    let mut tail = vec![0u8; salt_len + nonce_prefix_len];
    reader
        .read_exact(&mut tail)
        .with_context(|| "read header tail (salt/nonce)".to_string())?;
    header.extend_from_slice(&tail);

    let salt = &tail[..salt_len];
    let nonce_prefix = &tail[salt_len..];

    // Ask password
    let pass: Zeroizing<String> = Zeroizing::new(rpassword::prompt_password("Password: ")?);

    // Derive key with stored params
    let key_bytes = derive_key(pass.as_bytes(), salt, mem_mib, time_cost, lanes)?;
    drop(pass);

    // Streaming decryption
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let mut writer = BufWriter::new(
        File::create(&output).with_context(|| format!("create {}", output.display()))?,
    );

    let mut remaining = total_len as u128;
    let mut idx: u64 = 0;

    // A single reusable buffer for ciphertext (max size per chunk)
    let mut ct_buf = vec![0u8; chunk_size + TAG_SIZE];

    while remaining > 0 {
        let this_pt_len = usize::try_from(remaining.min(chunk_size as u128)).unwrap();
        let this_ct_len = this_pt_len + TAG_SIZE;

        // Read exactly this chunk's ciphertext
        reader
            .read_exact(&mut ct_buf[..this_ct_len])
            .with_context(|| format!("read ciphertext chunk {idx} from {}", input.display()))?;

        // Nonce for this chunk
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
        nonce_bytes[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_le_bytes());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let last = (remaining as usize) == this_pt_len;
        let aad = aad_for_chunk(&header, idx, last, this_pt_len as u32);

        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct_buf[..this_ct_len],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!(
                    "Decryption failed for chunk {idx} (wrong password or corrupted file)"
                )
            })?;

        writer
            .write_all(&pt)
            .with_context(|| format!("write plaintext chunk {idx} to {}", output.display()))?;

        remaining -= this_pt_len as u128;
        idx += 1;
    }

    // Reject trailing garbage after the last chunk
    let mut probe = [0u8; 1];
    match reader.read(&mut probe) {
        Ok(0) => {} // clean EOF
        Ok(_) => bail!("Trailing bytes after final chunk (corrupted or tampered file)"),
        Err(e) => return Err(e).context("final trailing-bytes check failed"),
    }

    writer.flush().with_context(|| format!("flush {}", output.display()))?;
    ct_buf.zeroize();

    println!("Decrypted → {}", output.display());
    Ok(())
}

fn profile_params(p: Profile) -> (u32, u32, u32) {
    match p {
        Profile::Interactive => (64, 2, 1),   // 64 MiB, 2 iters
        Profile::Moderate => (256, 3, 1),     // 256 MiB, 3 iters
        Profile::Paranoid => (1024, 4, 1),    // 1 GiB, 4 iters (default)
    }
}

fn aad_for_chunk(header: &[u8], idx: u64, last: bool, pt_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 8 + 1 + 4);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&idx.to_le_bytes());
    aad.push(if last { 1 } else { 0 });
    aad.extend_from_slice(&pt_len.to_le_bytes());
    aad
}

fn build_header_v2(
    mem_mib: u32,
    time_cost: u32,
    lanes: u32,
    chunk_size: u32,
    total_len: u64,
    salt: &[u8],
    nonce_prefix: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(
        4 + 1 + 1 + 4 * 4 + 8 + 1 + 1 + salt.len() + nonce_prefix.len(),
    );
    h.extend_from_slice(MAGIC); // 4
    h.push(VERSION); // 1
    h.push(ALG_XCHACHA20_POLY1305); // 1
    h.extend_from_slice(&mem_mib.to_le_bytes()); // 4
    h.extend_from_slice(&time_cost.to_le_bytes()); // 4
    h.extend_from_slice(&lanes.to_le_bytes()); // 4
    h.extend_from_slice(&chunk_size.to_le_bytes()); // 4
    h.extend_from_slice(&total_len.to_le_bytes()); // 8
    h.push(salt.len() as u8); // 1
    h.push(nonce_prefix.len() as u8); // 1
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce_prefix);
    h
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
