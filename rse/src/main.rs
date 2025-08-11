// rse — Rust Safe Encrypt (single-file, Windows & Linux)
// ------------------------------------------------------------
// A Windows & Linux CLI for safe, chunked, authenticated file encryption.
// Goals: crash-safe, atomic I/O; misuse-resistant AEAD; strong KDF.
// Default suite: XChaCha20-Poly1305 + HKDF-SHA512 + Argon2id + BLAKE3
//
// ─────────────────────────────────────────────────────────────────────────────
// HOW TO BUILD (create Cargo.toml next to this file)
// ─────────────────────────────────────────────────────────────────────────────
// [package]
// name = "rse"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// anyhow = "1"
// argon2 = "0.5"
// blake3 = "1"
// chacha20poly1305 = "0.10"  // XChaCha20Poly1305 is available by default
// clap = { version = "4", features = ["derive"] }
// hkdf = "0.12"
// rand = "0.8"
// sha2 = "0.10"
// rpassword = "7"
// zeroize = "1"
//
// Build (Linux):   cargo build --release && ./target/release/rse --help
// Build (Windows): cargo build --release && .\target\release\rse.exe --help
//
// Example: rse encrypt -i secret.pdf -o secret.pdf.rse
//          rse decrypt -i secret.pdf.rse -o secret.pdf
//          rse inspect -i secret.pdf.rse
//          rse verify  -i secret.pdf.rse
//          rse rewrap  -i secret.pdf.rse   # change passphrase/KDF fast
//
// Notes:
// - Single-file implementation for ease of review.
// - Passphrase mode only (recipient keys not implemented in this file).
// - Uses atomic temp files + fsync + rename for both encrypt/decrypt/rewrap.
// - Per-chunk independent AEAD with subkeys via HKDF; constant nonce is safe
//   ONLY because each chunk uses a unique key (documented below).
// - Header is MACed with a BLAKE3 keyed hash derived from the file key.
// - Trailer is a KEYED MAC over the plaintext hash (prevents file-identity leak).
// - Sensible caps/guards on KDF and chunk params to avoid DoS/accidents.
// - On Windows, directory fsync is a no-op (not exposed); files are still fsync'd.
//
// SECURITY REMARKS:
// - This tool defends confidentiality/integrity at rest and in cloud storage.
// - It cannot protect data on a compromised machine at the moment of use.
// - Secure deletion on SSDs is inherently unreliable; wipe with care.
// - Back up before encrypting until you trust your workflow.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher as Blake3Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use std::cmp::min;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, copy, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

// File format identifiers
const MAGIC: &[u8; 8] = b"RSE1v1\0\0"; // file magic
const SUITE_ID: u16 = 1; // XChaCha20-Poly1305 + HKDF-SHA512 + Argon2id
const TRAILER_MAGIC: &[u8; 8] = b"RSE1TRLR"; // trailer magic

// Header flags
const FLAG_KEYED_TRAILER: u32 = 1 << 0; // trailer is keyed (preferred)

// Defaults
const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
const MAX_CHUNK_SIZE: u32 = 256 * 1024 * 1024; // 256 MiB cap to prevent accidents/DoS
const AEAD_TAG_SIZE: usize = 16; // XChaCha20-Poly1305 tag length

// Argon2 defaults/bounds
const ARGON2_DEFAULT_M_KIB: u32 = 512 * 1024; // 512 MiB
const ARGON2_DEFAULT_T_COST: u32 = 3; // iterations
const ARGON2_DEFAULT_P: u32 = 1; // lanes

const ARGON2_MIN_M_KIB: u32 = 64 * 1024; // 64 MiB minimum
const ARGON2_MAX_M_KIB: u32 = 2 * 1024 * 1024; // 2 GiB max
const ARGON2_MIN_T_COST: u32 = 1;
const ARGON2_MAX_T_COST: u32 = 10;
const ARGON2_MIN_P: u32 = 1;
const ARGON2_MAX_P: u32 = 8;

#[derive(Debug, Clone)]
struct Header {
    version: u16,
    suite_id: u16,
    flags: u32,
    uuid: [u8; 16],
    chunk_size: u32,
    plaintext_size: u64,
    kdf_m_kib: u32,
    kdf_t_cost: u32,
    kdf_parallelism: u32,
    salt: [u8; 16],
    wrap_nonce: [u8; 24],
    wrapped_key: Vec<u8>, // AEAD(file_key) with tag
    header_mac: [u8; 32], // Blake3 keyed over header (excluding this field)
}

impl Header {
    fn encode_without_mac(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.suite_id.to_le_bytes());
        v.extend_from_slice(&self.flags.to_le_bytes());
        v.extend_from_slice(&self.uuid);
        v.extend_from_slice(&self.chunk_size.to_le_bytes());
        v.extend_from_slice(&self.plaintext_size.to_le_bytes());
        v.extend_from_slice(&self.kdf_m_kib.to_le_bytes());
        v.extend_from_slice(&self.kdf_t_cost.to_le_bytes());
        v.extend_from_slice(&self.kdf_parallelism.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.wrap_nonce);
        let wl = self.wrapped_key.len() as u16;
        v.extend_from_slice(&wl.to_le_bytes());
        v.extend_from_slice(&self.wrapped_key);
        v
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = self.encode_without_mac();
        v.extend_from_slice(&self.header_mac);
        v
    }

    fn decode(mut data: &[u8]) -> Result<Self> {
        let mut take = |n: usize| -> Result<&[u8]> {
            if data.len() < n {
                bail!("truncated header");
            }
            let (a, b) = data.split_at(n);
            data = b;
            Ok(a)
        };
        let magic = take(8)?;
        if magic != MAGIC {
            bail!("bad magic");
        }
        let version = u16::from_le_bytes(take(2)?.try_into().unwrap());
        if version != 1 {
            bail!("unsupported version: {}", version);
        }
        let suite_id = u16::from_le_bytes(take(2)?.try_into().unwrap());
        if suite_id != SUITE_ID {
            bail!("unsupported suite: {}", suite_id);
        }
        let flags = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(take(16)?);

        let chunk_size = u32::from_le_bytes(take(4)?.try_into().unwrap());
        if chunk_size == 0 || chunk_size % 1024 != 0 {
            bail!("invalid chunk size");
        }
        if chunk_size > MAX_CHUNK_SIZE {
            bail!(
                "chunk size too large ({} MiB > {} MiB)",
                chunk_size / 1024 / 1024,
                MAX_CHUNK_SIZE / 1024 / 1024
            );
        }

        let plaintext_size = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let kdf_m_kib = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let kdf_t_cost = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let kdf_parallelism = u32::from_le_bytes(take(4)?.try_into().unwrap());
        validate_kdf_params(kdf_m_kib, kdf_t_cost, kdf_parallelism)?;

        let mut salt = [0u8; 16];
        salt.copy_from_slice(take(16)?);
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(take(24)?);

        let wl = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let wrapped_key = take(wl)?.to_vec();
        if wrapped_key.len() < 32 + AEAD_TAG_SIZE {
            bail!("wrapped_key too short");
        }

        let mut header_mac = [0u8; 32];
        header_mac.copy_from_slice(take(32)?);
        Ok(Self {
            version,
            suite_id,
            flags,
            uuid,
            chunk_size,
            plaintext_size,
            kdf_m_kib,
            kdf_t_cost,
            kdf_parallelism,
            salt,
            wrap_nonce,
            wrapped_key,
            header_mac,
        })
    }
}

#[derive(Parser)]
#[command(name = "rse", version, about = "Rust Safe Encrypt — safe, strong file encryption (Windows & Linux CLI)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file with a passphrase
    Encrypt {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Chunk size in MiB (default 4, max 256)
        #[arg(long = "chunk-mib")]
        chunk_mib: Option<u32>,
        /// Overwrite output if it already exists
        #[arg(long = "force")]
        force: bool,
        /// Tune Argon2 memory in MiB (default 512)
        #[arg(long = "kdf-mib")]
        kdf_mib: Option<u32>,
        /// Argon2 time cost/iterations (default 3)
        #[arg(long = "kdf-iters")]
        kdf_iters: Option<u32>,
        /// Argon2 parallelism (default 1)
        #[arg(long = "kdf-par")]
        kdf_par: Option<u32>,
    },

    /// Decrypt a file
    Decrypt {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Overwrite output if it already exists
        #[arg(long = "force")]
        force: bool,
    },

    /// Inspect header without decrypting
    Inspect {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
    },

    /// Verify an encrypted file end-to-end (integrity + trailer MAC/hash)
    Verify {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
    },

    /// Rewrap the file key with a new passphrase/KDF (no data re-encryption)
    Rewrap {
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// Optional output path; defaults to in-place via atomic temp+rename
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Overwrite output if it already exists
        #[arg(long = "force")]
        force: bool,
        /// New Argon2 memory in MiB (default: keep existing)
        #[arg(long = "kdf-mib")]
        kdf_mib: Option<u32>,
        /// New Argon2 iterations (default: keep existing)
        #[arg(long = "kdf-iters")]
        kdf_iters: Option<u32>,
        /// New Argon2 parallelism (default: keep existing)
        #[arg(long = "kdf-par")]
        kdf_par: Option<u32>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt {
            input,
            output,
            chunk_mib,
            force,
            kdf_mib,
            kdf_iters,
            kdf_par,
        } => {
            let chunk_mib_val =
                chunk_mib.unwrap_or(DEFAULT_CHUNK_SIZE / 1024 / 1024).max(1);
            if chunk_mib_val > (MAX_CHUNK_SIZE / 1024 / 1024) {
                bail!(
                    "chunk-mib too large ({} > {} MiB)",
                    chunk_mib_val,
                    MAX_CHUNK_SIZE / 1024 / 1024
                );
            }
            let chunk_size = chunk_mib_val * 1024 * 1024;

            let kdf_m_kib =
                (kdf_mib.unwrap_or(ARGON2_DEFAULT_M_KIB / 1024) * 1024)
                    .clamp(ARGON2_MIN_M_KIB, ARGON2_MAX_M_KIB);
            let kdf_t_cost = kdf_iters
                .unwrap_or(ARGON2_DEFAULT_T_COST)
                .clamp(ARGON2_MIN_T_COST, ARGON2_MAX_T_COST);
            let kdf_parallelism = kdf_par
                .unwrap_or(ARGON2_DEFAULT_P)
                .clamp(ARGON2_MIN_P, ARGON2_MAX_P);
            validate_kdf_params(kdf_m_kib, kdf_t_cost, kdf_parallelism)?;

            encrypt_cmd(
                &input,
                output.as_deref(),
                chunk_size,
                force,
                kdf_m_kib,
                kdf_t_cost,
                kdf_parallelism,
            )
        }
        Commands::Decrypt {
            input,
            output,
            force,
        } => decrypt_cmd(&input, output.as_deref(), force),
        Commands::Inspect { input } => inspect_cmd(&input),
        Commands::Verify { input } => verify_cmd(&input),
        Commands::Rewrap {
            input,
            output,
            force,
            kdf_mib,
            kdf_iters,
            kdf_par,
        } => rewrap_cmd(
            &input, output.as_deref(), force, kdf_mib, kdf_iters, kdf_par,
        ),
    }
}

fn encrypt_cmd(
    input: &Path,
    output_opt: Option<&Path>,
    chunk_size: u32,
    force: bool,
    kdf_m_kib: u32,
    kdf_t_cost: u32,
    kdf_parallelism: u32,
) -> Result<()> {
    if !input.is_file() {
        bail!("input is not a regular file");
    }
    let input_meta = fs::metadata(input)?;
    let plaintext_size = input_meta.len();

    // Output path
    let default_out = input.with_extension("rse");
    let out_path = output_opt.unwrap_or(&default_out);

    if out_path.exists() && !force {
        bail!("output exists; pass --force to overwrite");
    }

    // Read passphrase twice
    let pass1 = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let pass2 = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
    if pass1.as_bytes() != pass2.as_bytes() {
        bail!("passphrases do not match");
    }

    // Generate file key
    let mut file_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *file_key);

    // KDF salt and Argon2id params
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek =
        Zeroizing::new(derive_kek(pass1.as_bytes(), &salt, kdf_m_kib, kdf_t_cost, kdf_parallelism)?);

    // Wrap file key (nonce is random; AD will include UUID once we have it)
    let mut wrap_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut wrap_nonce);

    // UUID
    let mut uuid = [0u8; 16];
    OsRng.fill_bytes(&mut uuid);

    // Build header (we will wrap with final AD that includes UUID)
    let mut header = Header {
        version: 1,
        suite_id: SUITE_ID,
        flags: FLAG_KEYED_TRAILER, // new files use keyed trailer
        uuid,
        chunk_size,
        plaintext_size,
        kdf_m_kib,
        kdf_t_cost,
        kdf_parallelism,
        salt,
        wrap_nonce,
        wrapped_key: Vec::new(),
        header_mac: [0u8; 32],
    };

    // Compute header MAC using a key derived from file_key
    let header_mac_key = hkdf_expand(&file_key[..], b"rse.header.mac", 32)?;
    // Bind wrapped key to the finalized UUID too (stronger binding).
    let ad_full = header_ad_prelude(SUITE_ID, &uuid);
    header.wrapped_key = aead_seal(&kek[..], &wrap_nonce, &ad_full, &file_key[..])?;
    let enc_header_no_mac = header.encode_without_mac();
    header.header_mac = blake3_keyed(&header_mac_key, &enc_header_no_mac);

    // Prepare output temp file in same directory
    let tmp_path = tmp_path_for(out_path);

    let mut in_file = File::open(input)?;
    let mut out_file = create_tmp_file(&tmp_path)?;

    // Write header
    let header_bytes = header.encode();
    out_file.write_all(&header_bytes)?;

    // Encrypt stream in chunks, hash plaintext in parallel
    let mut hasher = Blake3Hasher::new();

    let total_chunks = chunk_count(plaintext_size, chunk_size);
    let mut remaining = plaintext_size;
    let mut buf = vec![0u8; chunk_size as usize];

    for idx in 0..total_chunks {
        let to_read = min(chunk_size as u64, remaining) as usize;
        in_file.read_exact(&mut buf[..to_read])?;
        hasher.update(&buf[..to_read]);

        // Unique subkey per chunk; constant zero nonce is safe due to unique keys.
        let subkey = hkdf_expand(&file_key[..], &chunk_info(idx as u64), 32)?;
        let nonce = [0u8; 24];
        let ad = chunk_ad(
            SUITE_ID,
            &uuid,
            idx as u64,
            total_chunks,
            plaintext_size,
            chunk_size as u64,
        );
        let mut ct = aead_seal(&subkey, &nonce, &ad, &buf[..to_read])?;
        out_file.write_all(&ct)?;
        // Zeroize ct immediately
        ct.zeroize();

        remaining -= to_read as u64;
    }

    // Write trailer: keyed over plaintext hash to avoid revealing file identity
    let pt_hash = hasher.finalize(); // 32 bytes
    let trailer_key = hkdf_expand(&file_key[..], b"rse.trailer.mac", 32)?;
    let trailer_tag = blake3_keyed(&trailer_key, pt_hash.as_bytes());
    out_file.write_all(TRAILER_MAGIC)?;
    out_file.write_all(&trailer_tag)?;

    out_file.sync_all()?;
    fsync_parent(out_path)?;

    // Atomic rename (Windows: remove dest if --force and exists)
    rename_replace(&tmp_path, out_path, force)?;

    // Zeroize sensitive buffers
    buf.zeroize();

    println!("Encrypted {} bytes to {:?}", plaintext_size, out_path);
    Ok(())
}

fn decrypt_cmd(input: &Path, output_opt: Option<&Path>, force: bool) -> Result<()> {
    if !input.is_file() {
        bail!("input is not a regular file");
    }
    let mut in_file = File::open(input)?;

    // Read and parse header
    let header = read_header(&mut in_file)?;

    // Passphrase
    let pass = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let kek = Zeroizing::new(derive_kek(
        pass.as_bytes(),
        &header.salt,
        header.kdf_m_kib,
        header.kdf_t_cost,
        header.kdf_parallelism,
    )?);

    // Unwrap file key
    let ad = header_ad_prelude(header.suite_id, &header.uuid);
    let file_key = Zeroizing::new(aead_open(
        &kek[..],
        &header.wrap_nonce,
        &ad,
        &header.wrapped_key,
    )?);

    // Verify header MAC
    let mac_key = hkdf_expand(&file_key[..], b"rse.header.mac", 32)?;
    let mut enc_no_mac = header.clone();
    enc_no_mac.header_mac = [0u8; 32];
    let calc_mac = blake3_keyed(&mac_key, &enc_no_mac.encode_without_mac());
    if calc_mac != header.header_mac {
        bail!("header MAC mismatch (possible corruption or wrong passphrase)");
    }

    // Output path
    let output = match output_opt {
        Some(p) => p.to_path_buf(),
        None => default_decrypt_out(input),
    };
    if output.exists() && !force {
        bail!("output exists; pass --force to overwrite");
    }

    // Prepare output temp
    let tmp_path = tmp_path_for(&output);
    let mut out_file = create_tmp_file(&tmp_path)?;

    // Decrypt chunks and compute hash
    let mut hasher = Blake3Hasher::new();

    let total_chunks = chunk_count(header.plaintext_size, header.chunk_size);
    let mut remaining = header.plaintext_size;

    for idx in 0..total_chunks {
        let to_plain = min(header.chunk_size as u64, remaining) as usize;
        let subkey = hkdf_expand(&file_key[..], &chunk_info(idx as u64), 32)?;
        let nonce = [0u8; 24];
        let ad = chunk_ad(
            header.suite_id,
            &header.uuid,
            idx as u64,
            total_chunks,
            header.plaintext_size,
            header.chunk_size as u64,
        );

        // Ciphertext length = plaintext + tag
        let mut ct = vec![0u8; to_plain + AEAD_TAG_SIZE];
        in_file.read_exact(&mut ct)?;
        let mut pt = aead_open(&subkey, &nonce, &ad, &ct)?;
        hasher.update(&pt);
        out_file.write_all(&pt)?;

        // Zeroize sensitive buffers promptly
        ct.zeroize();
        pt.zeroize();

        remaining -= to_plain as u64;
    }

    // Read trailer and verify
    let mut trailer_magic = [0u8; 8];
    in_file.read_exact(&mut trailer_magic)?;
    if &trailer_magic != TRAILER_MAGIC {
        bail!("missing or bad trailer");
    }
    let mut trailer_hash = [0u8; 32];
    in_file.read_exact(&mut trailer_hash)?;
    let calc = hasher.finalize();
    if (header.flags & FLAG_KEYED_TRAILER) != 0 {
        let trailer_key = hkdf_expand(&file_key[..], b"rse.trailer.mac", 32)?;
        let expect = blake3_keyed(&trailer_key, calc.as_bytes());
        if trailer_hash != expect {
            bail!("trailer MAC mismatch (corruption)");
        }
    } else {
        // Legacy v1: unkeyed plaintext hash (supported for backward compatibility)
        if trailer_hash != *calc.as_bytes() {
            bail!("trailer hash mismatch (corruption)");
        }
    }

    out_file.sync_all()?;
    fsync_parent(&output)?;
    rename_replace(&tmp_path, &output, force)?;

    println!("Decrypted {} bytes to {:?}", header.plaintext_size, output);
    Ok(())
}

fn inspect_cmd(input: &Path) -> Result<()> {
    let mut f = File::open(input)?;
    let header = read_header(&mut f)?;
    println!("File: {:?}", input);
    println!("  version: {}", header.version);
    println!("  suite: {}", header.suite_id);
    println!("  flags: 0x{:08x} (keyed_trailer={})",
             header.flags, (header.flags & FLAG_KEYED_TRAILER) != 0);
    println!("  uuid: {}", hex(&header.uuid));
    println!("  chunk_size: {} KiB", header.chunk_size / 1024);
    println!("  plaintext_size: {} bytes", header.plaintext_size);
    println!(
        "  kdf: Argon2id m={} MiB t={} p={}",
        header.kdf_m_kib / 1024,
        header.kdf_t_cost,
        header.kdf_parallelism
    );
    println!("  salt: {}", hex(&header.salt));
    println!("  wrap_nonce: {}", hex(&header.wrap_nonce));
    println!("  wrapped_key_len: {}", header.wrapped_key.len());
    Ok(())
}

fn verify_cmd(input: &Path) -> Result<()> {
    let mut f = File::open(input)?;
    let header = read_header(&mut f)?;

    let pass = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let kek = Zeroizing::new(derive_kek(
        pass.as_bytes(),
        &header.salt,
        header.kdf_m_kib,
        header.kdf_t_cost,
        header.kdf_parallelism,
    )?);

    let ad = header_ad_prelude(header.suite_id, &header.uuid);
    let file_key = Zeroizing::new(aead_open(
        &kek[..],
        &header.wrap_nonce,
        &ad,
        &header.wrapped_key,
    )?);

    // Verify header MAC
    let mac_key = hkdf_expand(&file_key[..], b"rse.header.mac", 32)?;
    let mut enc_no_mac = header.clone();
    enc_no_mac.header_mac = [0u8; 32];
    let calc_mac = blake3_keyed(&mac_key, &enc_no_mac.encode_without_mac());
    if calc_mac != header.header_mac {
        bail!("header MAC mismatch");
    }

    // Stream through ciphertext, decrypt to RAM and drop, while hashing
    let mut hasher = Blake3Hasher::new();
    let total_chunks = chunk_count(header.plaintext_size, header.chunk_size);
    let mut remaining = header.plaintext_size;

    for idx in 0..total_chunks {
        let to_plain = min(header.chunk_size as u64, remaining) as usize;
        let subkey = hkdf_expand(&file_key[..], &chunk_info(idx as u64), 32)?;
        let nonce = [0u8; 24];
        let ad = chunk_ad(
            header.suite_id,
            &header.uuid,
            idx as u64,
            total_chunks,
            header.plaintext_size,
            header.chunk_size as u64,
        );
        let mut ct = vec![0u8; to_plain + AEAD_TAG_SIZE];
        f.read_exact(&mut ct)?;
        let mut pt = aead_open(&subkey, &nonce, &ad, &ct)?;
        hasher.update(&pt);

        // Zeroize
        ct.zeroize();
        pt.zeroize();

        remaining -= to_plain as u64;
    }

    let mut trailer_magic = [0u8; 8];
    f.read_exact(&mut trailer_magic)?;
    if &trailer_magic != TRAILER_MAGIC {
        bail!("missing or bad trailer");
    }
    let mut trailer_hash = [0u8; 32];
    f.read_exact(&mut trailer_hash)?;
    let calc = hasher.finalize();
    if (header.flags & FLAG_KEYED_TRAILER) != 0 {
        let trailer_key = hkdf_expand(&file_key[..], b"rse.trailer.mac", 32)?;
        let expect = blake3_keyed(&trailer_key, calc.as_bytes());
        if trailer_hash != expect {
            bail!("trailer MAC mismatch");
        }
    } else if trailer_hash != *calc.as_bytes() {
        bail!("trailer hash mismatch");
    }

    println!("OK: header + all chunks + trailer verified");
    Ok(())
}

fn rewrap_cmd(
    input: &Path,
    output_opt: Option<&Path>,
    force: bool,
    kdf_mib: Option<u32>,
    kdf_iters: Option<u32>,
    kdf_par: Option<u32>,
) -> Result<()> {
    if !input.is_file() {
        bail!("input is not a regular file");
    }
    let mut in_file = File::open(input)?;
    let mut header = read_header(&mut in_file)?;

    // Old passphrase to unwrap
    let old_pass = Zeroizing::new(rpassword::prompt_password("Current passphrase: ")?);
    let old_kek = Zeroizing::new(derive_kek(
        old_pass.as_bytes(),
        &header.salt,
        header.kdf_m_kib,
        header.kdf_t_cost,
        header.kdf_parallelism,
    )?);

    // Recover file key
    let ad = header_ad_prelude(header.suite_id, &header.uuid);
    let file_key = Zeroizing::new(aead_open(
        &old_kek[..],
        &header.wrap_nonce,
        &ad,
        &header.wrapped_key,
    )?);

    // New passphrase
    let new_pass1 = Zeroizing::new(rpassword::prompt_password("New passphrase: ")?);
    let new_pass2 = Zeroizing::new(rpassword::prompt_password("Confirm new passphrase: ")?);
    if new_pass1.as_bytes() != new_pass2.as_bytes() {
        bail!("passphrases do not match");
    }

    // New KDF params (default to existing if not specified)
    let new_kdf_m_kib = match kdf_mib {
        Some(v) => (v * 1024).clamp(ARGON2_MIN_M_KIB, ARGON2_MAX_M_KIB),
        None => header.kdf_m_kib,
    };
    let new_kdf_t_cost = kdf_iters
        .unwrap_or(header.kdf_t_cost)
        .clamp(ARGON2_MIN_T_COST, ARGON2_MAX_T_COST);
    let new_kdf_parallelism = kdf_par
        .unwrap_or(header.kdf_parallelism)
        .clamp(ARGON2_MIN_P, ARGON2_MAX_P);
    validate_kdf_params(new_kdf_m_kib, new_kdf_t_cost, new_kdf_parallelism)?;

    // New salt + KEK + wrap nonce
    let mut new_salt = [0u8; 16];
    OsRng.fill_bytes(&mut new_salt);
    let new_kek = Zeroizing::new(derive_kek(
        new_pass1.as_bytes(),
        &new_salt,
        new_kdf_m_kib,
        new_kdf_t_cost,
        new_kdf_parallelism,
    )?);
    let mut new_wrap_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut new_wrap_nonce);

    // Rewrap file key (AD includes same suite_id + same UUID)
    let new_wrapped = aead_seal(&new_kek[..], &new_wrap_nonce, &ad, &file_key[..])?;

    // Update header fields & MAC
    header.salt = new_salt;
    header.kdf_m_kib = new_kdf_m_kib;
    header.kdf_t_cost = new_kdf_t_cost;
    header.kdf_parallelism = new_kdf_parallelism;
    header.wrap_nonce = new_wrap_nonce;
    header.wrapped_key = new_wrapped;
    let mac_key = hkdf_expand(&file_key[..], b"rse.header.mac", 32)?;
    let enc_no_mac = header.encode_without_mac();
    header.header_mac = blake3_keyed(&mac_key, &enc_no_mac);

    // Output path (default: same file name)
    let out_path = output_opt.unwrap_or(input);
    if out_path.exists() && !force && out_path != input {
        bail!("output exists; pass --force to overwrite");
    }

    // Write temp file with new header + copy the remainder, then atomic rename.
    let tmp_path = tmp_path_for(out_path);
    let mut out_file = create_tmp_file(&tmp_path)?;
    let header_bytes = header.encode();
    out_file.write_all(&header_bytes)?;
    // Copy the remainder (ciphertext chunks + trailer) from current position
    copy(&mut in_file, &mut out_file)?;
    out_file.sync_all()?;
    fsync_parent(out_path)?;
    rename_replace(&tmp_path, out_path, force)?;
    println!("Rewrapped header for {:?}", out_path);
    Ok(())
}

fn read_header(f: &mut File) -> Result<Header> {
    // Read enough to get wrapped_key length; then read the rest
    // fixed = MAGIC(8)+version(2)+suite(2)+flags(4)+uuid(16)+chunk(4)+pt(8)+
    //         kdf m(4)+kdf t(4)+kdf p(4)+salt(16)+wrap_nonce(24)+wl(2)
    let mut fixed = [0u8; 8 + 2 + 2 + 4 + 16 + 4 + 8 + 4 + 4 + 4 + 16 + 24 + 2];
    f.read_exact(&mut fixed)?;
    let wl_start = 8 + 2 + 2 + 4 + 16 + 4 + 8 + 4 + 4 + 4 + 16 + 24;
    let wl =
        u16::from_le_bytes(fixed[wl_start..wl_start + 2].try_into().unwrap()) as usize;
    let mut rest = vec![0u8; wl + 32]; // wrapped_key + header_mac
    f.read_exact(&mut rest)?;
    let mut all = Vec::with_capacity(fixed.len() + rest.len());
    all.extend_from_slice(&fixed);
    all.extend_from_slice(&rest);
    Header::decode(&all)
}

fn validate_kdf_params(m_kib: u32, t_cost: u32, p: u32) -> Result<()> {
    if !(ARGON2_MIN_M_KIB..=ARGON2_MAX_M_KIB).contains(&m_kib) {
        bail!("kdf memory out of range");
    }
    if !(ARGON2_MIN_T_COST..=ARGON2_MAX_T_COST).contains(&t_cost) {
        bail!("kdf iters out of range");
    }
    if !(ARGON2_MIN_P..=ARGON2_MAX_P).contains(&p) {
        bail!("kdf parallelism out of range");
    }
    Ok(())
}

fn derive_kek(
    pass: &[u8],
    salt16: &[u8; 16],
    m_kib: u32,
    t_cost: u32,
    p: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(m_kib, t_cost, p, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let alg = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    alg.hash_password_into(pass, salt16, &mut out)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

fn aead_seal(
    key_bytes: &[u8],
    nonce_bytes: &[u8; 24],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::from_slice(key_bytes);
    let aead = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };
    let ct = aead
        .encrypt(nonce, payload)
        .map_err(|_| anyhow!("aead encrypt failed"))?;
    Ok(ct)
}

fn aead_open(
    key_bytes: &[u8],
    nonce_bytes: &[u8; 24],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::from_slice(key_bytes);
    let aead = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };
    let pt = aead.decrypt(nonce, payload).map_err(|_| {
        anyhow!("authentication failed (wrong passphrase or corruption)")
    })?;
    Ok(pt)
}

fn hkdf_expand(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk: Hkdf<Sha512> = Hkdf::new(None, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow!("hkdf expand"))?;
    Ok(okm)
}

fn blake3_keyed(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key32 = [0u8; 32];
    key32.copy_from_slice(&key[..32]);
    blake3::keyed_hash(&key32, data).into()
}

fn header_ad_prelude(suite_id: u16, uuid: &[u8]) -> Vec<u8> {
    // Bind wrapped key to suite + UUID
    let mut ad = Vec::with_capacity(2 + uuid.len());
    ad.extend_from_slice(&suite_id.to_le_bytes());
    ad.extend_from_slice(uuid);
    ad
}

fn chunk_info(idx: u64) -> Vec<u8> {
    let mut info = b"rse.chunk".to_vec();
    info.extend_from_slice(&idx.to_le_bytes());
    info
}

fn chunk_ad(
    suite_id: u16,
    uuid: &[u8; 16],
    idx: u64,
    total: u64,
    pt_size: u64,
    chunk_size: u64,
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(2 + 16 + 8 * 4);
    ad.extend_from_slice(&suite_id.to_le_bytes());
    ad.extend_from_slice(uuid);
    ad.extend_from_slice(&idx.to_le_bytes());
    ad.extend_from_slice(&total.to_le_bytes());
    ad.extend_from_slice(&pt_size.to_le_bytes());
    ad.extend_from_slice(&chunk_size.to_le_bytes());
    ad
}

fn chunk_count(plaintext_size: u64, chunk_size: u32) -> u64 {
    if chunk_size == 0 {
        return 0;
    }
    let cs = chunk_size as u64;
    let q = plaintext_size / cs;
    let r = plaintext_size % cs;
    if r > 0 {
        q + 1
    } else {
        q
    }
}

fn create_tmp_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn rename_replace(tmp: &Path, dest: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite && dest.exists() {
        let _ = fs::remove_file(dest);
    }
    fs::rename(tmp, dest)
}

#[cfg(unix)]
fn fsync_parent(path: &Path) -> io::Result<()> {
    let p = path.parent().unwrap_or(Path::new("."));
    let dir = OpenOptions::new().read(true).open(p)?;
    dir.sync_all()
}

#[cfg(windows)]
fn fsync_parent(_path: &Path) -> io::Result<()> {
    // Windows does not expose directory fsync in std; rely on file syncs.
    Ok(())
}

fn tmp_path_for(final_path: &Path) -> PathBuf {
    let mut p = final_path.as_os_str().to_os_string();
    p.push(".part");
    PathBuf::from(p)
}

fn default_decrypt_out(input: &Path) -> PathBuf {
    let mut s = input
        .file_name()
        .unwrap_or_else(|| OsStr::new("out.bin"))
        .to_os_string();
    // Strip .rse if present
    if let Some(name) = input.file_name().and_then(OsStr::to_str) {
        if name.ends_with(".rse") {
            let base = &name[..name.len() - 4];
            return input.with_file_name(base);
        }
    }
    // Else .dec
    s.push(".dec");
    input.with_file_name(s)
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize]);
        out.push(HEX[(x & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap()
}
