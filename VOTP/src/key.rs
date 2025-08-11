//! key.rs – deterministic high-strength key material generator
//!
//! Build stand-alone with:
//!   cargo run --release --features keygen -- keygen 10MB my.key
//!
//! Integrated into votp’s CLI as the `keygen` sub-command.

#![cfg(feature = "keygen")]

use std::{
    fs::File,
    io::{self, Write},
    process,
    time::Instant,
};

#[cfg(unix)]
use std::fs::OpenOptions;

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::Block; // public Block type (1 KiB) for with_memory API
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake3;
use clap::{Args, ValueEnum};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(windows)]
use crate::util; // tighten_dacl

/// **Updated defaults**
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
const DEFAULT_ARGON2_TIME_COST: u32 = 3;

/// Hard cap on generated key size (bytes)
const MAX_KEY_BYTES: u128 = 20 * 1024 * 1024 * 1024; // 20 GiB

/// Require ≥16 random bytes of salt (24+ base64 chars).
const MIN_SALT_LEN_RAW: usize = 16;

#[derive(Copy, Clone, ValueEnum, Debug)]
pub enum StreamAlgo {
    Blake3,
    Chacha,
}

impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamAlgo::Blake3 => write!(f, "blake3"),
            StreamAlgo::Chacha => write!(f, "chacha"),
        }
    }
}

/// CLI for the `keygen` sub-command
#[derive(Args, Debug)]
#[command(
    about = "Deterministic cryptographic key generator (NOT a perfect OTP)",
    after_help = "Size format: <n><B|KB|MB|GB> (case-insensitive)\n\
                  B  = bytes\n\
                  KB = kibibytes (×1024)\n\
                  MB = mebibytes (×1024²)\n\
                  GB = gibibytes (×1024³)\n\
                  Max key size = 20 GiB\n\
                  A unique, random salt *must* be supplied with --salt BASE64 (≥16 random bytes; 24+ base64 chars)."
)]
pub struct KeyArgs {
    /// Key size (e.g. 32B, 10KB, 3MB, 1GB)
    pub size: String,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    pub output: String,

    /// Output stream algorithm
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    pub algo: StreamAlgo,

    /// Mandatory salt (base64)
    #[arg(short, long)]
    pub salt: Option<String>,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    pub argon2_memory: u32,

    /// Argon2 time cost
    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME_COST)]
    pub argon2_time: u32,

    /// Argon2 parallelism (0 = auto)
    #[arg(long, default_value_t = 0)]
    pub argon2_par: u32,

    /// Convenience helper: generate a fresh base-64 salt of N bytes and exit
    #[arg(long = "gen-salt")]
    pub gen_salt: Option<usize>,
}

/* ------------------------------------------------------------------------- */

/// Generate a random salt, print it and exit.
fn gen_and_print_salt(n: usize) -> ! {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    println!("{}", B64.encode(&buf));
    process::exit(0);
}

/// Parallelism helper (0 = auto).
fn effective_parallelism(user: u32) -> u32 {
    if user != 0 {
        return user;
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

pub fn run(k: KeyArgs) -> io::Result<()> {
    /* ---------- optional salt generator fast-path --------------------- */
    if let Some(n) = k.gen_salt {
        gen_and_print_salt(n);
    }

    /* ---------- parse size ------------------------------------------- */
    let size = parse_size(&k.size).unwrap_or_else(|e| {
        eprintln!("❌ {e}");
        process::exit(1);
    });

    /* ---------- password + confirm (constant-time compare) ----------- */
    let pwd1: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Enter password: ")?);
    let pwd2: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Confirm password: ")?);

    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    /* ---------- salt -------------------------------------------------- */
    let salt_b64: Zeroizing<String> = Zeroizing::new(k.salt.unwrap_or_else(|| {
        eprintln!("❌ A unique base-64 salt is required (use --salt).");
        process::exit(1);
    }));

    let salt_bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(match B64.decode(&*salt_b64) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("❌ Salt is not valid base64");
                process::exit(1);
            }
        });

    if salt_bytes.len() < MIN_SALT_LEN_RAW {
        eprintln!("❌ Salt too short – need ≥{MIN_SALT_LEN_RAW} random bytes (24+ base64 chars).");
        process::exit(1);
    }

    /* ---------- derive 32-byte seed ---------------------------------- */
    let par_eff = effective_parallelism(k.argon2_par);
    println!(
        "📦 Generating {size} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        k.algo, k.argon2_memory, k.argon2_time, par_eff
    );

    let start = Instant::now();
    let mut seed = derive_seed(&pwd1, &salt_bytes, k.argon2_memory, k.argon2_time, par_eff);

    /* ---------- stream generator ------------------------------------- */
    let result = match k.algo {
        StreamAlgo::Blake3 => write_blake3(&k.output, &seed, size),
        StreamAlgo::Chacha => write_chacha(&k.output, &seed, size),
    };

    /* ---------- clean-up --------------------------------------------- */
    seed.zeroize();
    result?;
    println!("✅ Key written to '{}' in {:.2?}", k.output, start.elapsed());
    Ok(())
}

/* ========== internal helpers =========================================== */

fn derive_seed(
    password: &Zeroizing<String>,
    salt_bytes: &[u8],
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    if mem > 4 * 1024 * 1024 {
        eprintln!("❌ argon2-memory ({mem} KiB) exceeds 4 GiB limit.");
        process::exit(1);
    }

    let params = match Params::new(mem, time, par, None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ invalid Argon2 parameters: {e}");
            process::exit(1);
        }
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use the "no-alloc" API: provide our own memory blocks (1 KiB each)
    let mut seed = [0u8; 32];
    let blocks_len = mem as usize; // mem is in KiB, Block::SIZE == 1024 bytes
    let mut blocks = vec![Block::new(); blocks_len];
    argon2
        .hash_password_into_with_memory(
            password.as_bytes(),
            salt_bytes,
            &mut seed,
            &mut blocks,
        )
        .unwrap_or_else(|e| {
            eprintln!("❌ Argon2id hashing failed: {e}");
            process::exit(1);
        });

    // Wipe Argon2 work memory before deallocation.
    for b in &mut blocks {
        *b = Block::new();
    }

    seed
}

fn write_blake3(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(path, size, |buf| xof.fill(buf))
}

fn write_chacha(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(path, size, |buf| rng.fill_bytes(buf))
}

fn stream_to_file<F>(path: &str, mut remaining: usize, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    // Create with 0600 on Unix at creation time (avoid umask window).
    let file: File = {
        #[cfg(unix)]
        {
            let mut opt = OpenOptions::new();
            opt.write(true).create(true).truncate(true).mode(0o600);
            opt.open(path)?
        }
        #[cfg(not(unix))]
        {
            File::create(path)?
        }
    };

    /* ---- tighten ACLs on Windows ------------------------------------ */
    #[cfg(windows)]
    util::tighten_dacl(std::path::Path::new(path))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Direct write, using a Zeroizing scratch buffer
    let mut buf = Zeroizing::new([0u8; 8192]);
    let mut f = file;

    while remaining != 0 {
        let n = remaining.min(buf.len());
        fill(&mut buf[..n]);
        f.write_all(&buf[..n])?;
        remaining -= n;
    }
    f.flush()?;
    f.sync_all()
}

/// Parse sizes like “32B”, “10KB”, “3MB”, “2GB” (case-insensitive).
fn parse_size(arg: &str) -> Result<usize, String> {
    let s = arg.trim().to_uppercase();

    let (num, mul): (&str, u128) = if let Some(n) = s.strip_suffix("GB") {
        (n, 1024u128.pow(3))
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1024u128.pow(2))
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1024u128)
    } else if let Some(n) = s.strip_suffix('B') {
        (n, 1)
    } else {
        return Err(format!(
            "Invalid size format: '{arg}' (expected <n>B|KB|MB|GB)"
        ));
    };

    let n: u128 = num
        .trim()
        .parse()
        .map_err(|_| format!("Invalid number in size specifier: '{arg}'"))?;

    let bytes = n
        .checked_mul(mul)
        .ok_or_else(|| format!("Size overflow for: '{arg}'"))?;

    if bytes > MAX_KEY_BYTES {
        return Err(format!(
            "Key size {} bytes exceeds maximum of {} bytes (20 GiB)",
            bytes, MAX_KEY_BYTES
        ));
    }

    usize::try_from(bytes)
        .map_err(|_| format!("Size too large for this platform: '{arg}'"))
}

