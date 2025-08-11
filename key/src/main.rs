///// key (single-file) – deterministic high-strength key material generator
/////
///// New UX: two-password mode (no base64). The second password (“pepper”)
///// is hashed into a secret salt, making this strictly stronger and friendlier.
/////
///// Usage examples:
/////   key 10485760 -o key.key
/////   key 1073741824 --algo chacha
/////
///// Notes:
/////   • Size is BYTES only (min 1, max 20 GiB).
/////   • This is NOT a perfect OTP: reusing a key or using a key shorter than data loses OTP guarantees.
/////   • Keys are raw bytes written with 0600 (Unix) or a protected DACL (Windows).

#![deny(unsafe_code)]

use std::{
    io::{self, Write},
    process,
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::Block; // 1 KiB block for with_memory API
use clap::{Parser, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/*───────────────────────────── Compile‑time “config” ─────────────────────────────*/
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

/// Change these constants to tweak defaults at compile time.
mod config {
    use super::StreamAlgo;

    /// Default stream algorithm
    pub const DEFAULT_STREAM_ALGO: StreamAlgo = StreamAlgo::Blake3;

    /// Argon2 defaults
    pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
    pub const DEFAULT_ARGON2_TIME: u32 = 3;
    /// 0 = auto (use available_parallelism)
    pub const DEFAULT_ARGON2_PAR: u32 = 0;

    /// Maximum key size in bytes (20 GiB)
    pub const KEY_MAX_BYTES: u128 = 20 * 1024 * 1024 * 1024;

    /// I/O buffer size for streaming to file (1 MiB)
    pub const IO_BUF_SIZE: usize = 1 << 20;

    /// Seed domain separation version
    pub const SEED_CTX_VERSION: &str = "v1";

    /// Minimum pepper length (usability + basic strength)
    pub const PEPPER_MIN_CHARS: usize = 8;
}

/*────────────────────────────────── Windows ACL ──────────────────────────────────*/
/// Applies a protected DACL allowing Owner, Administrators, and SYSTEM full control.
/// Implemented here to avoid extra modules/files.

#[cfg(windows)]
#[allow(unsafe_code)]
mod win_acl {
    use std::{io, path::Path, ptr};
    use std::os::windows::ffi::OsStrExt;

    use winapi::shared::minwindef::{BOOL, FALSE};
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::SetNamedSecurityInfoW;
    use winapi::um::securitybaseapi::GetSecurityDescriptorDacl;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
        PACL,
        PSECURITY_DESCRIPTOR,
    };
    use winapi::shared::ntdef::LPCWSTR;

    // FFI declaration (normally in sddl.h). Linked from advapi32.
    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: LPCWSTR,
            StringSDRevision: u32, // SDDL_REVISION_1 = 1
            SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
            SecurityDescriptorSize: *mut u32,
        ) -> winapi::shared::minwindef::BOOL;
    }

    /// Apply a protected DACL from SDDL:
    /// D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)
    pub fn tighten(path: &Path) -> io::Result<()> {
        let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";

        let (sd, dacl) = sddl_to_dacl(SDDL)?;

        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        unsafe { LocalFree(sd as *mut _); }

        // Avoid needing the `winerror` feature: 0 == ERROR_SUCCESS
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn sddl_to_dacl(sddl: &str) -> io::Result<(PSECURITY_DESCRIPTOR, PACL)> {
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut present: BOOL = FALSE;
        let mut defaulted: BOOL = FALSE;
        let mut pdacl: PACL = ptr::null_mut();

        let wides: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wides.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let ok2 = unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut pdacl, &mut defaulted) };
        if ok2 == 0 {
            unsafe { LocalFree(psd as *mut _) };
            return Err(io::Error::last_os_error());
        }
        if present == 0 {
            unsafe { LocalFree(psd as *mut _) };
            return Err(io::Error::new(io::ErrorKind::Other, "No DACL present"));
        }
        Ok((psd, pdacl))
    }
}

#[cfg(windows)]
use win_acl::tighten as tighten_dacl;

/*───────────────────────────────── CLI definition ─────────────────────────────────*/

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Deterministic cryptographic key generator (NOT a perfect OTP)",
    after_help = "SIZE is in BYTES only (1..=20 GiB).\n\
                  You will be prompted for two passwords (the second becomes a secret salt)."
)]
struct Cli {
    /// Key size in BYTES (e.g. 32, 1048576). Allowed range: 1..=20 GiB.
    #[arg(value_name = "SIZE_BYTES")]
    size_bytes: u128,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    output: String,

    /// Output stream algorithm
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = config::DEFAULT_STREAM_ALGO)]
    algo: StreamAlgo,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_MEMORY_KIB)]
    argon2_memory: u32,

    /// Argon2 time cost (iterations)
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_TIME)]
    argon2_time: u32,

    /// Argon2 parallelism (lanes); 0 = auto
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_PAR)]
    argon2_par: u32,
}

/*─────────────────────────────────── Main ───────────────────────────────────*/

fn main() -> io::Result<()> {
    let k = Cli::parse();

    // Validate size: BYTES only
    if k.size_bytes == 0 || k.size_bytes > config::KEY_MAX_BYTES {
        eprintln!(
            "❌ SIZE_BYTES out of range: {} (allowed 1..={} bytes)",
            k.size_bytes, config::KEY_MAX_BYTES
        );
        process::exit(1);
    }

    // Password (confirm with constant-time compare); forbid empty
    fn read_password(prompt: &str) -> Zeroizing<String> {
        match prompt_password(prompt) {
            Ok(s) if !s.is_empty() => Zeroizing::new(s),
            Ok(_) => {
                eprintln!("❌ Empty password not allowed.");
                process::exit(1);
            }
            Err(e) => {
                eprintln!("❌ Failed to read password: {e}");
                process::exit(1);
            }
        }
    }
    let pwd1 = read_password("🔐 Enter password: ");
    let pwd2 = read_password("🔐 Confirm password: ");

    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    // Second password (pepper → secret salt)
    let pepper1 = read_password("🔐 Enter second password (salt/pepper): ");
    let pepper2 = read_password("🔐 Confirm second password: ");
    if pepper1.as_bytes().ct_eq(pepper2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Second passwords do not match. Aborting.");
        process::exit(1);
    }
    if pepper1.chars().count() < config::PEPPER_MIN_CHARS {
        eprintln!(
            "❌ Second password too short – need ≥{} characters.",
            config::PEPPER_MIN_CHARS
        );
        process::exit(1);
    }

    // Derive a 32‑byte secret salt from the pepper (domain-separated, versioned)
    let salt_bytes = Zeroizing::new(derive_salt_from_pepper(&pepper1).to_vec());

    // Derive 32-byte seed with Argon2id (with lane clamp)
    let mut par_eff = effective_parallelism(k.argon2_par);
    let max_par = (k.argon2_memory / 8).max(1);
    if par_eff > max_par {
        eprintln!(
            "ℹ️ Reducing Argon2 lanes from {par_eff} to {max_par} to satisfy m ≥ 8p (m={} KiB).",
            k.argon2_memory
        );
        par_eff = max_par;
    }

    println!(
        "📦 Generating {} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        k.size_bytes, k.algo, k.argon2_memory, k.argon2_time, par_eff
    );

    let start = Instant::now();

    // Raw Argon2 seed
    let mut seed_raw = derive_seed(&pwd1, &salt_bytes, k.argon2_memory, k.argon2_time, par_eff);

    // Domain-separate the stream seed so algo/params can't collide with other tools.
    let mut seed = derive_stream_seed(&seed_raw, k.algo, k.argon2_memory, k.argon2_time, par_eff);

    // Stream out key material
    let result = match k.algo {
        StreamAlgo::Blake3 => write_blake3(&k.output, &seed, k.size_bytes),
        StreamAlgo::Chacha => write_chacha(&k.output, &seed, k.size_bytes),
    };

    // Wipe seeds and pepper copies ASAP
    seed_raw.zeroize();
    seed.zeroize();

    result?;
    println!("✅ Key written to '{}' in {:.2?}", k.output, start.elapsed());
    Ok(())
}

/*──────────────────────────────── Helpers ────────────────────────────────*/

/// Parallelism helper (0 = auto).
fn effective_parallelism(user: u32) -> u32 {
    if user != 0 {
        return user.max(1);
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

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
    let blocks_len = mem as usize; // mem is in KiB; Block::SIZE == 1024 bytes
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

    // Wipe Argon2 working memory before drop.
    for b in &mut blocks {
        *b = Block::new();
    }
    seed
}

/// Derive a secret salt (32 bytes) from the second password (pepper).
fn derive_salt_from_pepper(pepper: &Zeroizing<String>) -> [u8; 32] {
    let context = format!("key/salt/pepper/{}", config::SEED_CTX_VERSION);
    blake3::derive_key(&context, pepper.as_bytes())
}

/// Domain-separate the final stream seed from the raw Argon2 seed.
/// Context is stable across program versions: "key/seed/v1".
fn derive_stream_seed(
    raw_seed: &[u8; 32],
    algo: StreamAlgo,
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    let context = format!(
        "key/seed/{}|algo={}|argon2(m={},t={},p={})",
        config::SEED_CTX_VERSION, algo, mem, time, par
    );
    blake3::derive_key(&context, raw_seed)
}

fn write_blake3(path: &str, seed: &[u8; 32], size_bytes: u128) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(path, size_bytes, |buf| xof.fill(buf))
}

fn write_chacha(path: &str, seed: &[u8; 32], size_bytes: u128) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(path, size_bytes, |buf| rng.fill_bytes(buf))
}

fn stream_to_file<F>(path: &str, mut remaining: u128, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    /* ---- open with tight permissions -------------------------------- */

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // atomic 0600 at creation
            .open(path)?;

        // Heap buffer so we don't blow stack; zeroized on drop.
        let mut buf = Zeroizing::new(vec![0u8; config::IO_BUF_SIZE]);

        while remaining != 0 {
            let n = remaining.min(config::IO_BUF_SIZE as u128) as usize;
            fill(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            remaining -= n as u128;
        }
        f.sync_all()?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        let file = std::fs::File::create(path)?;
        // Tighten ACLs immediately after creation.
        tighten_dacl(std::path::Path::new(path))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Heap buffer so we don't blow stack; zeroized on drop.
        let mut buf = Zeroizing::new(vec![0u8; config::IO_BUF_SIZE]);

        let mut f = file;
        while remaining != 0 {
            let n = remaining.min(config::IO_BUF_SIZE as u128) as usize;
            fill(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            remaining -= n as u128;
        }
        f.sync_all()?;
        return Ok(());
    }
}
