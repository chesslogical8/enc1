//! otp – one-time-pad style XOR transformer (always in place, positional input).
//!
//! Rules:
//! - Executable, input file, and key file must all be in the SAME directory.
//! - Key file MUST be named "key.key" (next to the executable); if missing, exit.
//! - Key wraps automatically if shorter than the input.
//! - Always writes in place safely: temp file in same dir + atomic replace.
//!
//! Security note: This can be a real one-time pad *only if* the key is truly random,
//! at least as long as the plaintext, never reused, and kept secret. If the key is
//! shorter (wrapping), this is repeating-key XOR (obfuscation, not cryptography).

#![deny(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use fs2::FileExt;
use same_file::is_same_file;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(unix)]
use std::fs::OpenOptions;
use tempfile::Builder as TempBuilder;
use zeroize::Zeroize;

/* ---------------- Windows ACL helper (tighten temp file ACL) ----------- */

#[cfg(windows)]
#[allow(unsafe_code)]
mod win_acl {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use winapi::shared::minwindef::{BOOL, FALSE};
    use winapi::shared::ntdef::LPCWSTR;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::SetNamedSecurityInfoW;
    use winapi::um::securitybaseapi::GetSecurityDescriptorDacl;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        DACL_SECURITY_INFORMATION, PACL, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: LPCWSTR,
            StringSDRevision: u32,
            SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
            SecurityDescriptorSize: *mut u32,
        ) -> BOOL;
    }

    /// Apply a protected DACL from SDDL:
    /// D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)
    pub(crate) fn tighten(path: &Path) -> io::Result<()> {
        let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";

        let (sd, dacl) = sddl_to_dacl(SDDL)?;

        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        unsafe {
            LocalFree(sd as *mut _);
        }

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn sddl_to_dacl(sddl: &str) -> io::Result<(PSECURITY_DESCRIPTOR, PACL)> {
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut present: BOOL = FALSE;
        let mut defaulted: BOOL = FALSE;
        let mut pdacl: PACL = std::ptr::null_mut();

        let wides: Vec<u16> = sddl.encode_utf16().chain([0]).collect();

        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wides.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let ok2 =
            unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut pdacl, &mut defaulted) };
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

#[cfg(not(windows))]
fn tighten_dacl(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/* ---------------- Windows atomic replacement helper -------------------- */

#[cfg(windows)]
#[allow(unsafe_code)]
mod win_replace {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    // Bind ReplaceFileW directly to avoid any statement/return-type quirks.
    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut core::ffi::c_void,
            lpReserved: *mut core::ffi::c_void,
        ) -> i32; // BOOL
    }

    // Use the constant from winapi so the value is correct.
    use winapi::um::winbase::REPLACEFILE_WRITE_THROUGH;

    pub(crate) fn replace(dst: &Path, src: &Path) -> io::Result<()> {
        fn to_wide(p: &Path) -> Vec<u16> {
            p.as_os_str().encode_wide().chain([0]).collect()
        }
        let wdst = to_wide(dst);
        let wsrc = to_wide(src);

        let status = unsafe {
            ReplaceFileW(
                wdst.as_ptr(),
                wsrc.as_ptr(),
                core::ptr::null(),
                REPLACEFILE_WRITE_THROUGH as u32,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
fn atomic_replace(dst: &Path, src: &Path) -> std::io::Result<()> {
    win_replace::replace(dst, src)
}

#[cfg(not(windows))]
fn atomic_replace(dst: &Path, src: &Path) -> std::io::Result<()> {
    // On Unix, rename within the same directory atomically replaces.
    fs::rename(src, dst)
}

/* ---------------- CLI --------------------------------------------------- */

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Simple OTP-style XOR transformer (always in place). Requires key.key next to the executable."
)]
struct Args {
    /// INPUT file name (positional). If relative, it's resolved relative to the executable directory.
    #[arg(value_name = "INPUT")]
    input: PathBuf,
}

/* ---------------- Constants -------------------------------------------- */

const BUF_CAP: usize = 64 * 1024; // 64 KiB
const REQUIRED_KEY_FILE: &str = "key.key";

/* ---------------- Helpers ---------------------------------------------- */

fn canonical_parent(path: &Path) -> Result<PathBuf> {
    let c = fs::canonicalize(path)
        .with_context(|| format!("canonicalizing path '{}'", path.display()))?;
    Ok(c.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("cannot get parent for '{}'", c.display()))?)
}

fn ensure_same_dir(path: &Path, dir: &Path, what: &str) -> Result<()> {
    let p_parent = canonical_parent(path)?;
    let dir_canon = fs::canonicalize(dir)?;
    if p_parent != dir_canon {
        bail!(
            "{} must be in the same directory as the executable.\n  {} is in:  {}\n  exe is in:   {}",
            what,
            what,
            p_parent.display(),
            dir_canon.display()
        );
    }
    Ok(())
}

/// Guard that removes a temp file on drop (unless disarmed).
struct TempGuard(Option<PathBuf>);
impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(&p);
        }
    }
}

#[cfg(unix)]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let f = OpenOptions::new().read(true).open(path)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/* ---------------- Main -------------------------------------------------- */

fn main() -> Result<()> {
    let t0 = Instant::now();
    let args = Args::parse();

    // Where is the executable? (the allowed directory)
    let exe = std::env::current_exe().context("cannot determine path to executable")?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot determine executable directory"))?;
    let exe_dir = fs::canonicalize(exe_dir).context("canonicalizing executable directory")?;

    // Paths: key must be next to the executable; input resolved relative to exe dir if relative.
    let key_path = exe_dir.join(REQUIRED_KEY_FILE);

    let input_path = if args.input.is_absolute() {
        args.input.clone()
    } else {
        exe_dir.join(&args.input)
    };

    if !input_path.exists() {
        bail!("input file '{}' does not exist", input_path.display());
    }
    ensure_same_dir(&input_path, &exe_dir, "Input file")?;

    // Extra safety: refuse to operate on key.key or on the executable itself (robust, cross-platform)
    if key_path.exists() && is_same_file(&input_path, &key_path)? {
        bail!("refusing to transform '{}'", REQUIRED_KEY_FILE);
    }
    if is_same_file(&input_path, &exe)? {
        bail!("refusing to transform the executable itself");
    }

    // Open input + lock (exclusive)
    let mut in_f = File::open(&input_path)
        .with_context(|| format!("opening input '{}'", input_path.display()))?;
    FileExt::lock_exclusive(&in_f).context("locking input file for exclusive access")?;

    // Open key + lock (shared), then check it is non-empty (TOCTOU-safe)
    let mut key_f = File::open(&key_path)
        .with_context(|| format!("opening key '{}'", key_path.display()))?;
    FileExt::lock_shared(&key_f).context("locking key file for shared read")?;
    if key_f.metadata()?.len() == 0 {
        bail!("key file is empty");
    }

    // Capture original destination metadata for preservation.
    let orig_meta = fs::metadata(&input_path)?;
    let orig_perms = orig_meta.permissions();

    #[cfg(unix)]
    let orig_mode = {
        use std::os::unix::fs::PermissionsExt;
        orig_perms.mode()
    };

    #[cfg(windows)]
    let was_readonly = orig_perms.readonly();

    // Create a temp file in the same directory
    let tmp = TempBuilder::new()
        .prefix(".otp-tmp-")
        .tempfile_in(&exe_dir)
        .context("creating temporary file for in-place transform")?;
    let (mut out_f, tmp_path) = tmp.keep().context("persisting temporary file")?;
    let mut tmp_guard = TempGuard(Some(tmp_path.clone())); // ensure cleanup on any failure
    FileExt::lock_exclusive(&out_f).context("locking temporary output file")?;

    // (Unix) pre-set the temp file's mode to match the original target, so post-rename mode is preserved.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, PermissionsExt::from_mode(orig_mode))
            .context("setting temporary file permissions to match target")?;
    }

    // Tighten ACL on the temp file (Windows only). Destination's ACL will be preserved on replace.
    #[cfg(windows)]
    tighten_dacl(&tmp_path)
        .with_context(|| format!("setting restrictive ACL on '{}'", tmp_path.display()))?;

    // XOR stream, wrapping key as needed
    let mut data_buf = vec![0u8; BUF_CAP];
    let mut key_buf = vec![0u8; BUF_CAP];

    loop {
        let n = in_f.read(&mut data_buf)?;
        if n == 0 {
            break;
        }
        fill_key_slice(&mut key_f, &mut key_buf[..n])?;
        for (d, k) in data_buf[..n].iter_mut().zip(&key_buf[..n]) {
            *d ^= *k;
        }
        out_f.write_all(&data_buf[..n])?;
        data_buf[..n].zeroize();
        key_buf[..n].zeroize();
    }
    out_f.flush()?;
    out_f.sync_all()?; // ensure bytes + metadata hit disk for the temp

    // Close handles before replacement (esp. for Windows)
    drop(in_f);
    drop(key_f);
    drop(out_f);

    // Windows: clear read-only bit temporarily so replacement can proceed;
    // we'll restore it if it was originally set.
    #[cfg(windows)]
    {
        if was_readonly {
            let mut perms = fs::metadata(&input_path)?.permissions();
            perms.set_readonly(false);
            fs::set_permissions(&input_path, perms)?;
        }
    }

    // Atomically replace the input with the transformed temp file
    atomic_replace(&input_path, &tmp_path).with_context(|| {
        format!(
            "replacing '{}' with transformed data",
            input_path.display()
        )
    })?;

    // Replacement succeeded—disarm temp cleanup.
    tmp_guard.0 = None;

    // Persist the rename; real fsync on Unix, no-op elsewhere.
    fsync_dir(&exe_dir).context("fsync directory after rename")?;

    // (Windows) Restore read-only bit if needed.
    #[cfg(windows)]
    {
        if was_readonly {
            let mut perms = fs::metadata(&input_path)?.permissions();
            perms.set_readonly(true);
            fs::set_permissions(&input_path, perms)?;
        }
    }

    eprintln!(
        "✓ in-place XOR (OTP-style) '{}' using key 'key.key' in {:.2?}",
        input_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        t0.elapsed()
    );

    Ok(())
}

/* ---------------- XOR helper ------------------------------------------- */

fn fill_key_slice<R: Read + Seek>(key: &mut R, dest: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < dest.len() {
        let n = key.read(&mut dest[filled..])?;
        if n == 0 {
            key.seek(SeekFrom::Start(0))?;
            let n2 = key.read(&mut dest[filled..])?;
            if n2 == 0 {
                bail!("key file became unreadable during processing");
            }
            filled += n2;
        } else {
            filled += n;
        }
    }
    Ok(())
}
