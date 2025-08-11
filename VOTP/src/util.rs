//! util.rs – Windows ACL helper + no-op stub for non-Windows.
//! Applies a protected DACL allowing Owner, Administrators, and SYSTEM full control.
//!
//! We convert SDDL → security descriptor via a direct FFI declaration to avoid
//! depending on `winapi::um::sddl` feature/module (not always enabled).

// ---------------- Windows implementation ---------------------------------
#[cfg(windows)]
#[allow(unsafe_code)]
mod win_acl {
    use std::{io, path::Path, ptr};
    use std::os::windows::ffi::OsStrExt;

    use winapi::shared::minwindef::{BOOL, FALSE};
    use winapi::shared::winerror::ERROR_SUCCESS;
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
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        unsafe { LocalFree(sd as *mut _); }

        if status != ERROR_SUCCESS {
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

// Re-export for callers in the rest of the code-base.
#[cfg(windows)]
pub(crate) use win_acl::tighten as tighten_dacl;

// ---------------- Non-Windows stub --------------------------------------
#[cfg(not(windows))]
#[allow(dead_code)]
pub(crate) fn tighten_dacl(_path: &std::path::Path) -> std::io::Result<()> {
    // POSIX platforms already use chmod(0o600) elsewhere.
    Ok(())
}
