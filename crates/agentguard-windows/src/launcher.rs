//! Low Integrity Level sandbox launcher for Windows (no admin required).

#![allow(dead_code)]

// ── Windows implementation ────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows::Win32::Security::{
        AllocateAndInitializeSid, FreeSid, GetTokenInformation, TokenElevation, SID_AND_ATTRIBUTES,
        SID_IDENTIFIER_AUTHORITY, TOKEN_ALL_ACCESS, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY,
    };
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, ResumeThread,
        CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, DETACHED_PROCESS, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    const SE_GROUP_INTEGRITY: u32 = 0x10;
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
    const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;

    pub struct LowIlProcess {
        pub pid: u32,
        pub handle: HANDLE,
        pub job: HANDLE,
        pub token: HANDLE,
    }

    impl Drop for LowIlProcess {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle);
                let _ = CloseHandle(self.job);
                let _ = CloseHandle(self.token);
            }
        }
    }

    pub fn is_admin() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token);
            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    pub fn low_il_supported() -> bool {
        let mut sid = windows::Win32::Security::PSID(std::ptr::null_mut());
        let auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        let result = unsafe {
            AllocateAndInitializeSid(
                &auth,
                1,
                SECURITY_MANDATORY_LOW_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if result.is_ok() {
            unsafe { FreeSid(sid) };
            true
        } else {
            false
        }
    }

    pub fn launch_low_il(
        exe: &str,
        args: &[String],
        cwd: &Path,
        proxy_port: u16,
    ) -> Result<LowIlProcess, String> {
        unsafe {
            let mut src_token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut src_token)
                .map_err(|e| format!("OpenProcessToken: {e}"))?;

            let restricted = create_restricted_token(src_token)?;
            let low_sid = create_low_integrity_sid()?;
            set_token_integrity_level(restricted, &low_sid)?;
            let job = create_restrictive_job()?;

            let dlp_proxy = format!("http://127.0.0.1:{}", proxy_port);
            std::env::set_var("HTTP_PROXY", &dlp_proxy);
            std::env::set_var("HTTPS_PROXY", &dlp_proxy);

            let mut cmdline = exe.to_string();
            for a in args {
                cmdline.push(' ');
                if a.contains(' ') {
                    cmdline.push('"');
                    cmdline.push_str(a);
                    cmdline.push('"');
                } else {
                    cmdline.push_str(a);
                }
            }
            let mut cmdline_wide: Vec<u16> =
                cmdline.encode_utf16().chain(std::iter::once(0)).collect();
            let cwd_wide: Vec<u16> = cwd
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessAsUserW(
                restricted,
                None,
                PWSTR(cmdline_wide.as_mut_ptr()),
                None,
                None,
                BOOL::from(false),
                CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                None,
                PCWSTR(cwd_wide.as_ptr()),
                &si,
                &mut pi,
            )
            .map_err(|e| {
                std::env::remove_var("HTTP_PROXY");
                std::env::remove_var("HTTPS_PROXY");
                format!("CreateProcessAsUserW: {e}")
            })?;

            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("HTTPS_PROXY");

            AssignProcessToJobObject(job, pi.hProcess).map_err(|e| {
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                format!("AssignProcessToJobObject: {e}")
            })?;

            apply_all_mitigations();
            ResumeThread(pi.hThread);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(src_token);

            Ok(LowIlProcess {
                pid: pi.dwProcessId,
                handle: pi.hProcess,
                job,
                token: restricted,
            })
        }
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn CreateRestrictedToken(
            existing_token_handle: HANDLE,
            flags: u32,
            disable_sid_count: u32,
            sids_to_disable: *const std::ffi::c_void,
            delete_privilege_count: u32,
            privileges_to_delete: *const std::ffi::c_void,
            restricted_sid_count: u32,
            sids_to_restrict: *const std::ffi::c_void,
            new_token_handle: *mut HANDLE,
        ) -> i32;
        fn SetTokenInformation(
            token_handle: HANDLE,
            token_information_class: u32,
            token_information: *const std::ffi::c_void,
            token_information_length: u32,
        ) -> i32;
    }

    unsafe fn create_restricted_token(existing: HANDLE) -> Result<HANDLE, String> {
        let mut restricted = HANDLE::default();
        let ret = CreateRestrictedToken(
            existing,
            0x1 | 0x2,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        );
        let _ = CloseHandle(existing);
        if ret != 0 {
            Ok(restricted)
        } else {
            Err("CreateRestrictedToken failed".into())
        }
    }

    unsafe fn create_low_integrity_sid() -> Result<windows::Win32::Security::PSID, String> {
        let mut sid = windows::Win32::Security::PSID(std::ptr::null_mut());
        let auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        AllocateAndInitializeSid(
            &auth,
            1,
            SECURITY_MANDATORY_LOW_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        )
        .map_err(|e| format!("SID: {e}"))?;
        Ok(sid)
    }

    unsafe fn set_token_integrity_level(
        token: HANDLE,
        sid: &windows::Win32::Security::PSID,
    ) -> Result<(), String> {
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: *sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let ret = SetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            &label as *const _ as *const std::ffi::c_void,
            std::mem::size_of_val(&label) as u32,
        );
        if ret != 0 {
            Ok(())
        } else {
            Err("SetTokenInformation failed".into())
        }
    }

    unsafe fn create_restrictive_job() -> Result<HANDLE, String> {
        let job = CreateJobObjectW(None, None).map_err(|e| format!("Job: {e}"))?;
        let mut basic = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
        basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        basic.ActiveProcessLimit = 16;
        SetInformationJobObject(
            job,
            windows::Win32::System::JobObjects::JobObjectBasicLimitInformation,
            &basic as *const _ as *const _,
            std::mem::size_of_val(&basic) as u32,
        )
        .map_err(|e| format!("JobInfo: {e}"))?;

        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
        SetInformationJobObject(
            job,
            windows::Win32::System::JobObjects::JobObjectBasicUIRestrictions,
            &ui as *const _ as *const _,
            std::mem::size_of_val(&ui) as u32,
        )
        .map_err(|e| format!("JobUI: {e}"))?;
        Ok(job)
    }

    unsafe fn apply_all_mitigations() {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetProcessMitigationPolicy(
                mitigation_policy: u32,
                lp_buffer: *const std::ffi::c_void,
                dw_length: usize,
            ) -> i32;
        }
        let sig = [1u32]; // MicrosoftSignedOnly
        let _ = SetProcessMitigationPolicy(8, sig.as_ptr() as *const _, 4);
        let sc = [1u32]; // DisallowWin32k
        let _ = SetProcessMitigationPolicy(6, sc.as_ptr() as *const _, 4);
        let il = [1u32, 1u32, 0u32, 0u32, 0u32]; // NoRemoteImages + NoLowLabel
        let _ = SetProcessMitigationPolicy(10, il.as_ptr() as *const _, 20);
        let dc = [1u32, 0u32, 0u32, 0u32]; // ProhibitDynamicCode
        let _ = SetProcessMitigationPolicy(2, dc.as_ptr() as *const _, 16);
        let cfg = [1u32, 0u32, 0u32]; // EnableCFG
        let _ = SetProcessMitigationPolicy(12, cfg.as_ptr() as *const _, 12);
    }
}

// ── Non-Windows stubs ────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub_impl {
    use std::path::Path;
    pub struct LowIlProcess {
        pub pid: u32,
    }
    pub fn is_admin() -> bool {
        false
    }
    pub fn low_il_supported() -> bool {
        false
    }
    pub fn launch_low_il(
        _exe: &str,
        _args: &[String],
        _cwd: &Path,
        _proxy_port: u16,
    ) -> Result<LowIlProcess, String> {
        Err("Low IL sandbox is only available on Windows".into())
    }
}

// ── Re-exports ────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub use stub_impl::*;
#[cfg(target_os = "windows")]
pub use windows_impl::*;
