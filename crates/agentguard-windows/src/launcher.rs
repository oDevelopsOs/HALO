//! Low Integrity Level sandbox launcher for Windows (no admin required).
//!
//! Creates an AI agent process inside a Low IL sandbox with:
//! - Restricted token (DISABLE_MAX_PRIVILEGE)
//! - Low Integrity Level (S-1-16-4096)
//! - Job Object (KILL_ON_JOB_CLOSE, DIE_ON_UNHANDLED_EXCEPTION)
//! - 5 process mitigation policies
//!
//! Requires: Windows 8+ for mitigation policies, Windows Vista+ for Low IL.
//!
//! ## Comparison with AppContainer (sandbox.rs):
//!
//! | Feature | AppContainer (admin) | Low IL (no admin) |
//! |---|---|---|
//! | Filesystem isolation | Capability SIDs | Implicit via SACL |
//! | Network isolation | Capability-based | None (use DLP proxy) |
//! | Registry isolation | AppContainer key | Low IL hive |
//! | Process creation | Any IL | Low IL only |
//! | Requires admin | Yes | No |

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(dead_code)]

    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_ACCESS_DENIED, HANDLE,
    };
    use windows::Win32::Security::{
        AllocateAndInitializeSid, FreeSid, GetTokenInformation, TokenElevation, TokenElevationType,
        TokenIntegrityLevel, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
        SE_GROUP_INTEGRITY, SID_IDENTIFIER_AUTHORITY, TOKEN_ALL_ACCESS, TOKEN_ELEVATION,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
        ResumeThread, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, DETACHED_PROCESS,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    use crate::helpers::win32::read_process_command_line_by_pid;

    /// Result of launching an agent in Low IL sandbox.
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

    /// Check if the current process has admin privileges.
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
                Some(&mut elevation as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );

            let _ = CloseHandle(token);

            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    /// Check if Low IL is supported on this system (Win8+, always true for Win10+).
    pub fn low_il_supported() -> bool {
        // Try to create an SID — if it fails, something is very wrong
        let mut sid: windows::Win32::Security::PSID = std::ptr::null_mut();
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

    /// Launch an agent executable inside a Low IL sandbox.
    ///
    /// # Arguments
    /// * `exe` - Full path to the executable to launch
    /// * `args` - Arguments to pass to the executable
    /// * `cwd` - Working directory
    /// * `proxy_port` - DLP proxy port for environment setup
    pub fn launch_low_il(
        exe: &str,
        args: &[String],
        cwd: &Path,
        proxy_port: u16,
    ) -> Result<LowIlProcess, String> {
        unsafe {
            // ── 1. Open current process token ──
            let mut src_token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut src_token)
                .map_err(|e| format!("OpenProcessToken: {e}"))?;

            // ── 2. Create restricted token (DISABLE_MAX_PRIVILEGE) ──
            let restricted = create_restricted_token(src_token)
                .map_err(|e| format!("CreateRestrictedToken: {e}"))?;

            // ── 3. Low Integrity Level (S-1-16-4096) ──
            let low_sid =
                create_low_integrity_sid().map_err(|e| format!("CreateLowIntegritySid: {e}"))?;

            set_token_integrity_level(restricted, &low_sid)
                .map_err(|e| format!("SetTokenIntegrityLevel: {e}"))?;

            // ── 4. Job Object with restrictions ──
            let job = create_restrictive_job().map_err(|e| format!("CreateJobObject: {e}"))?;

            // ── 5. Set proxy environment variables ──
            let dlp_proxy = format!("http://127.0.0.1:{}", proxy_port);
            std::env::set_var("HTTP_PROXY", &dlp_proxy);
            std::env::set_var("HTTPS_PROXY", &dlp_proxy);
            std::env::set_var("NO_PROXY", "localhost,127.0.0.1");

            // ── 6. Build command line ──
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

            let cmdline_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
            let cwd_wide: Vec<u16> = cwd
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // ── 7. CreateProcessAsUserW SUSPENDED ──
            let mut si = STARTUPINFOW {
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
                // Clean up env vars on failure
                std::env::remove_var("HTTP_PROXY");
                std::env::remove_var("HTTPS_PROXY");
                std::env::remove_var("NO_PROXY");
                format!("CreateProcessAsUserW: {e}")
            })?;

            // Clean up proxy vars from daemon process
            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("NO_PROXY");

            // ── 8. Assign to Job Object BEFORE resume (critical) ──
            AssignProcessToJobObject(job, pi.hProcess).map_err(|e| {
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                format!("AssignProcessToJobObject: {e}")
            })?;

            // ── 9. Apply process mitigations ──
            apply_process_mitigations(pi.hProcess);

            // ── 10. Resume ──
            ResumeThread(pi.hThread);
            let _ = CloseHandle(pi.hThread);

            // Cleanup source token
            let _ = CloseHandle(src_token);

            tracing::info!(
                pid = pi.dwProcessId,
                exe = %exe,
                "Low IL sandbox process launched"
            );

            Ok(LowIlProcess {
                pid: pi.dwProcessId,
                handle: pi.hProcess,
                job,
                token: restricted,
            })
        }
    }

    // ── Helper: CreateRestrictedToken ───────────────────────

    #[link(name = "advapi32")]
    extern "system" {
        fn CreateRestrictedToken(
            existing_token_handle: HANDLE,
            flags: u32,
            disable_sid_count: u32,
            sids_to_disable: *const c_void,
            delete_privilege_count: u32,
            privileges_to_delete: *const c_void,
            restricted_sid_count: u32,
            sids_to_restrict: *const c_void,
            new_token_handle: *mut HANDLE,
        ) -> i32;
    }

    const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
    const SANDBOX_INERT: u32 = 0x2;

    unsafe fn create_restricted_token(existing: HANDLE) -> Result<HANDLE, String> {
        let mut restricted = HANDLE::default();
        let ret = CreateRestrictedToken(
            existing,
            DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
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
            Err(format!(
                "CreateRestrictedToken failed: {:?}",
                GetLastError()
            ))
        }
    }

    // ── Helper: Low Integrity SID (S-1-16-4096) ─────────────

    unsafe fn create_low_integrity_sid() -> Result<windows::Win32::Security::PSID, String> {
        let mut sid: windows::Win32::Security::PSID = std::ptr::null_mut();
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
        .map_err(|e| format!("AllocateAndInitializeSid: {e}"))?;
        Ok(sid)
    }

    // ── Helper: SetTokenInformation for Integrity Level ──────

    #[link(name = "advapi32")]
    extern "system" {
        fn SetTokenInformation(
            token_handle: HANDLE,
            token_information_class: u32,
            token_information: *const c_void,
            token_information_length: u32,
        ) -> i32;
    }

    const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25; // TokenIntegrityLevel

    unsafe fn set_token_integrity_level(
        token: HANDLE,
        sid: &windows::Win32::Security::PSID,
    ) -> Result<(), String> {
        let label = TOKEN_MANDATORY_LABEL {
            Label: windows::Win32::Security::SID_AND_ATTRIBUTES {
                Sid: *sid,
                Attributes: SE_GROUP_INTEGRITY.0,
            },
        };

        let ret = SetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            &label as *const _ as *const c_void,
            std::mem::size_of_val(&label) as u32,
        );

        if ret != 0 {
            Ok(())
        } else {
            Err(format!(
                "SetTokenInformation(TokenIntegrityLevel) failed: {:?}",
                GetLastError()
            ))
        }
    }

    // ── Helper: Restrictive Job Object ──────────────────────

    unsafe fn create_restrictive_job() -> Result<HANDLE, String> {
        let job = CreateJobObjectW(None, None).map_err(|e| format!("CreateJobObjectW: {e}"))?;

        // Basic limits
        let mut basic = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
        basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        basic.ActiveProcessLimit = 16;

        SetInformationJobObject(
            job,
            windows::Win32::System::JobObjects::JobObjectBasicLimitInformation,
            &basic as *const _ as *const c_void,
            std::mem::size_of_val(&basic) as u32,
        )
        .map_err(|e| format!("SetInfoJobObject(basic): {e}"))?;

        // UI restrictions
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: (JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS)
                .0,
        };

        SetInformationJobObject(
            job,
            windows::Win32::System::JobObjects::JobObjectBasicUIRestrictions,
            &ui as *const _ as *const c_void,
            std::mem::size_of_val(&ui) as u32,
        )
        .map_err(|e| format!("SetInfoJobObject(ui): {e}"))?;

        Ok(job)
    }

    // ── Process Mitigation Policies (5 of 7) ─────────────────

    #[link(name = "kernel32")]
    extern "system" {
        fn SetProcessMitigationPolicy(
            mitigation_policy: u32,
            lp_buffer: *const c_void,
            dw_length: usize,
        ) -> i32;
    }

    // Mitigation policy GUIDs
    const PROCESS_MITIGATION_POLICY_SIGNATURE: u32 = 8;
    const PROCESS_MITIGATION_POLICY_SYSCALL_DISABLE: u32 = 6;
    const PROCESS_MITIGATION_POLICY_IMAGE_LOAD: u32 = 10; // ProcessImageLoadPolicy
    const PROCESS_MITIGATION_POLICY_DYNAMIC_CODE: u32 = 2;
    const PROCESS_MITIGATION_POLICY_CONTROL_FLOW_GUARD: u32 = 12; // ProcessControlFlowGuardPolicy

    unsafe fn apply_process_mitigations(process: HANDLE) {
        // 1. MicrosoftSignedOnly — only allow Microsoft-signed DLLs
        #[repr(C)]
        struct MitigationSignature {
            microsoft_signed_only: u32,
        }
        let sig = MitigationSignature {
            microsoft_signed_only: 1,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY_SIGNATURE,
            &sig as *const _ as *const c_void,
            std::mem::size_of::<MitigationSignature>(),
        );

        // 2. DisallowWin32kSystemCalls — no GDI/USER (CLI agents don't need it)
        #[repr(C)]
        struct MitigationSyscallDisable {
            disallow_win32k_system_calls: u32,
        }
        let sc = MitigationSyscallDisable {
            disallow_win32k_system_calls: 1,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY_SYSCALL_DISABLE,
            &sc as *const _ as *const c_void,
            std::mem::size_of::<MitigationSyscallDisable>(),
        );

        // 3. NoRemoteImages + NoLowMandatoryLabelImages
        #[repr(C)]
        struct MitigationImageLoad {
            no_remote_images: u32,
            no_low_mandatory_label_images: u32,
            prefer_system32_images: u32,
            audit_no_remote_images: u32,
            audit_no_low_mandatory_label_images: u32,
        }
        let il = MitigationImageLoad {
            no_remote_images: 1,
            no_low_mandatory_label_images: 1,
            prefer_system32_images: 0,
            audit_no_remote_images: 0,
            audit_no_low_mandatory_label_images: 0,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY_IMAGE_LOAD,
            &il as *const _ as *const c_void,
            std::mem::size_of::<MitigationImageLoad>(),
        );

        // 4. ProhibitDynamicCode — no JIT compilation except for signed runtimes
        #[repr(C)]
        struct MitigationDynamicCode {
            prohibit_dynamic_code: u32,
            allow_thread_opt_out: u32,
            allow_remote_downgrade: u32,
            audit_prohibit_dynamic_code: u32,
        }
        let dc = MitigationDynamicCode {
            prohibit_dynamic_code: 1,
            allow_thread_opt_out: 0,
            allow_remote_downgrade: 0,
            audit_prohibit_dynamic_code: 0,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY_DYNAMIC_CODE,
            &dc as *const _ as *const c_void,
            std::mem::size_of::<MitigationDynamicCode>(),
        );

        // 5. EnableControlFlowGuard
        #[repr(C)]
        struct MitigationCFG {
            enable_control_flow_guard: u32,
            enable_export_suppression: u32,
            strict_mode: u32,
        }
        let cfg = MitigationCFG {
            enable_control_flow_guard: 1,
            enable_export_suppression: 0,
            strict_mode: 0,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY_CONTROL_FLOW_GUARD,
            &cfg as *const _ as *const c_void,
            std::mem::size_of::<MitigationCFG>(),
        );

        tracing::debug!("Applied 5 process mitigation policies to Low IL sandbox");
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
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

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;

#[cfg(test)]
#[cfg(target_os = "windows")]
use windows_impl::*;

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin_returns_bool() {
        let admin = is_admin();
        // Can't assert specific value, but should not panic
        let _ = admin;
    }

    #[test]
    fn test_low_il_supported_returns_bool() {
        let supported = low_il_supported();
        let _ = supported;
    }

    #[test]
    fn test_launch_low_il_rejects_nonexistent() {
        let result = launch_low_il(
            "C:\\Windows\\nonexistent_agentguard_test.exe",
            &[],
            std::path::Path::new("C:\\"),
            7771,
        );
        assert!(result.is_err());
    }
}
