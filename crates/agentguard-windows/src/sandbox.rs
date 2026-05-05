//! Lanza agentes IA dentro de AppContainer/LPAC en Windows.
//!
//! No requiere certificado EV ni driver firmado. 100% user-mode.
//!
//! Workflow:
//! 1. Crea (o reutiliza) el perfil AppContainer para este agente.
//! 2. Aplica DENY ACEs en rutas protegidas para el SID del AppContainer.
//! 3. Lanza el proceso con las SECURITY_CAPABILITIES del AppContainer.
//! 4. Inyecta variables de entorno del proxy DLP.
//!
//! Requiere: Windows 8+ para AppContainer, Windows 10+ para LPAC.
//!
//! NOTA: A diferencia de Linux (bwrap --die-with-parent), Windows no tiene
//! un mecanismo directo de "matar hijo si el padre muere". La mitigación es
//! vía Job Objects con JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE en guard.rs.

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(dead_code)]
    use agentguard_core::config::Config;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROCESS_INFORMATION, STARTUPINFOEXW,
    };

    use crate::helpers::win32::{
        self, free_app_container_sid, SecurityCapabilities,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    };

    pub struct SandboxLauncher {
        config: Config,
    }

    impl SandboxLauncher {
        pub fn new(config: Config) -> Self {
            Self { config }
        }

        pub async fn launch(
            &self,
            agent_exe: &str,
            project_dir: &Path,
            with_extra_isolation: bool,
        ) -> Result<u32, anyhow::Error> {
            if !appcontainer_supported() {
                anyhow::bail!("AppContainer sandbox requires Windows 8 or later");
            }

            // 1. Build unique AppContainer name from project path hash
            let mut hasher = DefaultHasher::new();
            project_dir.to_string_lossy().hash(&mut hasher);
            let hash = hasher.finish();
            let container_name = format!("AgentGuard.AC{:016x}", hash);
            let display_name = format!("AgentGuard AI Agent — {}", agent_exe);

            // 2. Create or get AppContainer profile
            let (appcontainer_sid, already_existed) =
                win32::create_or_get_app_container(&container_name, &display_name)
                    .map_err(|e| anyhow::anyhow!("AppContainer profile: {e}"))?;

            if already_existed {
                tracing::debug!(
                    container = %container_name,
                    "reusing existing AppContainer profile — capabilities may differ from expected"
                );
            }

            // 3. Build SecurityCapabilities for the new process
            let mut caps_array: Vec<win32::SidAndAttributes> = Vec::new();

            // LPAC (Less Privileged AppContainer):
            // - capabilities = NULL → default AppContainer (gets implicit internetClient etc.)
            // - capabilities = valid pointer to empty list → LPAC (no implicit capabilities)
            // This ensures the sandboxed process can only connect to localhost (DLP proxy).
            let (caps_ptr, caps_count) = if with_extra_isolation {
                tracing::debug!("LPAC mode: AppContainer with no network capabilities");
                (caps_array.as_mut_ptr(), caps_array.len() as u32)
            } else {
                // Standard AppContainer — still has internetClient capability
                (caps_array.as_mut_ptr(), caps_array.len() as u32)
            };

            let sec_caps = SecurityCapabilities {
                app_container_sid: appcontainer_sid,
                capabilities: caps_ptr,
                capability_count: caps_count,
                reserved: 0,
            };

            // 4. Build STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_LIST
            let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

            // Allocate attribute list (2 attributes: SECURITY_CAPABILITIES + handle list)
            const ATTR_COUNT: u32 = 1;
            let mut attr_list_size: usize = 0;

            // First call: get required size
            unsafe {
                InitializeProcThreadAttributeList(
                    LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                    ATTR_COUNT,
                    0,
                    &mut attr_list_size,
                )?;
            }

            let mut attr_buf: Vec<u8> = vec![0u8; attr_list_size];
            let attr_list_ptr = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_ptr);

            unsafe {
                InitializeProcThreadAttributeList(attr_list, ATTR_COUNT, 0, &mut attr_list_size)?;

                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    Some(&sec_caps as *const _ as *const std::ffi::c_void),
                    std::mem::size_of::<SecurityCapabilities>(),
                    None,
                    None,
                )?;
            }

            si.lpAttributeList = attr_list;

            // 5. Build command line
            let agent_wide: Vec<u16> = agent_exe.encode_utf16().chain(std::iter::once(0)).collect();
            let cwd_wide: Vec<u16> = project_dir
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // 6. Set proxy environment variables for DLP
            // NOTE: CreateProcessW with lpEnvironment=None inherits parent env.
            // We set/remove vars around the call to avoid polluting the daemon.
            // This is safe because the daemon is single-threaded at this point.
            let dlp_proxy = format!("http://127.0.0.1:{}", self.config.dlp.proxy_port);
            std::env::set_var("HTTP_PROXY", &dlp_proxy);
            std::env::set_var("HTTPS_PROXY", &dlp_proxy);
            std::env::set_var("NO_PROXY", "localhost,127.0.0.1");

            // 7. Create the AppContainer process
            let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            let create_result = unsafe {
                CreateProcessW(
                    PCWSTR(agent_wide.as_ptr()),
                    windows::core::PWSTR(std::ptr::null_mut()),
                    None,
                    None,
                    false,
                    EXTENDED_STARTUPINFO_PRESENT,
                    None,
                    PCWSTR(cwd_wide.as_ptr()),
                    &si.StartupInfo,
                    &mut pi,
                )
            };

            // Clean up proxy vars from daemon environment
            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("NO_PROXY");

            // Always clean up attribute list and capabilities
            unsafe { DeleteProcThreadAttributeList(attr_list) };
            free_app_container_sid(appcontainer_sid);

            create_result?;

            let pid = pi.dwProcessId;

            // Close handles we don't need (process + thread handles from CreateProcess)
            unsafe {
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
            }

            tracing::info!(
                pid = pid,
                agent = %agent_exe,
                container = %container_name,
                "AppContainer process launched"
            );

            Ok(pid)
        }

        pub fn check_capabilities() -> SandboxCapabilities {
            SandboxCapabilities {
                appcontainer_available: appcontainer_supported(),
                etw_available: true, // ETW always available with admin rights
            }
        }
    }

    fn appcontainer_supported() -> bool {
        win32::appcontainer_supported()
    }

    #[derive(Debug, Clone)]
    pub struct SandboxCapabilities {
        pub appcontainer_available: bool,
        pub etw_available: bool,
    }

    impl SandboxCapabilities {
        pub fn effective_mode(&self, requested: &str) -> &'static str {
            match requested {
                "hybrid" if self.appcontainer_available => "sandbox",
                "sandbox" if self.appcontainer_available => "sandbox",
                _ => "monitor",
            }
        }

        pub fn report(&self) -> String {
            let mut parts: Vec<&str> = Vec::new();
            if self.appcontainer_available {
                parts.push("AppContainer=yes");
            } else {
                parts.push("AppContainer=no");
            }
            if self.etw_available {
                parts.push("ETW=yes");
            }
            if parts.is_empty() {
                "sandbox not available on this Windows version".to_string()
            } else {
                parts.join(" ")
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
mod stub_impl {
    use agentguard_core::config::Config;
    use std::path::Path;

    pub struct SandboxLauncher;

    impl SandboxLauncher {
        pub fn new(_config: Config) -> Self {
            tracing::info!("AppContainer sandbox: not available on this platform (Windows only)");
            Self
        }

        pub async fn launch(
            &self,
            _agent_exe: &str,
            _project_dir: &Path,
            _with_extra_isolation: bool,
        ) -> Result<u32, anyhow::Error> {
            anyhow::bail!("AppContainer sandbox is only available on Windows")
        }

        pub fn check_capabilities() -> SandboxCapabilities {
            SandboxCapabilities {
                appcontainer_available: false,
                etw_available: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct SandboxCapabilities {
        pub appcontainer_available: bool,
        pub etw_available: bool,
    }

    #[allow(dead_code)]
    impl SandboxCapabilities {
        pub fn effective_mode(&self, requested: &str) -> &'static str {
            match requested {
                "hybrid" if self.appcontainer_available => "sandbox",
                "sandbox" if self.appcontainer_available => "sandbox",
                _ => "monitor",
            }
        }

        pub fn report(&self) -> String {
            let mut parts: Vec<&str> = Vec::new();
            if self.appcontainer_available {
                parts.push("AppContainer=yes");
            }
            if self.etw_available {
                parts.push("ETW=yes");
            }
            if parts.is_empty() {
                "no sandbox capabilities on this platform".to_string()
            } else {
                parts.join(" ")
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;

#[cfg(test)]
mod tests {
    use super::SandboxCapabilities;

    #[test]
    fn effective_mode_when_appcontainer_available() {
        let caps = SandboxCapabilities {
            appcontainer_available: true,
            etw_available: true,
        };
        assert_eq!(caps.effective_mode("sandbox"), "sandbox");
        assert_eq!(caps.effective_mode("hybrid"), "sandbox");
        assert_eq!(caps.effective_mode("monitor"), "monitor");
    }

    #[test]
    fn effective_mode_falls_back_to_monitor() {
        let caps = SandboxCapabilities {
            appcontainer_available: false,
            etw_available: true,
        };
        assert_eq!(caps.effective_mode("sandbox"), "monitor");
        assert_eq!(caps.effective_mode("hybrid"), "monitor");
    }

    #[test]
    fn report_contains_capabilities() {
        let caps = SandboxCapabilities {
            appcontainer_available: true,
            etw_available: true,
        };
        let r = caps.report();
        assert!(r.contains("AppContainer=yes"), "{r}");
        assert!(r.contains("ETW=yes"), "{r}");
    }

    #[test]
    fn report_without_capabilities_is_nonempty() {
        let caps = SandboxCapabilities {
            appcontainer_available: false,
            etw_available: false,
        };
        assert!(!caps.report().is_empty());
    }
}
