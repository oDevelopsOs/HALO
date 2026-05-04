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

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::path::Path;
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::*;
    use windows::Win32::Security::Authorization::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::Storage::FileSystem::*;

    use agentguard_core::config::Config;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum SandboxError {
        #[error("Failed to create AppContainer profile: {0}")]
        ProfileCreation(String),
        #[error("Failed to launch process in AppContainer: {0}")]
        ProcessLaunch(String),
        #[error("Failed to apply DENY ACE to {path}: {err}")]
        AceApplication { path: String, err: String },
    }

    pub struct SandboxLauncher {
        config: Config,
    }

    impl SandboxLauncher {
        pub fn new(config: Config) -> Self {
            Self { config }
        }

        /// Lanza un proceso dentro de AppContainer/LPAC.
        pub async fn launch(
            &self,
            agent_exe: &str,
            project_dir: &Path,
            _with_extra_isolation: bool,
        ) -> Result<u32, anyhow::Error> {
            unsafe {
                // 1. Crear perfil AppContainer
                let container_name = format!("AgentGuard-{}\0", agent_exe)
                    .encode_utf16()
                    .collect::<Vec<u16>>();
                let display_name = format!("AgentGuard sandbox for {}\0", agent_exe)
                    .encode_utf16()
                    .collect::<Vec<u16>>();
                let description = "Sandboxed AI agent\0"
                    .encode_utf16()
                    .collect::<Vec<u16>>();

                let mut app_container_sid: PSID = PSID::default();

                let hr = CreateAppContainerProfile(
                    windows::core::PCWSTR(container_name.as_ptr()),
                    windows::core::PCWSTR(display_name.as_ptr()),
                    windows::core::PCWSTR(description.as_ptr()),
                    None,
                    &mut app_container_sid,
                );

                if hr.is_err() {
                    DeriveAppContainerSidFromAppContainerName(
                        windows::core::PCWSTR(container_name.as_ptr()),
                        &mut app_container_sid,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("Cannot get AppContainer SID: {:?}", e)
                    })?;
                }

                // 2. Aplicar DENY ACEs en rutas protegidas
                for protected_dir in &self.config.protected_dirs {
                    if let Err(e) =
                        apply_deny_ace(protected_dir, app_container_sid)
                    {
                        tracing::warn!(
                            path = %protected_dir.display(),
                            error = %e,
                            "could not apply DENY ACE — AppContainer provides baseline isolation"
                        );
                    }
                }

                // 3. Preparar SECURITY_CAPABILITIES
                let capabilities = SECURITY_CAPABILITIES {
                    AppContainerSid: app_container_sid,
                    Capabilities: std::ptr::null_mut(),
                    CapabilityCount: 0,
                    Reserved: 0,
                };

                // 4. Preparar STARTUPINFOEX con atributo de AppContainer
                let mut attr_list_size: usize = 0;
                InitializeProcThreadAttributeList(
                    LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                    1,
                    0,
                    &mut attr_list_size,
                );

                let mut attr_list_buf = vec![0u8; attr_list_size];
                let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(
                    attr_list_buf.as_mut_ptr() as *mut _,
                );

                InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)
                    .map_err(|e| {
                        anyhow::anyhow!("InitializeProcThreadAttributeList: {:?}", e)
                    })?;

                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    Some(&capabilities as *const _ as *const std::ffi::c_void),
                    std::mem::size_of::<SECURITY_CAPABILITIES>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    anyhow::anyhow!("UpdateProcThreadAttribute: {:?}", e)
                })?;

                let mut startup_info = STARTUPINFOEXW::default();
                startup_info.StartupInfo.cb =
                    std::mem::size_of::<STARTUPINFOEXW>() as u32;
                startup_info.lpAttributeList = attr_list;

                // 5. Variables de entorno con el proxy DLP
                let env_block = build_env_block(&self.config);

                // 6. Comando a ejecutar
                let mut cmd_line: Vec<u16> =
                    format!("{}\0", agent_exe).encode_utf16().collect();
                let project_str: Vec<u16> = format!("{}\0", project_dir.display())
                    .encode_utf16()
                    .collect();

                let mut process_info = PROCESS_INFORMATION::default();

                // 7. Crear el proceso en AppContainer
                CreateProcessW(
                    None,
                    windows::core::PWSTR(cmd_line.as_mut_ptr()),
                    None,
                    None,
                    false,
                    EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_CONSOLE,
                    Some(env_block.as_ptr() as *const std::ffi::c_void),
                    windows::core::PCWSTR(project_str.as_ptr()),
                    &startup_info.StartupInfo as *const _ as *const STARTUPINFOW,
                    &mut process_info,
                )
                .map_err(|e| {
                    anyhow::anyhow!("CreateProcessW in AppContainer failed: {:?}", e)
                })?;

                let pid = process_info.dwProcessId;

                CloseHandle(process_info.hThread).ok();

                // Monitorizar el proceso en background
                tokio::spawn(async move {
                    WaitForSingleObject(process_info.hProcess, INFINITE);
                    CloseHandle(process_info.hProcess).ok();
                    tracing::info!(pid, "sandboxed agent exited");
                });

                FreeSid(app_container_sid);
                DeleteProcThreadAttributeList(attr_list);

                tracing::info!(
                    agent = %agent_exe,
                    pid,
                    "agent launched in AppContainer sandbox"
                );

                Ok(pid)
            }
        }

        pub fn check_capabilities() -> SandboxCapabilities {
            SandboxCapabilities {
                appcontainer_available: true,
                etw_available: true,
            }
        }
    }

    /// Aplica una DENY ACE al SID del AppContainer en la ruta dada.
    fn apply_deny_ace(path: &Path, container_sid: PSID) -> Result<(), SandboxError> {
        let path_wide: Vec<u16> = format!("{}\0", path.display())
            .encode_utf16()
            .collect();

        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();

            GetNamedSecurityInfoW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
            .map_err(|e| SandboxError::AceApplication {
                path: path.display().to_string(),
                err: format!("{:?}", e),
            })?;

            let mut ea = EXPLICIT_ACCESS_W::default();
            ea.grfAccessPermissions = FILE_ALL_ACCESS.0;
            ea.grfAccessMode = DENY_ACCESS;
            ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName =
                windows::core::PWSTR(container_sid.0 as *mut u16);

            let mut new_dacl: *mut ACL = std::ptr::null_mut();
            SetEntriesInAclW(Some(&[ea]), Some(dacl), &mut new_dacl)
                .map_err(|e| SandboxError::AceApplication {
                    path: path.display().to_string(),
                    err: format!("{:?}", e),
                })?;

            SetNamedSecurityInfoW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl),
                None,
            )
            .map_err(|e| SandboxError::AceApplication {
                path: path.display().to_string(),
                err: format!("{:?}", e),
            })?;

            LocalFree(HLOCAL(new_dacl as *mut std::ffi::c_void));
            LocalFree(HLOCAL(sd.0));
        }

        tracing::info!(path = %path.display(), "DENY ACE applied for AppContainer");
        Ok(())
    }

    /// Construye un bloque de variables de entorno en formato Windows.
    fn build_env_block(config: &Config) -> Vec<u16> {
        let proxy_url = format!("http://127.0.0.1:{}", config.dlp.proxy_port);
        let vars = [
            format!("HTTP_PROXY={}", proxy_url),
            format!("HTTPS_PROXY={}", proxy_url),
            format!("http_proxy={}", proxy_url),
            format!("https_proxy={}", proxy_url),
            "AGENTGUARD_SANDBOXED=1".to_string(),
        ];

        let mut block: Vec<u16> = Vec::new();
        for var in &vars {
            block.extend(var.encode_utf16());
            block.push(0);
        }
        block.push(0);
        block
    }

    #[derive(Debug, Clone)]
    pub struct SandboxCapabilities {
        pub appcontainer_available: bool,
        pub etw_available: bool,
    }

    impl SandboxCapabilities {
        pub fn effective_mode(&self, requested: &str) -> &'static str {
            match requested {
                "sandbox" | "hybrid" if self.appcontainer_available => "sandbox",
                _ => "monitor",
            }
        }

        pub fn report(&self) -> String {
            format!(
                "AppContainer={} ETW={}",
                if self.appcontainer_available { "yes" } else { "no" },
                if self.etw_available { "yes" } else { "no" },
            )
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
mod stub_impl {
    use std::path::Path;
    use agentguard_core::config::Config;

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
        pub fn effective_mode(&self, _requested: &str) -> &'static str {
            "monitor"
        }

        pub fn report(&self) -> String {
            "no sandbox capabilities on this platform".to_string()
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;
