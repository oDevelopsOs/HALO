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
    use agentguard_core::config::Config;

    pub struct SandboxLauncher {
        _config: Config,
    }

    impl SandboxLauncher {
        pub fn new(config: Config) -> Self {
            Self { _config: config }
        }

        pub async fn launch(
            &self,
            _agent_exe: &str,
            _project_dir: &Path,
            _with_extra_isolation: bool,
        ) -> Result<u32, anyhow::Error> {
            // AppContainer sandbox requires Windows 10 build 15063+ with
            // SECURITY_CAPABILITIES API (currently not available in windows-rs v0.58)
            anyhow::bail!("AppContainer sandbox not yet available (requires future windows crate version)")
        }

        pub fn check_capabilities() -> SandboxCapabilities {
            SandboxCapabilities {
                appcontainer_available: false,
                etw_available: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct SandboxCapabilities {
        pub appcontainer_available: bool,
        pub etw_available: bool,
    }

    impl SandboxCapabilities {
        pub fn effective_mode(&self, _requested: &str) -> &'static str {
            "monitor"
        }

        pub fn report(&self) -> String {
            "sandbox not available on this Windows version".to_string()
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
        pub fn effective_mode(&self, _requested: &str) -> &'static str {
            "monitor"
        }

        pub fn report(&self) -> String {
            "no sandbox capabilities on this platform".to_string()
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;
