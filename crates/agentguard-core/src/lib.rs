//! Biblioteca interna del daemon AgentGuard — lógica compartida para todas las plataformas.
//!
//! Los binarios por SO (`agentguard-linux`, `agentguard-windows`, `agentguard-macos`)
//! dependen de esta lib y solo añaden su implementación específica del trait `KernelGuard`.

pub mod ca;
pub mod config;
pub mod dlp;
pub mod events;
pub mod guard;
pub mod ipc_server;
pub mod updater;
pub mod vault;

pub use ca::{CaError, LocalCa};
pub use config::{
    AgentDetection, Config, ConfigError, DlpAction, KnownAgent, SandboxConfig, WindowsConfig,
};
pub use dlp::DlpProxy;
pub use events::{SecurityEvent, ViolationKind};
pub use guard::{GuardError, KernelGuard, ProtectionLevel};
pub use ipc_server::{IpcServer, IpcServerBuilder, IpcShutdown};
pub use updater::{UpdateError, Updater};
pub use vault::{Snapshot, Vault, VaultError};
