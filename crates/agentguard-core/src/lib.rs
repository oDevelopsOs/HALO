//! Biblioteca interna del daemon AgentGuard — lógica compartida para todas las plataformas.
//!
//! Los binarios por SO (`agentguard-linux`, `agentguard-windows`)
//! dependen de esta lib y solo añaden su implementación específica del trait `KernelGuard`.

pub mod ca;
pub mod config;
pub mod db;
pub mod dlp;
pub mod events;
pub mod guard;
pub mod ipc_server;
pub mod ota;
pub mod project_discoverer;
pub mod smart_guardian;
pub mod smart_protect;
pub mod updater;
pub mod vault;

pub use ca::{CaError, LocalCa};
pub use config::{
    AgentDetection, Config, ConfigError, DlpAction, GuardianConfig, GuardianMode, KnownAgent,
    ProtectionProfile, RedactionStyle, RiskLevel, SandboxConfig, SmartProtection, WindowsConfig,
};
pub use dlp::{DlpProxy, PromptSanitizer, RedactionEngine};
pub use events::{SecurityEvent, ViolationKind};
pub use guard::{GuardError, KernelGuard, ProtectionLevel};
pub use ipc_server::{IpcServer, IpcServerBuilder, IpcShutdown};
pub use project_discoverer::{ProjectContext, ProjectDiscoverer, ProjectType};
pub use smart_guardian::SmartGuardian;
pub use smart_protect::{generate_smart_suggestions, DetectedAgent, ProtectionSuggestion};
pub use updater::{UpdateError, Updater};
pub use vault::{Snapshot, Vault, VaultError};
