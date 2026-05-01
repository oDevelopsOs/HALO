//! Biblioteca interna del daemon AgentGuard.
//!
//! El binario (`main.rs`) compone los módulos expuestos aquí. Separar el
//! código en una lib nos permite escribir tests de integración desde
//! `crates/agentguard-daemon/tests/`.

pub mod config;
pub mod dlp;
pub mod events;
pub mod guard;
pub mod vault;

pub use config::{Config, ConfigError, DlpAction};
pub use events::{SecurityEvent, ViolationKind};
pub use guard::{select_guard, GuardError, KernelGuard, ProtectionLevel};
pub use vault::{Snapshot, Vault, VaultError};
