//! AgentGuard Linux daemon — library and binary crate.
//!
//! Exports sandbox, process_watcher, displacement, autoheal, seccomp, and guard modules.

pub mod autoheal;
#[cfg(target_os = "linux")]
pub mod displacement;
#[cfg(target_os = "linux")]
pub mod fd_broker;
pub mod guard;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod seccomp;
#[cfg(target_os = "linux")]
pub mod seccomp_notif;
pub mod shim_config;
pub mod telemetry;

#[cfg(feature = "ebpf")]
pub mod process_watcher;
