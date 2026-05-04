//! AgentGuard Linux daemon — library and binary crate.
//!
//! Exports sandbox, process_watcher, and guard modules.

pub mod guard;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod sandbox;

#[cfg(feature = "ebpf")]
pub mod process_watcher;
