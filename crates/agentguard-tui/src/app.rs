//! Estado global de la aplicación TUI.

use agentguard_common::SnapshotInfo;

use crate::ipc::IpcClient;

#[derive(Debug, Default, Clone, PartialEq)]
pub enum Tab {
    #[default]
    Dashboard,
    Zones,
    Incidents,
    Snapshots,
}

impl Tab {
    pub fn all() -> [Tab; 4] {
        [Tab::Dashboard, Tab::Zones, Tab::Incidents, Tab::Snapshots]
    }

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Zones => "Protected Zones",
            Tab::Incidents => "Recent Incidents",
            Tab::Snapshots => "Snapshots",
        }
    }
}

/// Estado del daemon obtenido vía IPC.
#[derive(Debug, Default, Clone)]
pub struct DaemonStatus {
    pub connected: bool,
    pub version: String,
    pub guard_backend: String,
    pub protection_level: String,
    pub dlp_enabled: bool,
    pub paused: bool,
    pub protected_dirs: Vec<String>,
    pub protected_files: Vec<String>,
    pub sandbox_mode: Option<String>,
    pub active_sandboxes: u32,
    pub capabilities: Option<String>,
    pub incidents_count: u64,
}

#[derive(Debug, Default, Clone)]
pub struct AppState {
    pub current_tab: Tab,
    pub daemon: DaemonStatus,
    pub incidents: Vec<String>,
    pub snapshots: Vec<SnapshotInfo>,
    pub status_message: Option<String>,
    pub error_message: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
        self.status_message = None;
    }

    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some(msg);
        self.error_message = None;
    }

    pub fn clear_message(&mut self) {
        self.status_message = None;
        self.error_message = None;
    }

    /// Refresca todos los datos desde el daemon.
    pub fn refresh(&mut self, client: &IpcClient) {
        match client.status() {
            Ok(resp) => {
                self.daemon.connected = true;
                if let agentguard_common::IpcResponse::StatusData {
                    version,
                    guard_backend,
                    protection_level,
                    dlp_enabled,
                    paused,
                    protected_dirs,
                    protected_files,
                    sandbox_mode,
                    active_sandboxes,
                    capabilities,
                    incidents_count,
                } = resp
                {
                    self.daemon.version = version;
                    self.daemon.guard_backend = guard_backend;
                    self.daemon.protection_level = protection_level;
                    self.daemon.dlp_enabled = dlp_enabled;
                    self.daemon.paused = paused;
                    self.daemon.protected_dirs = protected_dirs;
                    self.daemon.protected_files = protected_files;
                    self.daemon.sandbox_mode = sandbox_mode;
                    self.daemon.active_sandboxes = active_sandboxes;
                    self.daemon.capabilities = capabilities;
                    self.daemon.incidents_count = incidents_count;
                }
                self.clear_message();
            }
            Err(e) => {
                self.daemon.connected = false;
                self.set_error(format!("Daemon disconnected: {e}"));
            }
        }

        match client.incidents(20) {
            Ok(lines) => self.incidents = lines,
            Err(_) => {
                if self.daemon.connected {
                    self.incidents = vec!["No incidents recorded yet.".into()];
                }
            }
        }

        match client.snapshots() {
            Ok(snaps) => self.snapshots = snaps,
            Err(_) => {
                if self.daemon.connected {
                    self.snapshots = Vec::new();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_all_returns_four_tabs() {
        assert_eq!(Tab::all().len(), 4);
    }

    #[test]
    fn tab_titles_are_unique() {
        let titles: Vec<&str> = Tab::all().iter().map(|t| t.title()).collect();
        let mut deduped: Vec<&str> = titles.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(titles.len(), deduped.len(), "all tab titles must be unique");
    }

    #[test]
    fn tab_default_is_dashboard() {
        assert_eq!(Tab::default(), Tab::Dashboard);
    }

    #[test]
    fn daemon_status_defaults_to_disconnected() {
        let ds = DaemonStatus::default();
        assert!(!ds.connected);
        assert!(ds.version.is_empty());
        assert!(ds.guard_backend.is_empty());
        assert_eq!(ds.incidents_count, 0);
    }

    #[test]
    fn app_state_new_is_default() {
        let state = AppState::new();
        assert_eq!(state.current_tab, Tab::Dashboard);
        assert!(!state.daemon.connected);
        assert!(state.incidents.is_empty());
        assert!(state.snapshots.is_empty());
    }

    #[test]
    fn set_error_clears_status() {
        let mut state = AppState::new();
        state.set_status("ok".into());
        state.set_error("fail".into());
        assert_eq!(state.error_message, Some("fail".into()));
        assert_eq!(state.status_message, None);
    }

    #[test]
    fn set_status_clears_error() {
        let mut state = AppState::new();
        state.set_error("fail".into());
        state.set_status("ok".into());
        assert_eq!(state.status_message, Some("ok".into()));
        assert_eq!(state.error_message, None);
    }

    #[test]
    fn clear_message_clears_both() {
        let mut state = AppState::new();
        state.set_error("fail".into());
        state.set_status("ok".into());
        state.clear_message();
        assert_eq!(state.error_message, None);
        assert_eq!(state.status_message, None);
    }
}
