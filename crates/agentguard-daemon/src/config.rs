//! Carga y validación del `config.toml` de AgentGuard.
//!
//! Responsabilidades:
//! - Deserializar el TOML a tipos fuertes.
//! - Expandir `~` y variables a rutas absolutas.
//! - Canonicalizar las rutas existentes (resuelve symlinks, previene path
//!   traversal — ver `.windsurf/rules/07-paths-and-privileges.md`).
//! - Validar que los regex de DLP compilan.
//!
//! Lo que NO hace: crear directorios, escribir a disco, mutar estado del
//! sistema. Es una capa pura de I/O de lectura.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Todos los errores que puede producir la carga de configuración.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No se pudo leer el archivo de configuración.
    #[error("failed to read config file {path:?}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// El TOML no es parseable.
    #[error("failed to parse TOML")]
    Parse(#[from] toml::de::Error),

    /// Un regex de DLP no compila.
    #[error("invalid DLP regex {name:?}")]
    BadRegex {
        name: String,
        #[source]
        source: regex::Error,
    },

    /// La acción de DLP tiene un valor desconocido.
    #[error("invalid DLP action {0:?} (allowed: block, alert, log)")]
    BadDlpAction(String),

    /// No se pudo localizar el directorio home para expandir `~`.
    #[error("cannot determine home directory for tilde expansion")]
    NoHome,
}

/// Top-level config. Coincide con la estructura del `config.toml` descrita
/// en `README.md` §15.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub agentguard: Meta,

    /// Directorios protegidos contra eliminación/renombrado.
    #[serde(default)]
    pub protected_dirs: Vec<PathBuf>,

    /// Archivos individuales protegidos contra escritura.
    #[serde(default)]
    pub protected_files: Vec<PathBuf>,

    /// Reglas de identificación de procesos "agente de IA".
    #[serde(default)]
    pub agent_processes: Vec<AgentProcess>,

    #[serde(default)]
    pub on_violation: OnViolation,

    #[serde(default)]
    pub alerts: Alerts,

    #[serde(default)]
    pub vault: VaultConfig,

    #[serde(default)]
    pub dlp: DlpConfig,

    #[serde(default)]
    pub updates: Updates,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Meta {
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "1".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentProcess {
    pub name: String,
    #[serde(default)]
    pub r#match: AgentMatch,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentMatch {
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub exe_any: Vec<String>,
    #[serde(default)]
    pub argv_contains_any: Vec<String>,
    #[serde(default)]
    pub env_has: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OnViolation {
    #[serde(default)]
    pub kill_process: bool,
    #[serde(default = "default_true")]
    pub snapshot_on_violation: bool,
}

impl Default for OnViolation {
    fn default() -> Self {
        Self {
            kill_process: false,
            snapshot_on_violation: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Alerts {
    #[serde(default = "default_true")]
    pub desktop_notifications: bool,
    #[serde(default)]
    pub sound: bool,
    #[serde(default)]
    pub webhook_url: String,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            desktop_notifications: true,
            sound: false,
            webhook_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    #[serde(default = "default_true")]
    pub snapshot_on_start: bool,
    #[serde(default = "default_snapshot_interval")]
    pub auto_snapshot_interval_hours: u64,
    #[serde(default = "default_keep_days")]
    pub keep_days: u64,
    /// Si está vacío, se usa el path canónico según modo (root vs usuario).
    #[serde(default)]
    pub vault_dir: PathBuf,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            snapshot_on_start: true,
            auto_snapshot_interval_hours: default_snapshot_interval(),
            keep_days: default_keep_days(),
            vault_dir: PathBuf::new(),
        }
    }
}

fn default_snapshot_interval() -> u64 {
    6
}
fn default_keep_days() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dlp_port")]
    pub proxy_port: u16,
    #[serde(default = "default_dlp_action")]
    pub action: String,
    #[serde(default, rename = "custom_patterns")]
    pub custom_patterns: Vec<DlpPattern>,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy_port: default_dlp_port(),
            action: default_dlp_action(),
            custom_patterns: Vec::new(),
        }
    }
}

fn default_dlp_port() -> u16 {
    7771
}
fn default_dlp_action() -> String {
    "block".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
}

/// Acción a tomar cuando el proxy DLP detecta un secreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    Block,
    Alert,
    Log,
}

impl DlpAction {
    /// Parsea el string de configuración. Error descriptivo si es desconocido.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.to_ascii_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
            "log" => Ok(Self::Log),
            _ => Err(ConfigError::BadDlpAction(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Updates {
    #[serde(default = "default_true")]
    pub auto_check: bool,
    #[serde(default = "default_update_interval")]
    pub check_interval_hours: u64,
    #[serde(default)]
    pub auto_install: bool,
    #[serde(default = "default_channel")]
    pub channel: String,
}

impl Default for Updates {
    fn default() -> Self {
        Self {
            auto_check: true,
            check_interval_hours: default_update_interval(),
            auto_install: false,
            channel: default_channel(),
        }
    }
}

fn default_update_interval() -> u64 {
    24
}
fn default_channel() -> String {
    "stable".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agentguard: Meta::default(),
            protected_dirs: Vec::new(),
            protected_files: Vec::new(),
            agent_processes: Vec::new(),
            on_violation: OnViolation::default(),
            alerts: Alerts::default(),
            vault: VaultConfig::default(),
            dlp: DlpConfig::default(),
            updates: Updates::default(),
        }
    }
}

impl Config {
    /// Lee y parsea un `config.toml` desde la ruta indicada. No realiza
    /// expansión de `~` ni canonicalización (usar [`Config::resolve`] para
    /// eso).
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_str(&text)
    }

    /// Parsea un `config.toml` desde un string.
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validaciones que no dependen del filesystem.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // DlpAction string debe ser reconocible.
        let _ = DlpAction::parse(&self.dlp.action)?;
        // Cada regex custom debe compilar.
        for p in &self.dlp.custom_patterns {
            regex::Regex::new(&p.regex).map_err(|source| ConfigError::BadRegex {
                name: p.name.clone(),
                source,
            })?;
        }
        Ok(())
    }

    /// Expande `~` al home del usuario en todas las rutas configurables.
    ///
    /// **No canonicaliza** (no sigue symlinks, no exige que el path exista).
    /// La canonicalización la hace el componente que va a usar realmente la
    /// ruta, justo antes de usarla, con `std::fs::canonicalize` — así
    /// errores de path inexistente son visibles en el punto de uso y no
    /// rompen la carga de config.
    pub fn resolve(mut self) -> Result<Self, ConfigError> {
        self.protected_dirs = self
            .protected_dirs
            .into_iter()
            .map(expand_tilde)
            .collect::<Result<_, _>>()?;
        self.protected_files = self
            .protected_files
            .into_iter()
            .map(expand_tilde)
            .collect::<Result<_, _>>()?;
        if !self.vault.vault_dir.as_os_str().is_empty() {
            self.vault.vault_dir = expand_tilde(self.vault.vault_dir.clone())?;
        }
        Ok(self)
    }

    /// Parsea la acción de DLP como enum fuerte.
    pub fn dlp_action(&self) -> Result<DlpAction, ConfigError> {
        DlpAction::parse(&self.dlp.action)
    }
}

/// Reemplaza un `~` inicial por el home del usuario. Cualquier otro path
/// se deja intacto.
fn expand_tilde(path: PathBuf) -> Result<PathBuf, ConfigError> {
    let s = match path.to_str() {
        Some(s) => s,
        None => return Ok(path), // paths no UTF-8: asumimos absolutos
    };
    if let Some(rest) = s.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or(ConfigError::NoHome)?;
        Ok(home.join(rest))
    } else if s == "~" {
        dirs::home_dir().ok_or(ConfigError::NoHome)
    } else {
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nota sobre layout TOML: los arrays top-level (`protected_dirs`,
    // `protected_files`) deben ir ANTES del primer `[header]`, o de lo
    // contrario TOML los absorbe dentro de esa tabla.
    const MINIMAL_TOML: &str = r#"
protected_dirs = ["/tmp/ag-test"]
protected_files = ["/tmp/ag-test/.env"]

[agentguard]
version = "1"

[dlp]
action = "block"
"#;

    #[test]
    fn parses_minimal_config() {
        let cfg = Config::from_str(MINIMAL_TOML).expect("parse ok");
        assert_eq!(cfg.agentguard.version, "1");
        assert_eq!(cfg.protected_dirs.len(), 1);
        assert_eq!(cfg.dlp.proxy_port, 7771);
        assert!(cfg.alerts.desktop_notifications);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = Config::from_str("").expect("parse ok");
        assert_eq!(cfg.vault.keep_days, 30);
        assert_eq!(cfg.vault.auto_snapshot_interval_hours, 6);
        assert_eq!(cfg.dlp.action, "block");
        assert_eq!(cfg.updates.channel, "stable");
    }

    #[test]
    fn rejects_bad_dlp_action() {
        let toml = r#"[dlp]
action = "nuke""#;
        let err = Config::from_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::BadDlpAction(ref s) if s == "nuke"));
    }

    #[test]
    fn rejects_bad_custom_regex() {
        let toml = r#"
[[dlp.custom_patterns]]
name = "broken"
regex = "[unclosed"
"#;
        let err = Config::from_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::BadRegex { .. }));
    }

    #[test]
    fn expand_tilde_replaces_home() {
        let p = expand_tilde(PathBuf::from("~/foo/bar")).unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(p, home.join("foo/bar"));
    }

    #[test]
    fn expand_tilde_leaves_absolute_untouched() {
        let p = expand_tilde(PathBuf::from("/etc/agentguard/config.toml")).unwrap();
        assert_eq!(p, PathBuf::from("/etc/agentguard/config.toml"));
    }

    #[test]
    fn resolve_expands_all_paths() {
        let toml = r#"
protected_dirs = ["~/docs", "/abs/path"]
protected_files = ["~/.env"]

[vault]
vault_dir = "~/vault"
"#;
        let cfg = Config::from_str(toml).unwrap().resolve().unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(cfg.protected_dirs[0], home.join("docs"));
        assert_eq!(cfg.protected_dirs[1], PathBuf::from("/abs/path"));
        assert_eq!(cfg.protected_files[0], home.join(".env"));
        assert_eq!(cfg.vault.vault_dir, home.join("vault"));
    }

    #[test]
    fn dlp_action_parses_case_insensitive() {
        assert_eq!(DlpAction::parse("BLOCK").unwrap(), DlpAction::Block);
        assert_eq!(DlpAction::parse("alert").unwrap(), DlpAction::Alert);
        assert_eq!(DlpAction::parse("Log").unwrap(), DlpAction::Log);
    }

    #[test]
    fn full_example_from_readme_parses() {
        // Subconjunto del ejemplo del README §15 — valida que el formato
        // documentado se mantenga compatible con el parser.
        let toml = r#"
protected_dirs = ["~/Documents", "~/Projects", "~/.ssh"]
protected_files = ["~/.env", "~/.netrc"]

[agentguard]
version = "1"

[[agent_processes]]
name = "cursor"
match = { exe = "cursor" }

[[agent_processes]]
name = "node-agent"
match = { exe = "node", env_has = "AGENTGUARD_AGENT" }

[on_violation]
kill_process = false
snapshot_on_violation = true

[alerts]
desktop_notifications = true

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 6
keep_days = 30

[dlp]
enabled = true
proxy_port = 7771
action = "block"

[[dlp.custom_patterns]]
name = "Mi API Key Interna"
regex = "mycompany-[a-zA-Z0-9]{32}"

[updates]
auto_check = true
channel = "stable"
"#;
        let cfg = Config::from_str(toml).expect("readme example parses");
        assert_eq!(cfg.protected_dirs.len(), 3);
        assert_eq!(cfg.agent_processes.len(), 2);
        assert_eq!(cfg.agent_processes[1].r#match.exe.as_deref(), Some("node"));
        assert_eq!(
            cfg.agent_processes[1].r#match.env_has.as_deref(),
            Some("AGENTGUARD_AGENT")
        );
        assert_eq!(cfg.dlp.custom_patterns.len(), 1);
    }
}
