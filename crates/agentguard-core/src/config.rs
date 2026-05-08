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

/// Nivel de riesgo de una ruta para protección inteligente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

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
    #[error("invalid DLP action {0:?} (allowed: block, alert, log, sanitize)")]
    BadDlpAction(String),

    /// No se pudo localizar el directorio home para expandir `~`.
    #[error("cannot determine home directory for tilde expansion")]
    NoHome,
}

/// Perfil de protección predefinido. Agrupa rutas por categoría.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectionProfile {
    pub name: String,
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub auto: bool,
}

/// Configuración de protección inteligente.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmartProtection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_suggest_on_start: bool,
    #[serde(default)]
    pub profiles: Vec<ProtectionProfile>,
}

impl Default for SmartProtection {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_suggest_on_start: true,
            profiles: builtin_protection_profiles(),
        }
    }
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

    /// v2.1: Sandbox configuration.
    #[serde(default)]
    pub sandbox: SandboxConfig,

    /// v2.1: Agent detection configuration.
    #[serde(default)]
    pub agent_detection: AgentDetection,

    #[serde(default)]
    pub updates: Updates,

    /// v2.1: Windows-specific configuration.
    #[serde(default)]
    pub windows: WindowsConfig,

    /// v2.2: SmartGuardian intelligent protection mode.
    #[serde(default)]
    pub guardian: GuardianConfig,

    /// Smart protection: perfiles predefinidos y detección automática.
    #[serde(default)]
    pub smart_protection: SmartProtection,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agentguard: Meta::default(),
            protected_dirs: builtin_protected_dirs(),
            protected_files: builtin_protected_files(),
            agent_processes: builtin_agent_patterns(),
            on_violation: OnViolation::default(),
            alerts: Alerts::default(),
            vault: VaultConfig::default(),
            dlp: DlpConfig::default(),
            sandbox: SandboxConfig::default(),
            agent_detection: AgentDetection::default(),
            updates: Updates::default(),
            windows: WindowsConfig::default(),
            guardian: GuardianConfig::default(),
            smart_protection: SmartProtection::default(),
        }
    }
}

/// Directorios protegidos por defecto (sin necesidad de config manual).
fn builtin_protected_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("~/Documents"),
        PathBuf::from("~/Projects"),
        PathBuf::from("~/Downloads"),
        PathBuf::from("~/.ssh"),
        PathBuf::from("~/.config"),
        PathBuf::from("~/Desktop"),
    ]
}

/// Archivos protegidos por defecto contra escritura.
fn builtin_protected_files() -> Vec<PathBuf> {
    vec![
        PathBuf::from("~/.env"),
        PathBuf::from("~/.netrc"),
        PathBuf::from("~/.aws/credentials"),
        PathBuf::from("~/.gitconfig"),
        PathBuf::from("~/.npmrc"),
    ]
}

/// Patrones de agentes IA predefinidos (sin necesidad de config manual).
fn builtin_agent_patterns() -> Vec<AgentProcess> {
    vec![
        AgentProcess {
            name: "cursor".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec!["cursor".into(), "Cursor".into()],
                argv_contains_any: vec![],
                env_has: None,
            },
        },
        AgentProcess {
            name: "claude-code".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec!["claude".into(), "claude-code".into()],
                argv_contains_any: vec![],
                env_has: None,
            },
        },
        AgentProcess {
            name: "vscode-copilot".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec!["code".into(), "code-insiders".into(), "codium".into()],
                argv_contains_any: vec![
                    "--agent-mode".into(),
                    "--copilot".into(),
                    "--assistant".into(),
                ],
                env_has: None,
            },
        },
        AgentProcess {
            name: "windsurf".into(),
            r#match: AgentMatch {
                exe: Some("windsurf".into()),
                exe_any: vec![],
                argv_contains_any: vec![],
                env_has: None,
            },
        },
        AgentProcess {
            name: "aider".into(),
            r#match: AgentMatch {
                exe: Some("aider".into()),
                exe_any: vec!["aider-chat".into()],
                argv_contains_any: vec![],
                env_has: None,
            },
        },
        AgentProcess {
            name: "opencode".into(),
            r#match: AgentMatch {
                exe: Some("opencode".into()),
                exe_any: vec![],
                argv_contains_any: vec![],
                env_has: None,
            },
        },
    ]
}

/// Perfiles de protección predefinidos para smart protection.
fn builtin_protection_profiles() -> Vec<ProtectionProfile> {
    vec![
        ProtectionProfile {
            name: "Personal".into(),
            paths: vec![
                PathBuf::from("~/Documents"),
                PathBuf::from("~/Desktop"),
                PathBuf::from("~/Pictures"),
                PathBuf::from("~/Downloads"),
                PathBuf::from("~/Videos"),
                PathBuf::from("~/Music"),
            ],
            auto: false,
        },
        ProtectionProfile {
            name: "Desarrollo".into(),
            paths: vec![
                PathBuf::from("~/Projects"),
                PathBuf::from("~/src"),
                PathBuf::from("~/code"),
                PathBuf::from("~/workspace"),
                PathBuf::from("~/dev"),
            ],
            auto: false,
        },
        ProtectionProfile {
            name: "Secretos".into(),
            paths: vec![
                PathBuf::from("~/.ssh"),
                PathBuf::from("~/.gnupg"),
                PathBuf::from("~/.aws"),
                PathBuf::from("~/.netrc"),
                PathBuf::from("~/.git-credentials"),
                PathBuf::from("~/.docker/config.json"),
            ],
            auto: false,
        },
        ProtectionProfile {
            name: "AI Workspaces".into(),
            paths: vec![],
            auto: true,
        },
    ]
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
    "sanitize".to_string()
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
    /// Sanitiza (redacta) el secreto y deja pasar el request.
    Sanitize,
}

impl DlpAction {
    /// Parsea el string de configuración. Error descriptivo si es desconocido.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.to_ascii_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
            "log" => Ok(Self::Log),
            "sanitize" => Ok(Self::Sanitize),
            _ => Err(ConfigError::BadDlpAction(s.to_string())),
        }
    }
}

// ─── v2.2: Guardian Configuration ───────────────────────────────────────────

/// Modo de operación del SmartGuardian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GuardianMode {
    /// Solo detecta y loguea, nunca bloquea ni sanitiza.
    Observation,
    /// Sanitiza + alerta (recomendado).
    #[default]
    Intelligent,
    /// Bloquea todo lo riesgoso.
    Strict,
}

/// Estilo de redacción para secretos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStyle {
    /// Reemplaza con marcador visible: [AGENTGUARD: X REDACTED]
    #[default]
    Visible,
    /// Reemplazo genérico: [REDACTED]
    Silent,
    /// Mensaje más descriptivo: [SECRET REMOVED - X]
    Aggressive,
}

impl RedactionStyle {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "silent" => Self::Silent,
            "aggressive" => Self::Aggressive,
            _ => Self::Visible,
        }
    }
}

/// Configuración del SmartGuardian (v2.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuardianConfig {
    /// Modo de operación global.
    #[serde(default)]
    pub mode: GuardianMode,

    /// Activar sanitización automática de secretos en prompts.
    #[serde(default = "default_true")]
    pub sanitization: bool,

    /// Detectar y proteger automáticamente workspaces de agentes IA.
    #[serde(default = "default_true")]
    pub auto_protect_ai_workspaces: bool,

    /// Estilo de redacción para secretos.
    #[serde(default)]
    pub redaction_style: RedactionStyle,

    /// Duración en minutos del modo "Trusted Edit".
    #[serde(default = "default_trusted_timeout")]
    pub trusted_edit_timeout_minutes: u32,

    /// Patrones que NUNCA deben redactarse (allowlist del usuario).
    #[serde(default)]
    pub trusted_patterns: Vec<TrustedPattern>,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            mode: GuardianMode::default(),
            sanitization: true,
            auto_protect_ai_workspaces: true,
            redaction_style: RedactionStyle::default(),
            trusted_edit_timeout_minutes: default_trusted_timeout(),
            trusted_patterns: Vec::new(),
        }
    }
}

fn default_trusted_timeout() -> u32 {
    30
}

/// Patrón que el usuario excluye de la redacción.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustedPattern {
    pub name: String,
    pub regex: String,
}

// ─── v2.1: Sandbox Configuration ─────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SandboxConfig {
    #[serde(default = "default_sandbox_mode")]
    pub modo_por_defecto: String,
    #[serde(default = "default_true")]
    pub auto_detectar_agentes: bool,
    #[serde(default = "default_true")]
    pub montar_solo_proyecto: bool,
    #[serde(default = "default_true")]
    pub morir_con_padre: bool,
    /// Enable --unshare-net for full network isolation.
    /// When enabled, the DLP proxy is unreachable from inside the sandbox.
    /// Use eBPF NET_RESTRICT_MODE as kernel-level mitigation instead.
    #[serde(default)]
    pub network_isolation: bool,
    #[serde(default)]
    pub bwrap_extra_args: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            modo_por_defecto: default_sandbox_mode(),
            auto_detectar_agentes: true,
            montar_solo_proyecto: true,
            morir_con_padre: true,
            network_isolation: false,
            bwrap_extra_args: Vec::new(),
        }
    }
}

fn default_sandbox_mode() -> String {
    "ebpf".to_string()
}

// ─── v2.1: Agent Detection Configuration ─────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentDetection {
    #[serde(default)]
    pub known_agents: Vec<KnownAgent>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KnownAgent {
    pub name: String,
    #[serde(default)]
    pub exe: Vec<String>,
    #[serde(default)]
    pub argv_contains: Vec<String>,
    #[serde(default)]
    pub env_has: Option<String>,
}

// ─── v2.1: Windows Configuration ─────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WindowsConfig {
    #[serde(default = "default_true")]
    pub use_lpac: bool,
    #[serde(default = "default_true")]
    pub use_etw: bool,
    #[serde(default = "default_windows_polling_interval")]
    pub polling_interval_ms: u64,
}

fn default_windows_polling_interval() -> u64 {
    500
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
    #[allow(clippy::should_implement_trait)]
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
        for profile in &mut self.smart_protection.profiles {
            profile.paths = std::mem::take(&mut profile.paths)
                .into_iter()
                .map(expand_tilde)
                .collect::<Result<_, _>>()?;
        }
        Ok(self)
    }

    /// Parsea la acción de DLP como enum fuerte.
    pub fn dlp_action(&self) -> Result<DlpAction, ConfigError> {
        DlpAction::parse(&self.dlp.action)
    }
}

/// Resuelve el home directory del usuario REAL, no de root.
/// Estrategia (en orden de prioridad):
/// 1. AGENTGUARD_USER_HOME env var (override explícito en config/systemd)
/// 2. SUDO_USER env var → buscar en /etc/passwd
/// 3. DBUS_SESSION_BUS_ADDRESS → extraer usuario
/// 4. Usuarios en /etc/passwd con UID >= 1000 y shell válida (excluye daemons)
/// 5. Fallback: dirs::home_dir() (será /root si nada más funciona)
pub fn resolve_real_user_home() -> Option<PathBuf> {
    // Override explícito (recomendado para producción via systemd Environment=)
    if let Ok(explicit) = std::env::var("AGENTGUARD_USER_HOME") {
        let p = PathBuf::from(&explicit);
        if p.is_dir() {
            tracing::debug!("Using AGENTGUARD_USER_HOME: {}", explicit);
            return Some(p);
        }
        tracing::warn!("AGENTGUARD_USER_HOME set but not a directory: {}", explicit);
    }

    // SUDO_USER → /etc/passwd lookup
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            if let Some(home) = home_from_passwd(&sudo_user) {
                tracing::info!("Resolved home via SUDO_USER={}: {:?}", sudo_user, home);
                return Some(home);
            }
        }
    }

    // Usuarios con UID >= 1000 en /etc/passwd (el primero con home válido)
    if let Some(home) = first_human_user_home() {
        tracing::info!("Resolved home via /etc/passwd scan: {:?}", home);
        return Some(home);
    }

    // Último recurso
    let fallback = dirs::home_dir();
    tracing::warn!(
        "Could not resolve real user home, falling back to: {:?}. \
         Set AGENTGUARD_USER_HOME in systemd service to fix this.",
        fallback
    );
    fallback
}

/// Busca el home de un usuario concreto en /etc/passwd.
fn home_from_passwd(username: &str) -> Option<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        // formato: user:x:uid:gid:gecos:home:shell
        if fields.len() >= 7 && fields[0] == username {
            let home = PathBuf::from(fields[5]);
            if home.is_dir() {
                return Some(home);
            }
        }
    }
    None
}

/// Retorna el home del primer usuario humano (UID >= 1000) con home válido.
fn first_human_user_home() -> Option<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    let mut candidates: Vec<(u32, PathBuf)> = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }

        let uid: u32 = fields[2].parse().ok()?;
        if uid < 1000 {
            continue; // excluir daemons del sistema
        }

        let shell = fields[6];
        // Excluir usuarios sin shell interactiva
        if shell.ends_with("/nologin") || shell.ends_with("/false") || shell.is_empty() {
            continue;
        }

        let home = PathBuf::from(fields[5]);
        if home.is_dir() {
            candidates.push((uid, home));
        }
    }

    // El de menor UID suele ser el usuario principal
    candidates.sort_by_key(|(uid, _)| *uid);
    candidates.into_iter().map(|(_, home)| home).next()
}

/// Expande rutas con ~ usando el home real, no el de root.
pub fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = resolve_real_user_home() {
            return home.join(rest);
        }
    }
    if path == "~" {
        if let Some(home) = resolve_real_user_home() {
            return home;
        }
    }
    PathBuf::from(path)
}

/// `Path`-aware variant of [`expand_path`].
///
/// Useful where the caller already has a `&Path` / `&PathBuf` and would
/// otherwise have to round-trip through `to_string_lossy()`. Non-UTF-8
/// paths are returned unchanged.
///
/// This exists to give a single, uniform API surface — `smart_protect.rs`
/// previously had its own `expand_path(&Path)` that used
/// [`dirs::home_dir`] directly and therefore resolved `~/...` to `/root/...`
/// when the daemon ran under systemd, defeating the whole "real user home"
/// resolver.
pub fn expand_path_p(path: &Path) -> PathBuf {
    match path.to_str() {
        Some(s) => expand_path(s),
        None => path.to_path_buf(),
    }
}

/// Reemplaza un `~` inicial por el home del usuario.
fn expand_tilde(path: PathBuf) -> Result<PathBuf, ConfigError> {
    let s = match path.to_str() {
        Some(s) => s,
        None => return Ok(path),
    };
    Ok(expand_path(s))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(cfg.dlp.action, "sanitize");
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
        assert_eq!(DlpAction::parse("SANITIZE").unwrap(), DlpAction::Sanitize);
        assert_eq!(DlpAction::parse("sanitize").unwrap(), DlpAction::Sanitize);
    }

    #[test]
    fn full_example_from_readme_parses() {
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

    #[test]
    fn smart_protection_defaults_have_four_profiles() {
        let cfg = Config::default();
        assert_eq!(cfg.smart_protection.profiles.len(), 4);
        assert_eq!(cfg.smart_protection.profiles[0].name, "Personal");
        assert_eq!(cfg.smart_protection.profiles[1].name, "Desarrollo");
        assert_eq!(cfg.smart_protection.profiles[2].name, "Secretos");
        let ai_ws = &cfg.smart_protection.profiles[3];
        assert_eq!(ai_ws.name, "AI Workspaces");
        assert!(ai_ws.auto);
        assert!(ai_ws.paths.is_empty());
    }

    #[test]
    fn smart_protection_can_be_disabled() {
        let toml = r#"
[smart_protection]
enabled = false
auto_suggest_on_start = false
"#;
        let cfg = Config::from_str(toml).expect("parse");
        assert!(!cfg.smart_protection.enabled);
        assert!(!cfg.smart_protection.auto_suggest_on_start);
        assert_eq!(cfg.smart_protection.profiles.len(), 0);
    }

    #[test]
    fn smart_protection_custom_profiles_work() {
        let toml = r#"
[[smart_protection.profiles]]
name = "Mi Empresa"
paths = ["~/work", "~/clientes"]
"#;
        let cfg = Config::from_str(toml).expect("parse");
        assert_eq!(cfg.smart_protection.profiles.len(), 1);
        assert_eq!(cfg.smart_protection.profiles[0].name, "Mi Empresa");
        assert_eq!(cfg.smart_protection.profiles[0].paths.len(), 2);
    }

    #[test]
    fn smart_protection_resolve_expands_profiles() {
        let toml = r#"
[[smart_protection.profiles]]
name = "Test"
paths = ["~/testdir"]
"#;
        let cfg = Config::from_str(toml).unwrap().resolve().unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            cfg.smart_protection.profiles[0].paths[0],
            home.join("testdir")
        );
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }
}
