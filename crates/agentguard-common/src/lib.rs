//! Tipos compartidos entre el daemon userspace y los programas eBPF.
//!
//! Este crate es `no_std` compatible para poder incluirse desde
//! `agentguard-ebpf` (target `bpfel-unknown-none`). Los tipos que requieren
//! heap (`String`, `Vec`, etc.) viven detrás de la feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Versión del protocolo IPC entre daemon, CLI y UI.
///
/// Bumpear en cada cambio breaking del enum `IpcCommand` / `IpcResponse`.
pub const IPC_PROTOCOL_VERSION: u32 = 2;

/// Ruta por defecto del socket IPC (Unix / Linux).
pub const IPC_SOCKET_PATH: &str = ".agentguard/agentguard.sock";

/// Nombre del named pipe en Windows.
pub const IPC_PIPE_NAME: &str = "agentguard";

/// Longitud máxima en bytes de un prefijo de ruta protegida.
///
/// Este valor debe ser el mismo en userspace y en el programa BPF, porque
/// el `struct PathPrefix` se comparte vía un BPF map.
pub const MAX_PREFIX_LEN: usize = 256;

/// Número máximo de prefijos protegidos simultáneamente.
///
/// Está limitado por el tamaño del array map BPF y por el coste del bucle
/// de comparación dentro del hook LSM (O(N) por syscall interceptada).
pub const MAX_PREFIXES: u32 = 64;

/// Número máximo de inodos en los mapas BPF `PROTECTED_DIR_INODES` y
/// `PROTECTED_FILE_INODES`. Debe coincidir con `with_max_entries(N, 0)`
/// en `agentguard-ebpf/src/file_guard.rs`.
///
/// Con indexado recursivo del subárbol (todos los subdirectorios bajo cada
/// raíz protegida), este valor cubre escenarios típicos:
/// - `~/Documents` con 5000 ficheros y 500 carpetas anidadas → ~500 inodes
/// - 16 raíces × 500 subdirs cada una → ~8000 inodes (cabe holgadamente)
///
/// Si se alcanza el límite el daemon emite una advertencia explícita y
/// continúa funcionando con la cobertura conseguida hasta ese punto.
pub const MAX_PROTECTED_INODES: u32 = 8192;

/// Longitud fija del campo `comm` de Linux (`TASK_COMM_LEN`).
pub const COMM_LEN: usize = 16;

/// Tipo de evento de seguridad detectado por los hooks eBPF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EventType {
    /// Intento de `unlink`/`rmdir` sobre una ruta protegida.
    FileDelete = 1,
    /// Intento de `write`/`truncate` sobre una ruta protegida.
    FileWrite = 2,
    /// Intento de `rename` que saca un archivo de una ruta protegida.
    FileRename = 3,
    /// Conexión saliente de un proceso marcado como agente de IA.
    NetworkSend = 4,
}

/// Evento emitido por el hook LSM de filesystem hacia el daemon.
///
/// Layout FFI: shared entre kernel (BPF) y userspace.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub event_type: EventType,
    pub path_len: u32,
    pub path: [u8; MAX_PREFIX_LEN],
    pub comm: [u8; COMM_LEN],
}

/// Evento emitido por el hook LSM de red.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub data_len: u32,
    pub data: [u8; 512],
    pub comm: [u8; COMM_LEN],
}

/// Prefijo de ruta protegida, almacenado en el BPF map `PROTECTED_PREFIXES`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PathPrefix {
    pub len: u32,
    pub bytes: [u8; MAX_PREFIX_LEN],
}

impl PathPrefix {
    /// Crea un `PathPrefix` copiando los bytes dados. Retorna `None` si el
    /// input excede `MAX_PREFIX_LEN`.
    pub fn from_bytes(src: &[u8]) -> Option<Self> {
        if src.len() > MAX_PREFIX_LEN {
            return None;
        }
        let mut bytes = [0u8; MAX_PREFIX_LEN];
        bytes[..src.len()].copy_from_slice(src);
        Some(Self {
            len: src.len() as u32,
            bytes,
        })
    }

    /// Devuelve el slice efectivo (truncado a `len`).
    pub fn as_slice(&self) -> &[u8] {
        let n = (self.len as usize).min(MAX_PREFIX_LEN);
        &self.bytes[..n]
    }
}

// `PathPrefix` es #[repr(C)], Copy y solo contiene enteros y arrays.
// Es seguro declararlo como Pod para el ecosistema aya (usado en maps BPF).
#[cfg(feature = "ebpf-aya")]
unsafe impl aya::Pod for PathPrefix {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_from_bytes_roundtrip() {
        let p = PathPrefix::from_bytes(b"/home/alice/Documents").expect("fits in MAX_PREFIX_LEN");
        assert_eq!(p.len as usize, "/home/alice/Documents".len());
        assert_eq!(p.as_slice(), b"/home/alice/Documents");
    }

    #[test]
    fn path_prefix_rejects_oversize_input() {
        let too_long = vec![b'a'; MAX_PREFIX_LEN + 1];
        assert!(PathPrefix::from_bytes(&too_long).is_none());
    }

    #[test]
    fn file_event_has_stable_size() {
        // Si este tamaño cambia, el BPF ring buffer parser debe actualizarse.
        // Layout: 3 u32 (pid, uid, event_type) + 1 u32 (path_len)
        //       + MAX_PREFIX_LEN bytes (path) + COMM_LEN bytes (comm).
        const EXPECTED: usize = 4 * 4 + MAX_PREFIX_LEN + COMM_LEN;
        assert_eq!(core::mem::size_of::<FileEvent>(), EXPECTED);
    }
}

// ─── Detección de agentes IA ────────────────────────────────────────────────

/// Evento de spawn de agente IA. Viaja del eBPF tracepoint al daemon userspace
/// vía ring buffer. Layout FFI: debe ser no_std + repr(C).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct AgentSpawnEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Nombre del ejecutable (comm del kernel), máx 16 bytes.
    pub comm: [u8; 16],
    /// Ruta completa del ejecutable, máx 256 bytes.
    pub exe_path: [u8; 256],
    /// Directorio de trabajo actual, máx 256 bytes.
    pub cwd: [u8; 256],
    /// argv[0..N] concatenado con \0, máx 128 bytes.
    pub argv: [u8; 128],
}

// Safety: AgentSpawnEvent es repr(C), Copy, solo contiene arrays de enteros.
// Es seguro marcarlo como Pod para aya en userspace.
#[cfg(feature = "ebpf-aya")]
unsafe impl aya::Pod for AgentSpawnEvent {}

impl AgentSpawnEvent {
    /// Decodifica `comm` como &str.
    #[cfg(not(target_arch = "bpf"))]
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    /// Decodifica `cwd` como &str.
    #[cfg(not(target_arch = "bpf"))]
    pub fn cwd_str(&self) -> &str {
        let end = self.cwd.iter().position(|&b| b == 0).unwrap_or(256);
        core::str::from_utf8(&self.cwd[..end]).unwrap_or("<invalid>")
    }

    /// Decodifica `exe_path` como &str.
    #[cfg(not(target_arch = "bpf"))]
    pub fn exe_str(&self) -> &str {
        let end = self.exe_path.iter().position(|&b| b == 0).unwrap_or(256);
        core::str::from_utf8(&self.exe_path[..end]).unwrap_or("<invalid>")
    }
}

// ------------------------------------------------------------------
// Tipos del protocolo IPC (solo userspace — feature "std").
// ------------------------------------------------------------------

#[cfg(feature = "std")]
mod ipc {
    use serde::{Deserialize, Serialize};

    #[doc = "Modo de sandbox para agentes IA."]
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    #[serde(rename_all = "lowercase")]
    pub enum SandboxMode {
        Monitor,
        Sandbox,
        Hybrid,
    }

    impl std::fmt::Display for SandboxMode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Monitor => write!(f, "monitor"),
                Self::Sandbox => write!(f, "sandbox"),
                Self::Hybrid => write!(f, "hybrid"),
            }
        }
    }

    #[doc = "Comando enviado del CLI/UI al daemon vía IPC."]
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "command", content = "args")]
    pub enum IpcCommand {
        /// Estado general de protección.
        Status,
        /// Proteger una ruta.
        Protect {
            path: std::string::String,
            #[serde(default)]
            watch_only: bool,
        },
        /// Desproteger una ruta.
        Unprotect { path: std::string::String },
        /// Crear snapshot.
        SnapshotCreate {
            #[serde(default = "default_label")]
            label: std::string::String,
        },
        /// Listar snapshots.
        SnapshotList,
        /// Restaurar snapshot por ID.
        SnapshotRestore {
            id: std::string::String,
            #[serde(default)]
            yes: bool,
        },
        /// Limpiar snapshots antiguos.
        SnapshotCleanup { keep_days: u64 },
        /// Mostrar incidentes recientes.
        Incidents { last: Option<usize> },
        /// Pausar protección.
        Pause { minutes: u64 },
        /// Reanudar protección.
        Resume,
        /// Ping (health-check).
        Ping,
        /// Lanzar un agente IA dentro del sandbox (v2.1).
        LaunchAgent {
            exe: std::string::String,
            cwd: std::string::String,
            #[serde(default)]
            extra_args: std::vec::Vec<std::string::String>,
            #[serde(default)]
            mode_override: Option<std::string::String>,
        },
        /// Añadir ruta protegida en runtime (v2.1).
        AddProtectedPath { path: std::string::String },
        /// Fase 5: Listar todos los agentes conocidos.
        AgentsList,
        /// Fase 5: Mostrar detalle de un agente.
        AgentsShow { name: std::string::String },
        /// Fase 5: Listar reglas de protección.
        RulesList,
        /// Fase 5: Estadísticas de incidentes.
        Stats,
        /// Fase 5: Incidencias con filtros.
        IncidentsFilter {
            #[serde(default)]
            kind: Option<std::string::String>,
            #[serde(default)]
            agent_name: Option<std::string::String>,
            #[serde(default)]
            from_ts: Option<i64>,
            #[serde(default)]
            to_ts: Option<i64>,
            #[serde(default)]
            limit: Option<u32>,
        },
        /// Fase 6: Suscribirse a eventos push del daemon.
        Subscribe {
            #[serde(default)]
            events: std::vec::Vec<std::string::String>,
        },
        /// Fase 6: Cancelar suscripción a eventos push.
        Unsubscribe,
        /// Obtener sugerencias de protección inteligente.
        SmartSuggest,
        /// Aplicar sugerencias de protección.
        SmartApply {
            paths: std::vec::Vec<std::string::String>,
        },
        /// Listar perfiles de protección disponibles.
        ProfilesList,
    }

    fn default_label() -> std::string::String {
        "manual".into()
    }

    #[doc = "Respuesta del daemon al CLI/UI vía IPC."]
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "status", content = "data")]
    pub enum IpcResponse {
        /// Operación completada con éxito.
        Ok {
            #[serde(default)]
            message: std::string::String,
        },
        /// Operación rechazada o error.
        Error { message: std::string::String },
        /// Respuesta a Status.
        StatusData {
            version: std::string::String,
            guard_backend: std::string::String,
            protection_level: std::string::String,
            dlp_enabled: bool,
            paused: bool,
            protected_dirs: std::vec::Vec<std::string::String>,
            protected_files: std::vec::Vec<std::string::String>,
            /// v2.1: modo de sandbox activo.
            #[serde(default)]
            sandbox_mode: Option<std::string::String>,
            /// v2.1: número de sandboxes activos.
            #[serde(default)]
            active_sandboxes: u32,
            /// v2.1: capacidades del sistema.
            #[serde(default)]
            capabilities: Option<std::string::String>,
            /// v2.1: contador de incidentes recientes.
            #[serde(default)]
            incidents_count: u64,
        },
        /// Respuesta a SnapshotList.
        SnapshotList {
            snapshots: std::vec::Vec<SnapshotInfo>,
        },
        /// Respuesta a Incidents.
        Incidents {
            lines: std::vec::Vec<std::string::String>,
        },
        /// Respuesta a Ping.
        Pong,
        /// v2.1: agente lanzado en sandbox.
        AgentLaunched { sandbox_pid: u32 },
        /// Fase 5: lista de agentes con estadísticas.
        AgentsList { agents: std::vec::Vec<AgentInfo> },
        /// Fase 5: detalle de un agente.
        AgentsShow {
            agent: AgentInfo,
            sessions: std::vec::Vec<SessionInfo>,
        },
        /// Fase 5: reglas de protección.
        RulesList { rules: std::vec::Vec<RuleInfo> },
        /// Fase 5: estadísticas de incidentes.
        StatsData {
            total_incidents: u64,
            violations_24h: u64,
            agents_tracked: u64,
        },
        /// Sugerencias de protección inteligente.
        SmartSuggestions {
            suggestions: std::vec::Vec<SuggestionInfo>,
        },
        /// Lista de perfiles de protección.
        ProfilesList {
            profiles: std::vec::Vec<ProfileInfo>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotInfo {
        pub id: std::string::String,
        pub timestamp: u64,
        pub label: std::string::String,
        pub files: usize,
        pub total_size: u64,
    }

    /// v2.1: Estado de un agente actualmente sandboxeado.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxedAgent {
        pub original_pid: u32,
        pub sandbox_pid: u32,
        pub agent_name: std::string::String,
        pub cwd: std::string::String,
        pub mode: SandboxMode,
        pub started_at: u64,
    }

    /// Fase 5: Información de un agente (del SQLite db).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AgentInfo {
        pub agent_name: std::string::String,
        pub first_seen: i64,
        pub last_seen: i64,
        pub total_sessions: i64,
        pub total_violations: i64,
        pub total_sandbox_seconds: i64,
    }

    /// Fase 5: Información de una sesión de agente.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionInfo {
        pub id: std::string::String,
        pub agent_name: std::string::String,
        pub pid: Option<i64>,
        pub sandbox_mode: Option<std::string::String>,
        pub started_at: i64,
        pub ended_at: Option<i64>,
        pub total_seconds: Option<i64>,
        pub violation_count: Option<i64>,
    }

    /// Sugerencia de protección generada por smart_protect.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuggestionInfo {
        pub path: std::string::String,
        pub group: std::string::String,
        pub reason: std::string::String,
        pub risk_level: std::string::String,
        pub size_bytes: u64,
        pub contains_secrets: bool,
        pub is_git_repo: bool,
        pub active_agents: std::vec::Vec<std::string::String>,
    }

    /// Información de un perfil de protección.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProfileInfo {
        pub name: std::string::String,
        pub path_count: usize,
        pub enabled: bool,
        pub is_auto: bool,
    }

    /// Fase 5: Información de una regla de protección.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RuleInfo {
        pub path: std::string::String,
        pub kind: std::string::String,
        pub added_at: i64,
        pub watch_only: bool,
    }

    /// Fase 6: Evento push del daemon al cliente (TUI/CLI).
    /// Se envía como JSON-line en una conexión persistente tras Subscribe.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "event", content = "data")]
    pub enum IpcEvent {
        /// Un agente IA fue detectado en directorio protegido.
        AgentSpawned {
            agent_name: std::string::String,
            pid: u32,
            sandbox_pid: Option<u32>,
            mode: std::string::String,
            cwd: std::string::String,
            timestamp: u64,
        },
        /// Un agente sandboxeado terminó.
        AgentExited {
            agent_name: std::string::String,
            sandbox_pid: u32,
            exit_code: Option<i32>,
            timestamp: u64,
        },
        /// Violación de seguridad detectada (filesystem o DLP).
        ViolationDetected {
            kind: std::string::String,
            agent_name: Option<std::string::String>,
            path: Option<std::string::String>,
            violation: Option<std::string::String>,
            detail: std::string::String,
            timestamp: u64,
        },
        /// Protección pausada o reanudada.
        ProtectionToggled {
            paused: bool,
            auto_resume_secs: Option<u64>,
        },
        /// Snapshot creado.
        SnapshotCreated {
            id: std::string::String,
            label: std::string::String,
            files: usize,
            total_size: u64,
        },
        /// Configuración recargada (SIGHUP).
        ConfigReloaded,
        /// Daemon está terminando.
        DaemonShutdown,
        /// Heartbeat periódico para detectar desconexión.
        Heartbeat { timestamp: u64 },
        /// El cliente se desconectó del daemon.
        Disconnected { reason: std::string::String },
    }
}

#[cfg(feature = "std")]
pub use ipc::{
    AgentInfo, IpcCommand, IpcEvent, IpcResponse, ProfileInfo, RuleInfo, SandboxMode,
    SandboxedAgent, SessionInfo, SnapshotInfo, SuggestionInfo,
};
