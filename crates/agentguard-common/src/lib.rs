//! Tipos compartidos entre el daemon userspace y los programas eBPF.
//!
//! Este crate es `no_std` compatible para poder incluirse desde
//! `agentguard-ebpf` (target `bpfel-unknown-none`). Los tipos que requieren
//! heap (`String`, `Vec`, etc.) viven detrás de la feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Versión del protocolo IPC entre daemon, CLI y UI.
///
/// Bumpear en cada cambio breaking del enum `IpcCommand` / `IpcResponse`.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_from_bytes_roundtrip() {
        let p = PathPrefix::from_bytes(b"/home/alice/Documents")
            .expect("fits in MAX_PREFIX_LEN");
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

// ------------------------------------------------------------------
// Tipos del protocolo IPC (solo userspace — feature "std").
// ------------------------------------------------------------------

#[cfg(feature = "std")]
mod ipc {
    use serde::{Deserialize, Serialize};

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
        Incidents { last: usize },
        /// Pausar protección.
        Pause { minutes: u64 },
        /// Reanudar protección.
        Resume,
        /// Ping (health-check).
        Ping,
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
        Error {
            message: std::string::String,
        },
        /// Respuesta a Status.
        StatusData {
            version: std::string::String,
            guard_backend: std::string::String,
            protection_level: std::string::String,
            dlp_enabled: bool,
            protected_dirs: std::vec::Vec<std::string::String>,
            protected_files: std::vec::Vec<std::string::String>,
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
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotInfo {
        pub id: std::string::String,
        pub timestamp: u64,
        pub label: std::string::String,
        pub files: usize,
        pub total_size: u64,
    }
}

#[cfg(feature = "std")]
pub use ipc::{IpcCommand, IpcResponse, SnapshotInfo};
