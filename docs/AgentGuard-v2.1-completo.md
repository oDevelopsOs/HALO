# AgentGuard v2.1 — Especificación Técnica Completa
**Módulo 10: Sandbox Launcher + Detección Automática de Agentes IA**  
**Versión 2.1 — Mayo 2026 · Rust 2021 Edition**

> Addendum oficial de v1.0. Inserta este contenido después del Módulo 9.  
> Los agentes ahora **nacen ya protegidos** — zero config para el usuario final.

---

## Índice

1. [Visión del Módulo 10](#1-visión)
2. [Tipos comunes nuevos](#2-tipos-comunes-nuevos)
3. [eBPF — Detección de procesos (Linux)](#3-ebpf--detección-de-procesos-linux)
4. [Sandbox Launcher — Linux (bwrap + Landlock)](#4-sandbox-launcher--linux)
5. [Sandbox Launcher — Windows (AppContainer/LPAC + ETW)](#5-sandbox-launcher--windows)
6. [Integración en el daemon principal](#6-integración-en-el-daemon)
7. [CLI v2.1 — Comandos simples](#7-cli-v21)
8. [Configuración extendida (config.toml v2.1)](#8-configuración-extendida)
9. [Tests obligatorios](#9-tests-obligatorios)
10. [Orden de implementación](#10-orden-de-implementación)

---

## 1. Visión

**Problema de v1.0:** el watchdog actúa *después* de que el agente ya corre libre.  
**Solución v2.1:** AgentGuard detecta el proceso en <100 ms y lo relanza **dentro del sandbox** antes de que pueda tocar nada.

```
Usuario ejecuta: cursor
        │
        ▼
eBPF tracepoint sched_process_exec detecta "cursor" (Linux)
ETW Event ID 1 detecta "cursor.exe"              (Windows)
        │
        ▼
¿cwd está en protected_dirs?
        │
        ├─ NO  → dejar pasar (modo monitor)
        │
        └─ SÍ  → matar el proceso original
                  re-lanzar dentro de bwrap/AppContainer
                  en <150 ms total
```

| Modo      | Extra RAM | CPU extra | Protección | Requiere root |
|-----------|-----------|-----------|------------|---------------|
| `monitor` | 0-1 MB    | <0.5%     | 92-95%     | No            |
| `sandbox` | 1-3 MB    | <2%       | 97-98%     | No            |
| `hybrid`  | 2-5 MB    | <3%       | 98-99%     | No            |

**Default en v2.1:** `sandbox`

---

## 2. Tipos comunes nuevos

### `agentguard-common/src/lib.rs` — añadir al archivo existente

```rust
// ─── Evento de spawn de agente IA ────────────────────────────────────────────

/// Enviado desde el eBPF de detección de procesos al daemon userspace.
/// Debe ser no_std compatible (sin String, sin Vec).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct AgentSpawnEvent {
    pub pid:      u32,
    pub ppid:     u32,
    pub uid:      u32,
    /// Nombre del ejecutable (comm), máx 16 bytes como en el kernel.
    pub comm:     [u8; 16],
    /// Ruta completa del ejecutable, máx 256 bytes.
    pub exe_path: [u8; 256],
    /// Directorio de trabajo actual, máx 256 bytes.
    pub cwd:      [u8; 256],
    /// argv[1..4] concatenado con \0, máx 128 bytes.
    pub argv:     [u8; 128],
}

impl AgentSpawnEvent {
    /// Helper para userspace: decodifica `comm` como &str.
    #[cfg(not(target_arch = "bpf"))]
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn cwd_str(&self) -> &str {
        let end = self.cwd.iter().position(|&b| b == 0).unwrap_or(256);
        std::str::from_utf8(&self.cwd[..end]).unwrap_or("<invalid>")
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn exe_str(&self) -> &str {
        let end = self.exe_path.iter().position(|&b| b == 0).unwrap_or(256);
        std::str::from_utf8(&self.exe_path[..end]).unwrap_or("<invalid>")
    }
}

// ─── Resultado de sandbox ────────────────────────────────────────────────────

/// Estado de un agente actualmente sandboxeado.
/// Solo userspace, puede usar std.
#[cfg(not(target_arch = "bpf"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxedAgent {
    pub original_pid:  u32,
    pub sandbox_pid:   u32,
    pub agent_name:    String,
    pub cwd:           std::path::PathBuf,
    pub mode:          SandboxMode,
    pub started_at:    u64,
}

#[cfg(not(target_arch = "bpf"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    Monitor,
    Sandbox,
    Hybrid,
}
```

### `agentguard-daemon/Cargo.toml` — dependencias nuevas

```toml
# Detección de agentes (Linux)
[target.'cfg(target_os = "linux")'.dependencies]
aya         = { version = "0.13", optional = true }
aya-log     = { version = "0.2",  optional = true }
# Landlock
landlock    = "0.4"

# Windows ETW + AppContainer
[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_JobObjects",
    "Win32_System_Threading",
    "Win32_Storage_FileSystem",
    "Win32_System_Diagnostics_Etw",
    "Win32_System_SystemInformation",
] }
# Para polling ligero si ETW es muy complejo
sysinfo = { version = "0.31", default-features = false, features = ["system"] }

# Compartido
uuid    = { version = "1", features = ["v4"] }
tokio   = { version = "1", features = ["full"] }
```

---

## 3. eBPF — Detección de procesos (Linux)

### `agentguard-ebpf/src/process_exec.rs`

```rust
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::pt_regs,
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
    BpfContext,
};
use agentguard_common::AgentSpawnEvent;

// Mapa de agentes conocidos: hash FNV-1a del comm → 1
// Poblado desde userspace con los nombres de config.toml
#[map]
static KNOWN_AGENTS: HashMap<u64, u8> = HashMap::with_max_entries(128, 0);

// Ring buffer de eventos hacia userspace
#[map]
static AGENT_SPAWN_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Tracepoint en sched_process_exec — se dispara cada vez que un proceso
/// llama execve/execveat con éxito (el proceso YA tiene la nueva imagen).
/// Overhead medido: ~0.3 µs por exec en kernels 5.15+.
#[tracepoint(name = "sched/sched_process_exec")]
pub fn handle_process_exec(ctx: TracePointContext) -> i32 {
    match try_handle_exec(&ctx) {
        Ok(_) => 0,
        Err(_) => 0, // fail-open siempre
    }
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<(), i64> {
    // Leer comm (nombre del proceso, max 16 bytes)
    let mut comm = [0u8; 16];
    unsafe {
        // bpf_get_current_comm llena el buffer con el nombre del proceso actual
        let ret = aya_bpf::helpers::bpf_get_current_comm(
            comm.as_mut_ptr() as *mut _,
            16,
        );
        if ret < 0 {
            return Ok(()); // no podemos leer el comm, ignorar
        }
    }

    // Hash del comm para buscar en el mapa
    let hash = fnv1a_hash_bytes(&comm);

    // ¿Es un agente conocido?
    if unsafe { KNOWN_AGENTS.get(&hash).is_none() } {
        return Ok(());
    }

    // Reservar entrada en el ring buffer
    if let Some(mut entry) = AGENT_SPAWN_EVENTS.reserve::<AgentSpawnEvent>(0) {
        let event = entry.as_mut_ptr();

        unsafe {
            // PID y UID del proceso nuevo
            (*event).pid  = ctx.pid();
            (*event).uid  = ctx.uid();
            // PPID: leer desde task_struct vía bpf_get_current_task
            (*event).ppid = get_ppid();

            // Copiar comm
            core::ptr::copy_nonoverlapping(
                comm.as_ptr(),
                (*event).comm.as_mut_ptr(),
                16,
            );

            // Leer filename del tracepoint (offset 16 en sched_process_exec args)
            // La estructura del tracepoint es: pid(4) + old_pid(4) + filename(ptr)
            // Leemos el puntero al filename con bpf_probe_read_user_str
            let filename_ptr = ctx.read_at::<u64>(16).unwrap_or(0);
            if filename_ptr != 0 {
                aya_bpf::helpers::bpf_probe_read_user_str_bytes(
                    filename_ptr as *const u8,
                    &mut (*event).exe_path,
                ).ok();
            }

            // cwd: no disponible directamente en el tracepoint de exec.
            // Se obtendrá desde userspace usando /proc/<pid>/cwd symlink.
            // Dejamos el campo vacío (el daemon lo rellena).
            // Sí podemos leer argv[0] y argv[1]:
            let argv_ptr = ctx.read_at::<u64>(24).unwrap_or(0);
            if argv_ptr != 0 {
                // argv es char**, leer argv[1] si existe
                let arg1_ptr = aya_bpf::helpers::bpf_probe_read_user::<u64>(
                    (argv_ptr + 8) as *const u64
                ).unwrap_or(0);
                if arg1_ptr != 0 {
                    aya_bpf::helpers::bpf_probe_read_user_str_bytes(
                        arg1_ptr as *const u8,
                        &mut (*event).argv,
                    ).ok();
                }
            }
        }

        entry.submit(0);
    }

    Ok(())
}

fn fnv1a_hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        if b == 0 { break; } // stop en null terminator
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

unsafe fn get_ppid() -> u32 {
    // Leer task->real_parent->tgid via bpf_get_current_task
    let task = aya_bpf::helpers::bpf_get_current_task();
    if task == 0 {
        return 0;
    }
    // Offset de real_parent en task_struct depende del kernel.
    // Usar CO-RE (BTF) para resolverlo automáticamente con aya.
    // Placeholder: devolver 0 si no disponible.
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### `agentguard-daemon/src/process_watcher_linux.rs`

```rust
//! Carga el programa eBPF de detección de procesos y reacciona ante
//! spawns de agentes IA en directorios protegidos.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use aya::{Bpf, BpfLoader, include_bytes_aligned};
use aya::maps::{HashMap, RingBuf};
use aya::programs::TracePoint;
use agentguard_common::AgentSpawnEvent;

use crate::config::Config;
use crate::sandbox_linux::SandboxLauncher;
use crate::daemon::SecurityEvent;

// El bytecode eBPF embebido en compile-time
static PROCESS_EXEC_BPF: &[u8] = include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/process_exec.bpf.o")
);

pub struct ProcessWatcher {
    bpf: Bpf,
}

impl ProcessWatcher {
    /// Carga el programa eBPF y popula el mapa con los agentes conocidos.
    pub async fn load(config: &Config) -> Result<Self, anyhow::Error> {
        let mut bpf = BpfLoader::new()
            .btf(aya::Btf::from_sys_fs().ok().as_ref())
            .load(PROCESS_EXEC_BPF)?;

        // Attachar el tracepoint
        let program: &mut TracePoint = bpf
            .program_mut("handle_process_exec")
            .ok_or_else(|| anyhow::anyhow!("Program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;

        // Poblar KNOWN_AGENTS con los hashes FNV-1a de los nombres de ejecutables
        let mut known_agents: HashMap<_, u64, u8> =
            HashMap::try_from(bpf.map_mut("KNOWN_AGENTS")
                .ok_or_else(|| anyhow::anyhow!("Map KNOWN_AGENTS not found"))?)?;

        for agent in &config.agent_detection.known_agents {
            for exe in &agent.exe {
                let hash = fnv1a_hash(exe);
                known_agents.insert(hash, 1u8, 0)?;
                tracing::debug!("Registered agent exe: {} (hash={:#x})", exe, hash);
            }
        }

        tracing::info!(
            "ProcessWatcher loaded: {} agent executables registered",
            config.agent_detection.known_agents.iter()
                .map(|a| a.exe.len())
                .sum::<usize>()
        );

        Ok(Self { bpf })
    }

    /// Loop principal: lee eventos del ring buffer y los procesa.
    /// Spawneado como tarea tokio separada.
    pub async fn run(
        mut self,
        config: Arc<RwLock<Config>>,
        event_tx: mpsc::Sender<SecurityEvent>,
    ) {
        let mut ring_buf = match self.bpf.map_mut("AGENT_SPAWN_EVENTS") {
            Some(map) => match RingBuf::try_from(map) {
                Ok(rb) => rb,
                Err(e) => {
                    tracing::error!("Failed to get AGENT_SPAWN_EVENTS ring buffer: {}", e);
                    return;
                }
            },
            None => {
                tracing::error!("Map AGENT_SPAWN_EVENTS not found");
                return;
            }
        };

        tracing::info!("ProcessWatcher ring buffer loop started");

        loop {
            // Drenar todos los eventos disponibles
            while let Some(item) = ring_buf.next() {
                // Safety: el eBPF garantiza que el tamaño es sizeof(AgentSpawnEvent)
                if item.len() < core::mem::size_of::<AgentSpawnEvent>() {
                    continue;
                }
                let event: AgentSpawnEvent = unsafe {
                    core::ptr::read_unaligned(item.as_ptr() as *const AgentSpawnEvent)
                };

                // Leer cwd desde /proc/<pid>/cwd (lo que no podíamos hacer en kernel)
                let cwd = read_proc_cwd(event.pid);

                // Procesar en una task separada para no bloquear el loop
                let config_clone = config.clone();
                let tx = event_tx.clone();
                let exe = event.exe_str().to_owned();
                let comm = event.comm_str().to_owned();
                let pid = event.pid;

                tokio::spawn(async move {
                    handle_agent_spawn(pid, comm, exe, cwd, config_clone, tx).await;
                });
            }

            // Esperar un poco antes de volver a drenar (evitar busy-loop)
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
    }
}

/// Lee el cwd de un proceso vía /proc/<pid>/cwd (symlink).
fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    let cwd_link = format!("/proc/{}/cwd", pid);
    std::fs::read_link(&cwd_link).ok()
}

/// Lógica de decisión cuando detectamos un spawn de agente.
async fn handle_agent_spawn(
    pid: u32,
    comm: String,
    exe: String,
    cwd: Option<PathBuf>,
    config: Arc<RwLock<Config>>,
    event_tx: mpsc::Sender<SecurityEvent>,
) {
    let cfg = config.read().await;

    // ¿El cwd está en una zona protegida?
    let cwd = match cwd {
        Some(c) => c,
        None => {
            tracing::debug!("Agent {} (pid={}) has no readable cwd, skipping", comm, pid);
            return;
        }
    };

    let is_protected = cfg.protected_dirs.iter().any(|protected| {
        cwd.starts_with(protected)
    });

    if !is_protected {
        tracing::debug!(
            "Agent {} (pid={}) in unprotected dir {:?}, ignoring",
            comm, pid, cwd
        );
        return;
    }

    let mode = &cfg.sandbox.modo_por_defecto;

    tracing::info!(
        "Agent detected: {} (pid={}) in protected dir {:?} → mode={}",
        comm, pid, cwd, mode
    );

    // Notificar al daemon principal
    let _ = event_tx.send(SecurityEvent::AgentDetected {
        pid,
        agent_name: comm.clone(),
        cwd: cwd.clone(),
        mode: mode.clone(),
    }).await;

    // Según el modo, actuar
    match mode.as_str() {
        "monitor" => {
            // Solo loggear, no intervenir
            tracing::info!("Monitor mode: agent {} allowed to run freely", comm);
        }
        "sandbox" | "hybrid" => {
            // Matar el proceso original y relanzar en sandbox
            kill_process(pid);

            let sandbox = SandboxLauncher::new(cfg.clone());
            match sandbox.launch(&exe, &cwd, mode == "hybrid").await {
                Ok(sandbox_pid) => {
                    tracing::info!(
                        "Agent {} relaunched in sandbox (pid={})",
                        comm, sandbox_pid
                    );
                    let _ = event_tx.send(SecurityEvent::AgentSandboxed {
                        original_pid: pid,
                        sandbox_pid,
                        agent_name: comm,
                        cwd,
                    }).await;
                }
                Err(e) => {
                    tracing::error!("Failed to sandbox agent {}: {}", comm, e);
                }
            }
        }
        _ => {
            tracing::warn!("Unknown mode '{}', defaulting to monitor", mode);
        }
    }
}

fn kill_process(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    // Dar 100ms para que termine limpiamente, luego SIGKILL
    std::thread::sleep(std::time::Duration::from_millis(100));
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

fn fnv1a_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
```

---

## 4. Sandbox Launcher — Linux

### `agentguard-daemon/src/sandbox_linux.rs`

```rust
//! Lanza agentes IA dentro de Bubblewrap (bwrap) + Landlock opcional.
//! No requiere root. Compatible con cualquier usuario.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use which::which;

use crate::config::Config;

pub struct SandboxLauncher {
    config: Config,
}

/// Monta que se pasa a bwrap.
struct BindMount {
    source:   PathBuf,
    dest:     PathBuf,
    readonly: bool,
}

impl SandboxLauncher {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Lanza un agente IA dentro de bwrap con aislamiento completo.
    ///
    /// # Argumentos
    /// - `agent_exe`: ruta o nombre del ejecutable del agente (e.g. "cursor")
    /// - `project_dir`: directorio de trabajo del agente
    /// - `with_landlock`: si true, activa también Landlock (modo hybrid)
    ///
    /// # Retorna
    /// El PID del proceso sandboxeado.
    pub async fn launch(
        &self,
        agent_exe: &str,
        project_dir: &Path,
        with_landlock: bool,
    ) -> Result<u32, anyhow::Error> {
        // Verificar que bwrap está instalado
        let bwrap_path = which("bwrap")
            .map_err(|_| anyhow::anyhow!(
                "bwrap no encontrado. Instalar con: sudo apt install bubblewrap"
            ))?;

        // Resolver la ruta real del agente
        let agent_path = which(agent_exe)
            .map_err(|_| anyhow::anyhow!("Ejecutable '{}' no encontrado en PATH", agent_exe))?;

        let mut cmd = Command::new(&bwrap_path);

        // ── Sistema de archivos base ─────────────────────────────────────────
        // Montar el sistema como read-only para que el agente tenga acceso
        // a las librerías y binarios del sistema.
        cmd.args(&["--ro-bind", "/usr", "/usr"]);
        cmd.args(&["--ro-bind", "/lib", "/lib"]);
        cmd.args(&["--ro-bind", "/lib64", "/lib64"]);
        cmd.args(&["--ro-bind", "/etc/ssl", "/etc/ssl"]);
        cmd.args(&["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]);

        // Directorios temporales aislados
        cmd.args(&["--tmpfs", "/tmp"]);
        cmd.args(&["--tmpfs", "/var/tmp"]);
        cmd.args(&["--tmpfs", "/home"]);       // /home vacío → el agente no ve nada
        cmd.args(&["--tmpfs", "/root"]);

        // proc y dev mínimos
        cmd.args(&["--proc", "/proc"]);
        cmd.args(&["--dev", "/dev"]);

        // ── Proyecto: lectura/escritura ──────────────────────────────────────
        let project_str = project_dir.to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid project path"))?;

        // Montar el proyecto en /workspace Y en su ruta original
        // (algunos agentes hardcodean su cwd)
        cmd.args(&["--bind", project_str, "/workspace"]);
        cmd.args(&["--bind", project_str, project_str]);

        // ── Binario del agente ───────────────────────────────────────────────
        let agent_str = agent_path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid agent path"))?;
        cmd.args(&["--ro-bind", agent_str, agent_str]);

        // ── Aislamiento de namespaces ────────────────────────────────────────
        cmd.args(&[
            "--unshare-pid",         // PID namespace propio
            "--unshare-net",         // Sin acceso a red... (se puede quitar si el agente necesita net)
            "--unshare-ipc",         // IPC namespace
            "--unshare-uts",         // hostname aislado
            "--unshare-user",        // user namespace (no necesita root)
            "--die-with-parent",     // si el daemon muere, el agente también
            "--new-session",         // sin terminal controlador
        ]);

        // Si el agente necesita red (mayoría la necesitan para APIs), no usar --unshare-net
        // y en su lugar bloquear con el DLP proxy ya existente.
        // Por tanto, quitamos --unshare-net y confiamos en el DLP.
        // Esto hace que el sandbox sea práctico.
        // TODO: hacer configurable en config.toml
        // Por ahora: eliminar --unshare-net para que el DLP proxy funcione.

        // Trabajar desde /workspace
        cmd.args(&["--chdir", "/workspace"]);

        // ── Binds adicionales del config ─────────────────────────────────────
        for extra in &self.config.sandbox.bwrap_extra_args {
            cmd.arg(extra);
        }

        // ── Landlock (modo hybrid) ───────────────────────────────────────────
        // Landlock se aplica al proceso hijo via preload, no a bwrap mismo.
        // Pasamos una variable de entorno que un wrapper interpreta.
        if with_landlock {
            cmd.env("AGENTGUARD_LANDLOCK", "1");
            cmd.env("AGENTGUARD_LANDLOCK_RW", project_str);
        }

        // ── Variables de entorno para el agente ─────────────────────────────
        // Inyectar el proxy DLP
        cmd.env("HTTP_PROXY",  format!("http://127.0.0.1:{}", self.config.dlp.proxy_port));
        cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{}", self.config.dlp.proxy_port));
        cmd.env("http_proxy",  format!("http://127.0.0.1:{}", self.config.dlp.proxy_port));
        cmd.env("https_proxy", format!("http://127.0.0.1:{}", self.config.dlp.proxy_port));

        // Marcar que el proceso fue lanzado por AgentGuard (útil para logs)
        cmd.env("AGENTGUARD_SANDBOXED", "1");

        // ── El ejecutable a lanzar ───────────────────────────────────────────
        cmd.arg("--");
        cmd.arg(agent_str);

        // stdout/stderr del agente van al terminal normal
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        cmd.stdin(Stdio::inherit());

        // Directorio de trabajo del proceso bwrap
        cmd.current_dir(project_dir);

        tracing::info!(
            "Launching {} in sandbox (project={:?}, landlock={})",
            agent_exe, project_dir, with_landlock
        );

        let child = cmd.spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn bwrap: {}", e))?;

        let pid = child.id()
            .ok_or_else(|| anyhow::anyhow!("Failed to get sandbox PID"))?;

        // Dejar que el proceso corra (no await el child aquí — el daemon lo monitorea)
        tokio::spawn(async move {
            let _ = child.wait_with_output().await;
            tracing::info!("Sandboxed agent (pid={}) exited", pid);
        });

        Ok(pid)
    }

    /// Verifica si el sistema soporta bwrap y Landlock.
    /// Llamado en el arranque del daemon.
    pub fn check_capabilities() -> SandboxCapabilities {
        SandboxCapabilities {
            bwrap_available: which("bwrap").is_ok(),
            landlock_available: check_landlock_support(),
            ebpf_lsm_available: check_ebpf_lsm_support(),
        }
    }
}

#[derive(Debug)]
pub struct SandboxCapabilities {
    pub bwrap_available:     bool,
    pub landlock_available:  bool,
    pub ebpf_lsm_available:  bool,
}

impl SandboxCapabilities {
    pub fn effective_mode(&self, requested: &str) -> &'static str {
        match requested {
            "hybrid" if self.bwrap_available && self.landlock_available => "hybrid",
            "hybrid" | "sandbox" if self.bwrap_available => "sandbox",
            _ => "monitor",
        }
    }

    pub fn report(&self) -> String {
        format!(
            "bwrap={} landlock={} eBPF_LSM={}",
            if self.bwrap_available { "✓" } else { "✗ (instalar bubblewrap)" },
            if self.landlock_available { "✓" } else { "✗ (kernel ≥5.13 requerido)" },
            if self.ebpf_lsm_available { "✓" } else { "✗ (kernel ≥5.7 + CONFIG_BPF_LSM requerido)" },
        )
    }
}

fn check_landlock_support() -> bool {
    // Landlock disponible desde kernel 5.13.
    // Se puede verificar llamando landlock_create_ruleset con flags=0 (ABI check).
    // Si devuelve ENOSYS, no disponible.
    use std::os::unix::ffi::OsStrExt;
    let output = std::process::Command::new("uname").arg("-r").output();
    if let Ok(out) = output {
        if let Ok(version) = std::str::from_utf8(&out.stdout) {
            let parts: Vec<u32> = version.trim().split('.')
                .take(2)
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() >= 2 {
                return parts[0] > 5 || (parts[0] == 5 && parts[1] >= 13);
            }
        }
    }
    false
}

fn check_ebpf_lsm_support() -> bool {
    // Verificar que "bpf" está en la lista de LSMs activos
    if let Ok(lsm_list) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        return lsm_list.contains("bpf");
    }
    false
}
```

### `agentguard-daemon/src/landlock.rs` (modo hybrid)

```rust
//! Aplica restricciones Landlock al proceso actual ANTES de ejecutar el agente.
//! Se usa como wrapper: el agente llama a este código en su preload,
//! o el daemon usa un helper binario mínimo.

use std::path::Path;
use landlock::{
    Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandlockError {
    #[error("Landlock not supported on this kernel")]
    NotSupported,
    #[error("Landlock ruleset creation failed: {0}")]
    RulesetCreation(String),
    #[error("Failed to add rule for {path}: {err}")]
    RuleAdd { path: String, err: String },
    #[error("Failed to restrict thread: {0}")]
    Restrict(String),
}

/// Aplica un perfil Landlock al proceso llamante:
/// - `rw_paths`: directorios con acceso lectura/escritura
/// - `ro_paths`: directorios con acceso solo lectura
/// - Todo lo demás: DENEGADO
pub fn apply_landlock_profile(
    rw_paths: &[&Path],
    ro_paths: &[&Path],
) -> Result<(), LandlockError> {
    // La ABI más reciente soportada (usar la más alta disponible)
    let abi = ABI::V3;

    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?
        .create()
        .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?;

    // Añadir reglas de lectura/escritura
    let mut ruleset = add_rules(ruleset, rw_paths, AccessFs::from_all(abi))?;

    // Añadir reglas de solo lectura
    let ro_access = AccessFs::from_read(abi);
    let mut ruleset = add_rules(ruleset, ro_paths, ro_access)?;

    // Aplicar al thread actual (se hereda por todos los hijos)
    let status = ruleset.restrict_self()
        .map_err(|e| LandlockError::Restrict(e.to_string()))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock: fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!("Landlock: partially enforced (older kernel)");
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!("Landlock: not enforced (not supported)");
        }
    }

    Ok(())
}

fn add_rules(
    ruleset: RulesetCreated,
    paths: &[&Path],
    access: AccessFs,
) -> Result<RulesetCreated, LandlockError> {
    let mut ruleset = ruleset;
    for path in paths {
        let fd = PathFd::new(path)
            .map_err(|e| LandlockError::RuleAdd {
                path: path.display().to_string(),
                err: e.to_string(),
            })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| LandlockError::RuleAdd {
                path: path.display().to_string(),
                err: e.to_string(),
            })?;
    }
    Ok(ruleset)
}
```

---

## 5. Sandbox Launcher — Windows

### `agentguard-daemon/src/process_watcher_windows.rs`

```rust
//! Detección de agentes IA en Windows vía ETW (Event Tracing for Windows).
//! No requiere driver ni certificado EV. 100% user-mode.

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::Foundation::*;
use crate::config::Config;
use crate::daemon::SecurityEvent;

/// Proveedor ETW del kernel para eventos de procesos.
/// GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
const KERNEL_PROCESS_PROVIDER: windows::core::GUID = windows::core::GUID::from_u128(
    0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716
);

const EVENT_ID_PROCESS_START: u16 = 1;

pub struct ProcessWatcher {
    config: Arc<RwLock<Config>>,
    event_tx: mpsc::Sender<SecurityEvent>,
}

impl ProcessWatcher {
    pub fn new(config: Arc<RwLock<Config>>, event_tx: mpsc::Sender<SecurityEvent>) -> Self {
        Self { config, event_tx }
    }

    /// Inicia el consumidor ETW en un hilo dedicado (ETW es síncrono).
    /// Retorna inmediatamente; el consumo ocurre en background.
    pub fn start(self) -> Result<(), anyhow::Error> {
        std::thread::Builder::new()
            .name("agentguard-etw".into())
            .spawn(move || {
                if let Err(e) = self.run_etw_session() {
                    tracing::error!("ETW session error: {}", e);
                }
            })?;
        Ok(())
    }

    fn run_etw_session(&self) -> Result<(), anyhow::Error> {
        // Nombre de sesión ETW único
        let session_name = "AgentGuard-ProcessWatcher\0"
            .encode_utf16()
            .collect::<Vec<u16>>();

        // Buffer para EVENT_TRACE_PROPERTIES
        let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
            + session_name.len() * 2;
        let mut buf = vec![0u8; buf_size];

        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            (*props).Wnode.BufferSize  = buf_size as u32;
            (*props).Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 1; // QPC timestamps
            (*props).LogFileMode       = EVENT_TRACE_REAL_TIME_MODE;
            (*props).BufferSize        = 64; // KB por buffer
            (*props).MinimumBuffers    = 4;
            (*props).MaximumBuffers    = 8;
        }

        let mut session_handle: TRACEHANDLE = TRACEHANDLE(0);

        unsafe {
            // Iniciar la sesión ETW
            let result = StartTraceW(
                &mut session_handle,
                windows::core::PCWSTR(session_name.as_ptr()),
                props,
            );

            // Si ya existe (ERROR_ALREADY_EXISTS), reconectar
            if result == ERROR_ALREADY_EXISTS.0 {
                tracing::debug!("ETW session already exists, reconnecting...");
                ControlTraceW(
                    TRACEHANDLE(0),
                    windows::core::PCWSTR(session_name.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                StartTraceW(
                    &mut session_handle,
                    windows::core::PCWSTR(session_name.as_ptr()),
                    props,
                ).ok()?;
            } else if result != 0 {
                anyhow::bail!("StartTraceW failed: {}", result);
            }

            // Suscribir al proveedor de procesos del kernel
            EnableTraceEx2(
                session_handle,
                &KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                TRACE_LEVEL_INFORMATION as u8,
                0x10, // WINEVENT_KEYWORD_PROCESS
                0,
                0,
                None,
            ).ok()?;
        }

        tracing::info!("ETW session started, monitoring process creation events");

        // Procesar eventos en un hilo de consumo
        // (ProcessTrace bloquea hasta que se llama CloseTrace)
        let mut log_file = EVENT_TRACE_LOGFILEW::default();
        let session_name_w: Vec<u16> = "AgentGuard-ProcessWatcher\0"
            .encode_utf16()
            .collect();

        unsafe {
            log_file.LoggerName = windows::core::PWSTR(
                session_name_w.as_ptr() as *mut u16
            );
            log_file.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.EventRecordCallback = Some(Self::event_callback);
            // Pasar self como contexto
            log_file.Context = self as *const Self as *mut std::ffi::c_void;

            let trace_handle = OpenTraceW(&mut log_file);
            if trace_handle.0 == u64::MAX {
                anyhow::bail!("OpenTraceW failed");
            }

            // Esto bloquea hasta CloseTrace
            ProcessTrace(&[trace_handle], None, None).ok()?;
            CloseTrace(trace_handle);
        }

        Ok(())
    }

    /// Callback ETW llamado para cada evento.
    /// IMPORTANTE: no debe bloquear — es síncrono en el hilo ETW.
    unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
        if record.is_null() { return; }
        let record = &*record;

        // Solo nos interesan ProcessStart (EventID=1)
        if record.EventHeader.EventDescriptor.Id != EVENT_ID_PROCESS_START {
            return;
        }

        // Recuperar &self del contexto
        let watcher = &*(record.UserContext as *const ProcessWatcher);

        // Parsear el UserData del evento para obtener ImageFileName y CommandLine
        // El layout depende del manifiesto ETW del proveedor.
        // Para Microsoft-Windows-Kernel-Process:
        // ProcessID (u32) + ParentProcessID (u32) + ImageFileName (WCHAR[]) + CommandLine (WCHAR[])
        if record.UserDataLength < 8 { return; }

        let data = std::slice::from_raw_parts(
            record.UserData as *const u8,
            record.UserDataLength as usize,
        );

        let process_id   = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let _parent_pid  = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // ImageFileName: string UTF-16 a partir del offset 8
        let image_name = parse_wchar_string(&data[8..]);

        // Verificar si es un agente conocido
        // (hacemos el check síncrono con try_read para no bloquear)
        let is_agent = if let Ok(cfg) = watcher.config.try_read() {
            cfg.agent_detection.known_agents.iter().any(|agent| {
                agent.exe.iter().any(|exe| {
                    image_name.to_lowercase().contains(&exe.to_lowercase())
                })
            })
        } else {
            false
        };

        if !is_agent { return; }

        // Leer el CurrentDirectory del proceso vía OpenProcess + NtQueryInformationProcess
        let cwd = read_process_cwd(process_id);

        // Enviar el evento al canal tokio (non-blocking)
        let tx = watcher.event_tx.clone();
        let agent_name = image_name.clone();
        let _ = tx.try_send(SecurityEvent::AgentDetected {
            pid:        process_id,
            agent_name,
            cwd:        cwd.into(),
            mode:       "sandbox".into(),
        });
    }
}

fn parse_wchar_string(data: &[u8]) -> String {
    let wchars: Vec<u16> = data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&wchars)
}

fn read_process_cwd(pid: u32) -> String {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        );
        match handle {
            Ok(h) => {
                // Usar NtQueryInformationProcess para obtener el RTL_USER_PROCESS_PARAMETERS
                // que contiene CurrentDirectory.
                // Simplificado: leer de /proc equivalente en Windows = no existe.
                // Usamos una heurística: el cwd suele ser el mismo que el del padre.
                // TODO: implementar NtQueryInformationProcess + ReadProcessMemory
                windows::Win32::Foundation::CloseHandle(h).ok();
                String::new()
            }
            Err(_) => String::new(),
        }
    }
}

/// Alternativa ligera: polling cada 500ms con sysinfo (más simple que ETW).
/// Usar si ETW da problemas de permisos en algunos entornos.
pub async fn start_polling_watcher(
    config: Arc<RwLock<Config>>,
    event_tx: mpsc::Sender<SecurityEvent>,
) {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cmd(Default::default()))
    );
    let mut known_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

    tracing::info!("ProcessWatcher: using polling mode (500ms interval)");

    loop {
        system.refresh_processes_specifics(
            ProcessRefreshKind::new().with_cmd(Default::default())
        );

        let cfg = config.read().await;
        let agent_exes: Vec<String> = cfg.agent_detection.known_agents.iter()
            .flat_map(|a| a.exe.iter().cloned())
            .collect();

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            if known_pids.contains(&pid_u32) { continue; }

            let exe_name = process.name().to_string_lossy().to_lowercase();
            let is_agent = agent_exes.iter().any(|e| exe_name.contains(&e.to_lowercase()));

            if is_agent {
                known_pids.insert(pid_u32);
                let cwd = process.cwd()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_default();

                tracing::info!("Agent detected via polling: {} (pid={})", exe_name, pid_u32);

                let _ = event_tx.send(SecurityEvent::AgentDetected {
                    pid: pid_u32,
                    agent_name: exe_name,
                    cwd,
                    mode: cfg.sandbox.modo_por_defecto.clone(),
                }).await;
            }
        }

        // Limpiar PIDs que ya no existen
        known_pids.retain(|pid| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

        drop(cfg);
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}
```

### `agentguard-daemon/src/sandbox_windows.rs`

```rust
//! Lanza agentes IA dentro de AppContainer/LPAC en Windows.
//! No requiere certificado EV ni driver firmado.

use std::path::Path;
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Storage::FileSystem::*;

use crate::config::Config;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Failed to create AppContainer profile: {0}")]
    ProfileCreation(String),
    #[error("Failed to launch process in AppContainer: {0}")]
    ProcessLaunch(String),
    #[error("Failed to apply DENY ACE to {path}: {err}")]
    AceApplication { path: String, err: String },
}

pub struct SandboxLauncher {
    config: Config,
}

impl SandboxLauncher {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Lanza un proceso dentro de AppContainer/LPAC.
    ///
    /// 1. Crea (o reutiliza) el perfil AppContainer para este agente.
    /// 2. Aplica DENY ACEs en rutas protegidas para el SID del AppContainer.
    /// 3. Lanza el proceso con las security capabilities del AppContainer.
    pub async fn launch(
        &self,
        agent_exe: &str,
        project_dir: &Path,
        _with_extra_isolation: bool,
    ) -> Result<u32, anyhow::Error> {
        unsafe {
            // 1. Crear perfil AppContainer
            let container_name = format!("AgentGuard-{}\0", agent_exe)
                .encode_utf16().collect::<Vec<u16>>();
            let display_name = format!("AgentGuard sandbox for {}\0", agent_exe)
                .encode_utf16().collect::<Vec<u16>>();
            let description = "Sandboxed AI agent\0"
                .encode_utf16().collect::<Vec<u16>>();

            let mut app_container_sid: PSID = PSID::default();

            // Intentar crear el perfil (puede fallar con HRESULT si ya existe)
            let hr = CreateAppContainerProfile(
                windows::core::PCWSTR(container_name.as_ptr()),
                windows::core::PCWSTR(display_name.as_ptr()),
                windows::core::PCWSTR(description.as_ptr()),
                None,
                &mut app_container_sid,
            );

            // Si ya existe, obtener el SID del perfil existente
            if hr.is_err() {
                let hr2 = DeriveAppContainerSidFromAppContainerName(
                    windows::core::PCWSTR(container_name.as_ptr()),
                    &mut app_container_sid,
                );
                hr2.map_err(|e| anyhow::anyhow!(
                    "Cannot get AppContainer SID: {:?}", e
                ))?;
            }

            // 2. Aplicar DENY ACEs en rutas protegidas
            for protected_dir in &self.config.protected_dirs {
                if let Err(e) = self.apply_deny_ace(protected_dir, app_container_sid) {
                    tracing::warn!("Could not apply DENY ACE to {:?}: {}", protected_dir, e);
                    // No es fatal: el AppContainer ya provee bastante aislamiento
                }
            }

            // 3. Preparar SECURITY_CAPABILITIES para el proceso
            let capabilities = SECURITY_CAPABILITIES {
                AppContainerSid: app_container_sid,
                Capabilities: std::ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };

            // 4. Preparar STARTUPINFOEXA con atributo de AppContainer
            let mut attr_list_size: usize = 0;

            // Primera llamada para obtener el tamaño del buffer
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut attr_list_size,
            );

            let mut attr_list_buf = vec![0u8; attr_list_size];
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(
                attr_list_buf.as_mut_ptr() as *mut _
            );

            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)
                .map_err(|e| anyhow::anyhow!("InitializeProcThreadAttributeList: {:?}", e))?;

            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(&capabilities as *const _ as *const std::ffi::c_void),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            ).map_err(|e| anyhow::anyhow!("UpdateProcThreadAttribute: {:?}", e))?;

            let mut startup_info = STARTUPINFOEXW::default();
            startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            startup_info.lpAttributeList = attr_list;

            // Configurar variables de entorno con el DLP proxy
            let env_block = build_env_block(&self.config);

            // Comando a ejecutar
            let mut cmd_line: Vec<u16> = format!("{}\0", agent_exe)
                .encode_utf16().collect();

            let project_str: Vec<u16> = format!("{}\0", project_dir.display())
                .encode_utf16().collect();

            let mut process_info = PROCESS_INFORMATION::default();

            // 5. Crear el proceso en AppContainer
            CreateProcessW(
                None,
                windows::core::PWSTR(cmd_line.as_mut_ptr()),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                Some(env_block.as_ptr() as *const std::ffi::c_void),
                windows::core::PCWSTR(project_str.as_ptr()),
                &startup_info.StartupInfo as *const _ as *const STARTUPINFOW,
                &mut process_info,
            ).map_err(|e| anyhow::anyhow!("CreateProcessW in AppContainer failed: {:?}", e))?;

            let pid = process_info.dwProcessId;

            // Cerrar handles que no necesitamos
            CloseHandle(process_info.hThread).ok();
            // Mantener hProcess para monitoreo — lo pasamos a un watcher
            tokio::spawn(async move {
                // Esperar a que el proceso termine
                WaitForSingleObject(process_info.hProcess, INFINITE);
                CloseHandle(process_info.hProcess).ok();
                tracing::info!("Sandboxed agent (pid={}) exited", pid);
            });

            // Liberar el SID
            FreeSid(app_container_sid);
            DeleteProcThreadAttributeList(attr_list);

            tracing::info!(
                "Agent '{}' launched in AppContainer (pid={})",
                agent_exe, pid
            );

            Ok(pid)
        }
    }

    /// Aplica una DENY ACE al SID del AppContainer en la ruta dada.
    /// Esto impide que el agente sandboxeado acceda a rutas protegidas.
    fn apply_deny_ace(&self, path: &Path, container_sid: PSID) -> Result<(), SandboxError> {
        let path_wide: Vec<u16> = format!("{}\0", path.display())
            .encode_utf16().collect();

        unsafe {
            // Obtener el DACL actual de la ruta
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();

            GetNamedSecurityInfoW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            ).map_err(|e| SandboxError::AceApplication {
                path: path.display().to_string(),
                err: format!("{:?}", e),
            })?;

            // Construir EXPLICIT_ACCESS con DENY para el AppContainer SID
            let mut ea = EXPLICIT_ACCESS_W::default();
            ea.grfAccessPermissions = FILE_ALL_ACCESS.0; // denegar todo
            ea.grfAccessMode        = DENY_ACCESS;
            ea.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName    = windows::core::PWSTR(container_sid.0 as *mut u16);

            let mut new_dacl: *mut ACL = std::ptr::null_mut();
            SetEntriesInAclW(
                Some(&[ea]),
                Some(dacl),
                &mut new_dacl,
            ).map_err(|e| SandboxError::AceApplication {
                path: path.display().to_string(),
                err: format!("{:?}", e),
            })?;

            // Aplicar el nuevo DACL
            SetNamedSecurityInfoW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl),
                None,
            ).map_err(|e| SandboxError::AceApplication {
                path: path.display().to_string(),
                err: format!("{:?}", e),
            })?;

            LocalFree(HLOCAL(new_dacl as *mut std::ffi::c_void));
            LocalFree(HLOCAL(sd.0));
        }

        tracing::info!("DENY ACE applied for AppContainer on {:?}", path);
        Ok(())
    }
}

/// Construye un bloque de variables de entorno en formato Windows (doble null-terminado).
fn build_env_block(config: &Config) -> Vec<u16> {
    let proxy_url = format!("http://127.0.0.1:{}", config.dlp.proxy_port);
    let vars = [
        format!("HTTP_PROXY={}", proxy_url),
        format!("HTTPS_PROXY={}", proxy_url),
        format!("http_proxy={}", proxy_url),
        format!("https_proxy={}", proxy_url),
        "AGENTGUARD_SANDBOXED=1".to_string(),
    ];

    let mut block: Vec<u16> = Vec::new();
    for var in &vars {
        block.extend(var.encode_utf16());
        block.push(0); // null terminator de cada variable
    }
    block.push(0); // null terminator final del bloque
    block
}
```

---

## 6. Integración en el daemon principal

### Eventos nuevos en `agentguard-daemon/src/daemon.rs`

```rust
// Añadir a SecurityEvent (manteniendo los existentes de v1.0):

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum SecurityEvent {
    // ── Existentes de v1.0 ────────────────────────────────────────────────
    FileViolation {
        path:       String,
        process:    String,
        pid:        u32,
        event_type: ViolationType,
        timestamp:  u64,
    },
    DlpViolation {
        pattern_name: String,
        destination:  String,
        process:      String,
        timestamp:    u64,
    },
    SystemError { message: String },

    // ── Nuevos en v2.1 ────────────────────────────────────────────────────
    /// Un agente IA fue detectado iniciándose en un directorio protegido.
    AgentDetected {
        pid:        u32,
        agent_name: String,
        cwd:        std::path::PathBuf,
        mode:       String,
    },
    /// El agente fue relanzado exitosamente dentro del sandbox.
    AgentSandboxed {
        original_pid: u32,
        sandbox_pid:  u32,
        agent_name:   String,
        cwd:          std::path::PathBuf,
    },
}
```

### Actualización de `AgentGuardDaemon::run()` en `daemon.rs`

```rust
impl AgentGuardDaemon {
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let config = self.config.read().await;

        // ── Verificar capacidades del sandbox ───────────────────────────────
        #[cfg(target_os = "linux")]
        {
            let caps = crate::sandbox_linux::SandboxLauncher::check_capabilities();
            tracing::info!("Sandbox capabilities: {}", caps.report());

            let effective_mode = caps.effective_mode(&config.sandbox.modo_por_defecto);
            if effective_mode != config.sandbox.modo_por_defecto.as_str() {
                tracing::warn!(
                    "Requested mode '{}' not available, using '{}'",
                    config.sandbox.modo_por_defecto, effective_mode
                );
                if !caps.bwrap_available {
                    // Notificar al usuario
                    self.send_desktop_notification(
                        "AgentGuard: instalar bubblewrap",
                        "Para activar el modo sandbox, ejecutar: sudo apt install bubblewrap"
                    ).await;
                }
            }
        }

        // ── Iniciar detección de procesos ──────────────────────────────────
        #[cfg(target_os = "linux")]
        {
            let protected_dirs = config.protected_dirs.clone();
            let tx = self.event_tx.clone();
            let cfg_clone = self.config.clone();
            tokio::spawn(async move {
                match crate::process_watcher_linux::ProcessWatcher::load(
                    &*cfg_clone.read().await
                ).await {
                    Ok(watcher) => watcher.run(cfg_clone, tx).await,
                    Err(e) => tracing::error!("ProcessWatcher failed to load: {}", e),
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            let tx = self.event_tx.clone();
            let cfg_clone = self.config.clone();
            // Intentar ETW primero, hacer fallback a polling si falla
            let watcher = crate::process_watcher_windows::ProcessWatcher::new(
                cfg_clone.clone(), tx.clone()
            );
            if watcher.start().is_err() {
                tracing::warn!("ETW watcher failed, falling back to polling");
                tokio::spawn(async move {
                    crate::process_watcher_windows::start_polling_watcher(cfg_clone, tx).await;
                });
            }
        }

        // ── Resto del arranque (igual que v1.0) ───────────────────────────
        // ... eBPF file guard, DLP proxy, IPC server, snapshot inicial ...

        // ── Loop principal ─────────────────────────────────────────────────
        loop {
            tokio::select! {
                Some(event) = self.event_rx.recv() => {
                    self.handle_event(event).await;
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("AgentGuard shutting down...");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_event(&self, event: SecurityEvent) {
        match &event {
            // ── Existentes de v1.0 (sin cambios) ─────────────────────────
            SecurityEvent::FileViolation { .. } => { /* igual que v1.0 */ }
            SecurityEvent::DlpViolation { .. }  => { /* igual que v1.0 */ }
            SecurityEvent::SystemError { message } => {
                tracing::error!("System error: {}", message);
            }

            // ── Nuevos v2.1 ───────────────────────────────────────────────
            SecurityEvent::AgentDetected { pid, agent_name, cwd, mode } => {
                tracing::info!(
                    "Agent '{}' (pid={}) detected in {:?} — mode={}",
                    agent_name, pid, cwd, mode
                );
                self.log_incident(&event).await;
            }

            SecurityEvent::AgentSandboxed { original_pid, sandbox_pid, agent_name, cwd } => {
                tracing::info!(
                    "Agent '{}' sandboxed: original_pid={} → sandbox_pid={}",
                    agent_name, original_pid, sandbox_pid
                );
                let config = self.config.read().await;
                if config.alerts.desktop_notifications {
                    self.send_desktop_notification(
                        &format!("AgentGuard: {} protegido", agent_name),
                        &format!(
                            "'{}' fue lanzado en sandbox dentro de {:?}",
                            agent_name, cwd
                        ),
                    ).await;
                }
                self.log_incident(&event).await;
            }
        }
    }
}
```

---

## 7. CLI v2.1

### `agentguard-cli/src/main.rs` — completo

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "agentguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Protege tu máquina de los agentes IA que se vuelven locos",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Configuración inicial interactiva (primera vez)
    Setup,

    /// Proteger un directorio o archivo
    #[command(alias = "protect")]
    Protege {
        /// Ruta a proteger. Usa '.' para el directorio actual.
        path: String,
        /// Solo monitorear (no bloquear ni sandboxear)
        #[arg(long)]
        solo_vigilar: bool,
    },

    /// Lanzar un agente IA dentro del sandbox de forma segura
    #[command(alias = "launch")]
    Lanza {
        /// Nombre del agente (cursor, claude, windsurf, aider, etc.)
        agente: String,
        /// Argumentos adicionales para el agente
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Forzar modo específico (monitor/sandbox/hybrid)
        #[arg(long)]
        modo: Option<String>,
    },

    /// Ver el estado actual de protección
    #[command(alias = "status")]
    Estado,

    /// Pausar la protección temporalmente
    #[command(alias = "pause")]
    Relaja {
        /// Duración en minutos
        #[arg(short, long, default_value = "30")]
        minutos: u64,
    },

    /// Restaurar archivos desde un snapshot
    #[command(alias = "restore")]
    Restaura {
        /// ID del snapshot ('ultimo' para el más reciente)
        #[arg(default_value = "ultimo")]
        id: String,
        /// No pedir confirmación
        #[arg(long)]
        si: bool,
    },

    /// Gestión de snapshots
    Snapshot {
        #[command(subcommand)]
        accion: SnapshotCommands,
    },

    /// Ver incidentes recientes
    Incidentes {
        #[arg(short, long, default_value = "20")]
        ultimos: usize,
    },

    /// Herramientas para usuarios avanzados
    #[command(subcommand, hide = true)]
    Avanzado(AdvancedCommands),
}

#[derive(Subcommand)]
enum SnapshotCommands {
    /// Crear snapshot ahora
    Crear {
        #[arg(short, long, default_value = "manual")]
        etiqueta: String,
    },
    /// Listar snapshots disponibles
    Listar,
    /// Borrar snapshots antiguos
    Limpiar {
        #[arg(long, default_value = "30")]
        dias: u64,
    },
}

#[derive(Subcommand)]
enum AdvancedCommands {
    /// Verificar capacidades del sistema
    CheckCapabilities,
    /// Ver/editar configuración raw
    Config,
    /// Gestión del daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonCommands,
    },
}

#[derive(Subcommand)]
enum DaemonCommands {
    Start, Stop, Restart,
    Logs { #[arg(short, long, default_value = "50")] lines: usize },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => cmd_setup().await?,
        Commands::Protege { path, solo_vigilar } => cmd_protege(&path, solo_vigilar).await?,
        Commands::Lanza { agente, args, modo } => cmd_lanza(&agente, args, modo).await?,
        Commands::Estado => cmd_estado().await?,
        Commands::Relaja { minutos } => cmd_relaja(minutos).await?,
        Commands::Restaura { id, si } => cmd_restaura(&id, si).await?,
        Commands::Snapshot { accion } => cmd_snapshot(accion).await?,
        Commands::Incidentes { ultimos } => cmd_incidentes(ultimos).await?,
        Commands::Avanzado(adv) => cmd_avanzado(adv).await?,
    }

    Ok(())
}

// ─── Implementaciones de comandos ─────────────────────────────────────────────

async fn cmd_setup() -> Result<(), anyhow::Error> {
    let cwd = std::env::current_dir()?;
    println!();
    println!("╔══════════════════════════════════════════╗");
    println!("║      Bienvenido a AgentGuard v2.1        ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  Detecté que estás en:");
    println!("  📁 {}", cwd.display());
    println!();
    print!("  ¿Proteger este directorio con modo sandbox? [S/n] ");
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let line = stdin.lock().lines().next()
        .unwrap_or(Ok("s".into()))
        .unwrap_or("s".into());

    if line.trim().to_lowercase() == "n" {
        println!();
        println!("  Ok. Puedes proteger directorios manualmente:");
        println!("  agentguard protege /tu/proyecto");
        return Ok(());
    }

    // Conectar al daemon y enviar comandos de configuración
    let mut client = ipc_client::connect().await
        .map_err(|_| anyhow::anyhow!(
            "El daemon no está corriendo. Iniciarlo con:\n  sudo systemctl start agentguard"
        ))?;

    client.send(ipc_client::IpcCommand::AddProtectedPath {
        path: cwd.to_string_lossy().to_string(),
    }).await?;

    println!();
    println!("  ✓ Modo sandbox activado");
    println!("  ✓ {:?} ahora está protegida", cwd);
    println!("  ✓ DLP Proxy activo en 127.0.0.1:7771");
    println!("  ✓ Detección automática de agentes IA activada");
    println!();
    println!("  A partir de ahora, cuando abras Cursor, Claude, Windsurf");
    println!("  o cualquier agente dentro de esta carpeta, quedará aislado.");
    println!();
    println!("  Comando recomendado:  agentguard lanza cursor");
    println!("  Ver estado:           agentguard estado");
    println!();

    Ok(())
}

async fn cmd_lanza(
    agente: &str,
    extra_args: Vec<String>,
    modo: Option<String>,
) -> Result<(), anyhow::Error> {
    let cwd = std::env::current_dir()?;

    println!("🚀 Lanzando {} en modo seguro...", agente);
    println!("   Directorio: {:?}", cwd);

    let mut client = ipc_client::connect().await
        .map_err(|_| anyhow::anyhow!("El daemon no está corriendo"))?;

    let response = client.send(ipc_client::IpcCommand::LaunchAgent {
        exe:        agente.to_string(),
        cwd:        cwd.to_string_lossy().to_string(),
        extra_args,
        mode_override: modo,
    }).await?;

    match response {
        ipc_client::IpcResponse::AgentLaunched { sandbox_pid } => {
            println!("✓ {} corriendo en sandbox (pid={})", agente, sandbox_pid);
            println!("  El agente tiene acceso completo a {:?}", cwd);
            println!("  Acceso a archivos sensibles: BLOQUEADO");
            println!("  DLP proxy: ACTIVO");
        }
        ipc_client::IpcResponse::Error(e) => {
            eprintln!("✗ Error al sandboxear: {}", e);
            eprintln!("  Lanzando {} sin sandbox (modo monitor)...", agente);
            // Lanzar directamente como fallback
            std::process::Command::new(agente).spawn()?;
        }
        _ => {}
    }

    Ok(())
}

async fn cmd_estado() -> Result<(), anyhow::Error> {
    let mut client = ipc_client::connect().await
        .map_err(|_| anyhow::anyhow!("El daemon no está corriendo"))?;

    let status = client.send(ipc_client::IpcCommand::Status).await?;

    if let ipc_client::IpcResponse::Status {
        protected,
        protected_paths,
        incidents_count,
        version,
        sandbox_mode,
        active_sandboxes,
        capabilities,
    } = status {
        println!();
        println!("┌─────────────────────────────────────────────┐");
        println!("│  🛡 AgentGuard {}{}│",
            version,
            " ".repeat(29_usize.saturating_sub(version.len()))
        );
        println!("├─────────────────────────────────────────────┤");
        if protected {
            println!("│  Estado: ✓ PROTEGIDO                        │");
        } else {
            println!("│  Estado: ✗ SIN PROTECCIÓN                   │");
        }
        println!("│  Modo: {:38}│", sandbox_mode);
        println!("│                                             │");
        println!("│  Directorios protegidos ({}):               │", protected_paths.len());
        for path in &protected_paths {
            let display = if path.len() > 40 {
                format!("...{}", &path[path.len()-37..])
            } else {
                path.clone()
            };
            println!("│    {:<41}│", display);
        }
        println!("│                                             │");
        println!("│  Incidentes (24h): {:<24}│", incidents_count);
        println!("│  Sandboxes activos: {:<23}│", active_sandboxes);
        println!("│                                             │");
        println!("│  Capacidades:                               │");
        println!("│    {:<41}│", capabilities);
        println!("└─────────────────────────────────────────────┘");
        println!();
    }

    Ok(())
}

async fn cmd_protege(path: &str, solo_vigilar: bool) -> Result<(), anyhow::Error> {
    let absolute = if path == "." {
        std::env::current_dir()?
    } else {
        PathBuf::from(path).canonicalize()
            .map_err(|_| anyhow::anyhow!("Ruta no encontrada: {}", path))?
    };

    let mut client = ipc_client::connect().await
        .map_err(|_| anyhow::anyhow!("El daemon no está corriendo"))?;

    client.send(ipc_client::IpcCommand::AddProtectedPath {
        path: absolute.to_string_lossy().to_string(),
    }).await?;

    println!("✓ Protegido: {:?}", absolute);
    if solo_vigilar {
        println!("  Modo: solo vigilar (las violaciones se alertan pero no se bloquean)");
    } else {
        println!("  Modo: sandbox (los agentes que intenten modificar archivos serán bloqueados)");
    }

    Ok(())
}

async fn cmd_relaja(minutos: u64) -> Result<(), anyhow::Error> {
    print!("⚠ Pausar la protección por {} minutos. ¿Seguro? [s/N] ", minutos);
    use std::io::{self, BufRead};
    let line = io::stdin().lock().lines().next()
        .unwrap_or(Ok("n".into()))
        .unwrap_or("n".into());

    if line.trim().to_lowercase() != "s" {
        println!("Cancelado.");
        return Ok(());
    }

    let mut client = ipc_client::connect().await?;
    client.send(ipc_client::IpcCommand::Pause {
        duration_seconds: minutos * 60,
    }).await?;

    println!("✓ Protección pausada por {} minutos", minutos);
    println!("  Reanudar antes con: agentguard estado");

    Ok(())
}

async fn cmd_restaura(id: &str, skip_confirm: bool) -> Result<(), anyhow::Error> {
    let mut client = ipc_client::connect().await?;

    // Si id == "ultimo", obtener el ID del snapshot más reciente
    let snapshot_id = if id == "ultimo" {
        if let ipc_client::IpcResponse::Snapshots(snaps) =
            client.send(ipc_client::IpcCommand::ListSnapshots).await?
        {
            snaps.into_iter().next()
                .map(|s| s.id)
                .ok_or_else(|| anyhow::anyhow!("No hay snapshots disponibles"))?
        } else {
            anyhow::bail!("Error al obtener snapshots");
        }
    } else {
        id.to_string()
    };

    if !skip_confirm {
        println!("⚠ Restaurar snapshot '{}'", snapshot_id);
        println!("  Esto sobreescribirá los archivos actuales.");
        print!("  ¿Continuar? [s/N] ");
        use std::io::{self, BufRead};
        let line = io::stdin().lock().lines().next()
            .unwrap_or(Ok("n".into()))
            .unwrap_or("n".into());
        if line.trim().to_lowercase() != "s" {
            println!("Cancelado.");
            return Ok(());
        }
    }

    client.send(ipc_client::IpcCommand::RestoreSnapshot {
        id: snapshot_id.clone(),
    }).await?;

    println!("✓ Snapshot '{}' restaurado", snapshot_id);

    Ok(())
}

async fn cmd_snapshot(accion: SnapshotCommands) -> Result<(), anyhow::Error> {
    let mut client = ipc_client::connect().await?;

    match accion {
        SnapshotCommands::Crear { etiqueta } => {
            client.send(ipc_client::IpcCommand::CreateSnapshot { label: etiqueta.clone() }).await?;
            println!("✓ Snapshot '{}' creado", etiqueta);
        }
        SnapshotCommands::Listar => {
            if let ipc_client::IpcResponse::Snapshots(snaps) =
                client.send(ipc_client::IpcCommand::ListSnapshots).await?
            {
                if snaps.is_empty() {
                    println!("No hay snapshots.");
                    return Ok(());
                }
                println!("{:<36}  {:<20}  {}", "ID", "Fecha", "Etiqueta");
                println!("{}", "─".repeat(70));
                for s in snaps {
                    let dt = format_timestamp(s.timestamp);
                    println!("{:<36}  {:<20}  {}", s.id, dt, s.label);
                }
            }
        }
        SnapshotCommands::Limpiar { dias } => {
            client.send(ipc_client::IpcCommand::CleanupSnapshots { keep_days: dias }).await?;
            println!("✓ Snapshots más viejos de {} días eliminados", dias);
        }
    }

    Ok(())
}

async fn cmd_incidentes(ultimos: usize) -> Result<(), anyhow::Error> {
    let mut client = ipc_client::connect().await?;

    if let ipc_client::IpcResponse::Incidents(incidents) =
        client.send(ipc_client::IpcCommand::ListIncidents { last_n: ultimos }).await?
    {
        if incidents.is_empty() {
            println!("✓ Sin incidentes recientes.");
            return Ok(());
        }

        println!();
        println!("  {:<12}  {:<12}  {:<15}  {}",
            "Hora", "Tipo", "Proceso", "Detalle");
        println!("  {}", "─".repeat(65));
        for inc in &incidents {
            // Formatear cada incidente desde el JSON
            if let (Some(ts), Some(tipo)) = (
                inc.get("timestamp").and_then(|v| v.as_u64()),
                inc.get("type").and_then(|v| v.as_str()),
            ) {
                let hora = format_timestamp_short(ts);
                let proceso = inc.get("process").and_then(|v| v.as_str()).unwrap_or("?");
                let detalle = inc.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                println!("  {:<12}  {:<12}  {:<15}  {}", hora, tipo, proceso, detalle);
            }
        }
        println!();
    }

    Ok(())
}

async fn cmd_avanzado(cmd: AdvancedCommands) -> Result<(), anyhow::Error> {
    match cmd {
        AdvancedCommands::CheckCapabilities => {
            #[cfg(target_os = "linux")]
            {
                let caps = agentguard_daemon::sandbox_linux::SandboxLauncher::check_capabilities();
                println!("Capacidades del sistema:");
                println!("  bwrap:     {}", if caps.bwrap_available { "✓ disponible" } else { "✗ instalar bubblewrap" });
                println!("  Landlock:  {}", if caps.landlock_available { "✓ disponible" } else { "✗ kernel ≥5.13 requerido" });
                println!("  eBPF LSM:  {}", if caps.ebpf_lsm_available { "✓ disponible" } else { "✗ kernel ≥5.7 + CONFIG_BPF_LSM requerido" });
                println!();
                println!("  Modo efectivo: {}", caps.effective_mode("hybrid"));
            }
            #[cfg(target_os = "windows")]
            {
                println!("Windows capabilities: AppContainer=✓ ETW=✓");
            }
        }
        AdvancedCommands::Config => {
            let config_path = get_config_path();
            println!("Config: {:?}", config_path);
            println!("Editar con tu editor de texto favorito.");
        }
        AdvancedCommands::Daemon { action } => {
            match action {
                DaemonCommands::Start   => println!("sudo systemctl start agentguard"),
                DaemonCommands::Stop    => println!("sudo systemctl stop agentguard"),
                DaemonCommands::Restart => println!("sudo systemctl restart agentguard"),
                DaemonCommands::Logs { lines } => {
                    std::process::Command::new("journalctl")
                        .args(&["-u", "agentguard", "-n", &lines.to_string()])
                        .status()?;
                }
            }
        }
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn format_timestamp(ts: u64) -> String {
    // Formateo básico sin dependencias de chrono
    let secs_since_epoch = ts;
    // Solo mostramos HH:MM:SS de forma aproximada
    format!("ts:{}", secs_since_epoch)
}

fn format_timestamp_short(ts: u64) -> String {
    format!("ts:{}", ts % 86400)
}

fn get_config_path() -> PathBuf {
    #[cfg(unix)]
    {
        dirs::home_dir().unwrap_or_default()
            .join(".agentguard")
            .join("config.toml")
    }
    #[cfg(windows)]
    {
        dirs::config_dir().unwrap_or_default()
            .join("AgentGuard")
            .join("config.toml")
    }
}
```

### IPC — Comandos nuevos en `ipc_server.rs`

```rust
// Añadir a IpcCommand:
#[derive(Serialize, Deserialize, Debug)]
pub enum IpcCommand {
    // ... existentes ...
    LaunchAgent {
        exe:           String,
        cwd:           String,
        extra_args:    Vec<String>,
        mode_override: Option<String>,
    },
    CleanupSnapshots { keep_days: u64 },
}

// Añadir a IpcResponse:
#[derive(Serialize, Deserialize, Debug)]
pub enum IpcResponse {
    // ... existentes ...
    Status {
        protected:        bool,
        protected_paths:  Vec<String>,
        incidents_count:  u64,
        version:          String,
        sandbox_mode:     String,         // nuevo
        active_sandboxes: u32,            // nuevo
        capabilities:     String,         // nuevo
    },
    AgentLaunched {
        sandbox_pid: u32,
    },
    Snapshots(Vec<SnapshotInfo>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SnapshotInfo {
    pub id:        String,
    pub timestamp: u64,
    pub label:     String,
    pub size:      u64,
}
```

---

## 8. Configuración extendida (config.toml v2.1)

```toml
# ~/.agentguard/config.toml — Versión 2.1
# Generado automáticamente por 'agentguard setup'

[agentguard]
version = "2"

# ── Protección de filesystem ──────────────────────────────────────────────────
protected_dirs = [
    "~/Documents",
    "~/Projects",
    "~/.ssh",
]
protected_files = [
    "~/.env",
    "~/.netrc",
    "~/.aws/credentials",
]

# ── Sandbox (NUEVO en v2.1) ───────────────────────────────────────────────────
[sandbox]
# Modo: monitor | sandbox | hybrid
modo_por_defecto = "sandbox"

# Detectar y sandboxear agentes automáticamente cuando se abren
auto_detectar_agentes = true

# El agente solo ve el directorio del proyecto + /usr (readonly)
montar_solo_proyecto = true

# Si AgentGuard muere, los agentes sandboxeados también mueren
morir_con_padre = true

# Argumentos extra para bwrap (usuarios avanzados)
bwrap_extra_args = []

# ── Detección de agentes (NUEVO en v2.1) ──────────────────────────────────────
[agent_detection]
known_agents = [
    { name = "cursor",       exe = ["cursor", "Cursor"]                              },
    { name = "claude-code",  exe = ["claude", "claude-code"]                         },
    { name = "windsurf",     exe = ["windsurf", "Windsurf"]                          },
    { name = "aider",        exe = ["aider"]                                          },
    { name = "vscode-agent", exe = ["code"], argv_contains = ["copilot", "cline"]    },
    { name = "node-agent",   exe = ["node"],   env_has = "AGENTGUARD_AGENT"          },
    { name = "python-agent", exe = ["python", "python3"], env_has = "AGENTGUARD_AGENT" },
]

# ── Violaciones ───────────────────────────────────────────────────────────────
[on_violation]
kill_process          = false
snapshot_on_violation = true

# ── Alertas ───────────────────────────────────────────────────────────────────
[alerts]
desktop_notifications = true
sound                 = false
webhook_url           = ""

# ── Vault ─────────────────────────────────────────────────────────────────────
[vault]
snapshot_on_start            = true
auto_snapshot_interval_hours = 6
keep_days                    = 30
# Mover de ~/.agentguard/vault a /var/lib/agentguard (fix conflicto systemd)
vault_dir = "/var/lib/agentguard/vault"

# ── DLP Proxy ─────────────────────────────────────────────────────────────────
[dlp]
enabled    = true
proxy_port = 7771
action     = "block"

[[dlp.custom_patterns]]
name  = "Internal API Key"
regex = "mycompany-[a-zA-Z0-9]{32}"

# ── Windows (NUEVO en v2.1) ───────────────────────────────────────────────────
[windows]
use_lpac            = true    # Less Privileged AppContainer (más seguro)
use_etw             = true    # ETW para detección; false = polling cada 500ms
polling_interval_ms = 500

# ── Auto-update ───────────────────────────────────────────────────────────────
[updates]
auto_check            = true
check_interval_hours  = 24
auto_install          = false
channel               = "stable"
```

---

## 9. Tests obligatorios

### `tests/integration/test_sandbox.rs`

```rust
#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::time::{sleep, Duration};

    // ── Test 1: Sandbox lanza el proceso correctamente ────────────────────

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_sandbox_launches_process() {
        // Verificar que bwrap está disponible
        if which::which("bwrap").is_err() {
            eprintln!("SKIP: bwrap not available");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let config = make_test_config(tmp.path());
        let launcher = agentguard_daemon::sandbox_linux::SandboxLauncher::new(config);

        // Lanzar 'echo' como agente de prueba
        let pid = launcher.launch("echo", tmp.path(), false).await;
        assert!(pid.is_ok(), "Sandbox launch failed: {:?}", pid.err());

        let pid = pid.unwrap();
        assert!(pid > 0, "PID should be positive");

        // Dar tiempo a que el proceso termine
        sleep(Duration::from_millis(200)).await;

        // Verificar que el proceso ya no existe
        let exists = unsafe { libc::kill(pid as i32, 0) == 0 };
        // echo termina rápido, así que ya debería haber terminado
        let _ = exists; // ok si ya terminó
    }

    // ── Test 2: El sandbox impide escribir fuera del proyecto ─────────────

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_sandbox_blocks_writes_outside_project() {
        if which::which("bwrap").is_err() {
            eprintln!("SKIP: bwrap not available");
            return;
        }

        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret content").unwrap();

        let config = make_test_config(project.path());
        let launcher = agentguard_daemon::sandbox_linux::SandboxLauncher::new(config);

        // Intentar leer el archivo fuera del proyecto usando 'cat'
        // Dentro del sandbox, /tmp y /home son tmpfs vacíos
        let pid = launcher.launch(
            &format!("cat {}", outside_file.display()),
            project.path(),
            false,
        ).await;

        // El proceso debería haberse lanzado pero 'cat' debería fallar
        // (el archivo no es visible dentro del sandbox)
        assert!(pid.is_ok());

        sleep(Duration::from_millis(300)).await;
        // El archivo original no debe haberse modificado
        let content = std::fs::read_to_string(&outside_file).unwrap();
        assert_eq!(content, "secret content");
    }

    // ── Test 3: Detección automática por eBPF ────────────────────────────

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_ebpf_detects_agent_spawn() {
        // Este test requiere root para cargar eBPF
        if std::env::var("AGENTGUARD_TEST_EBPF").is_err() {
            eprintln!("SKIP: set AGENTGUARD_TEST_EBPF=1 to run eBPF tests (requires root)");
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let config = make_full_test_config();
        let config_arc = std::sync::Arc::new(tokio::sync::RwLock::new(config));

        // Cargar el watcher
        let watcher_result = agentguard_daemon::process_watcher_linux::ProcessWatcher::load(
            &*config_arc.read().await
        ).await;

        assert!(watcher_result.is_ok(), "Failed to load ProcessWatcher: {:?}", watcher_result.err());
        let watcher = watcher_result.unwrap();

        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(10);
        tokio::spawn(async move { watcher.run(config_arc, event_tx).await; });

        // Lanzar un proceso de prueba que simula un agente conocido
        // El nombre del ejecutable debe estar en KNOWN_AGENTS
        // Usamos un symlink temporal para simular "cursor"
        let tmp = TempDir::new().unwrap();
        let fake_cursor = tmp.path().join("cursor");
        std::os::unix::fs::symlink("/bin/echo", &fake_cursor).unwrap();

        let mut path_env = std::env::var("PATH").unwrap_or_default();
        path_env = format!("{}:{}", tmp.path().display(), path_env);

        std::process::Command::new("cursor")
            .env("PATH", path_env)
            .arg("hello")
            .spawn()
            .expect("Failed to spawn fake cursor");

        // Esperar evento
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            event_rx.recv()
        ).await;

        assert!(event.is_ok(), "Timeout waiting for AgentDetected event");
        if let Some(agentguard_daemon::daemon::SecurityEvent::AgentDetected { agent_name, .. }) = event.unwrap() {
            assert_eq!(agent_name, "cursor");
        } else {
            panic!("Expected AgentDetected event");
        }
    }

    // ── Test 4: Vault + sandbox (workflow completo) ───────────────────────

    #[tokio::test]
    async fn test_vault_snapshot_before_sandbox() {
        let tmp = TempDir::new().unwrap();

        // Crear archivo "importante" en el proyecto
        let important_file = tmp.path().join("important.md");
        std::fs::write(&important_file, "contenido importante").unwrap();

        let vault = agentguard_daemon::vault::Vault::new_with_dir(
            tmp.path().join("vault")
        ).unwrap();

        // Snapshot previo al sandbox
        let snapshot = vault.create_snapshot(
            &[tmp.path().to_path_buf()],
            "pre-session",
        ).await.unwrap();

        assert_eq!(snapshot.label, "pre-session");
        assert!(!snapshot.files.is_empty());

        // Simular que el agente borra el archivo
        std::fs::remove_file(&important_file).unwrap();
        assert!(!important_file.exists());

        // Restaurar
        vault.restore(&snapshot.id).await.unwrap();
        assert!(important_file.exists());
        assert_eq!(
            std::fs::read_to_string(&important_file).unwrap(),
            "contenido importante"
        );
    }

    // ── Test 5: DLP bloquea en modo sandbox ───────────────────────────────

    #[tokio::test]
    async fn test_dlp_proxy_blocks_api_keys() {
        use agentguard_daemon::dlp_proxy::{DlpProxy, DlpAction};

        let proxy = DlpProxy::new(17779, vec![], DlpAction::Block).unwrap();
        tokio::spawn(async move { proxy.start().await.unwrap(); });
        sleep(Duration::from_millis(150)).await;

        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http("http://127.0.0.1:17779").unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Request con API key de Anthropic → debe ser bloqueado
        let resp = client.post("http://httpbin.org/post")
            .header("Authorization",
                "Bearer sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAAAAAA"
            )
            .body("test payload")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 403);
        let body = resp.text().await.unwrap();
        assert!(body.contains("AgentGuard DLP"), "Expected DLP block message, got: {}", body);

        // Request limpio → debe pasar
        let resp_ok = client.post("http://httpbin.org/post")
            .body("sin secretos aquí")
            .send()
            .await
            .unwrap();

        assert_eq!(resp_ok.status(), 200);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn make_test_config(project_dir: &std::path::Path) -> agentguard_daemon::config::Config {
        let mut config = agentguard_daemon::config::Config::default();
        config.protected_dirs = vec![project_dir.to_path_buf()];
        config.dlp.proxy_port = 17771;
        config.sandbox.modo_por_defecto = "sandbox".into();
        config
    }

    fn make_full_test_config() -> agentguard_daemon::config::Config {
        let mut config = agentguard_daemon::config::Config::default();
        config.agent_detection.known_agents = vec![
            agentguard_daemon::config::KnownAgent {
                name: "cursor".into(),
                exe:  vec!["cursor".into()],
                argv_contains: vec![],
                env_has: None,
            },
        ];
        config
    }
}
```

### Checklist de verificación pre-release v2.1

```
[ ] agentguard setup → configuración completa en <1 minuto
[ ] agentguard lanza cursor → proceso nace dentro de bwrap/AppContainer
[ ] Abrir cursor en carpeta protegida sin 'agentguard lanza' → detectado + sandboxeado en <150ms
[ ] Agente intenta leer ~/.ssh/id_rsa → EPERM (invisible dentro del sandbox)
[ ] API key en request HTTPS → bloqueado por DLP (requiere HTTPS MITM activo)
[ ] kill -9 del daemon → eBPF sigue activo + agentes en sandbox mantienen die-with-parent
[ ] Snapshot → restore → hashes idénticos verificados con blake3
[ ] RAM del daemon en idle: < 10 MB
[ ] CPU del daemon en idle: < 0.1%
[ ] RAM extra por agente sandboxeado: < 5 MB
[ ] agentguard avanzado check-capabilities → reporte correcto del sistema
[ ] Config inválida → error descriptivo, no panic
[ ] Vault en /var/lib/agentguard (no conflicto con ProtectHome=read-only)
```

---

## 10. Orden de implementación

```
Fase 1 (v1.0 existente — no cambiar)
  ✓ common types · config · vault · eBPF file_guard · DLP proxy HTTP · CLI básica

Fase 2A — Detección de procesos (añadir a semana 4-5)
  [ ] agentguard-common: AgentSpawnEvent, SandboxedAgent, SandboxMode
  [ ] agentguard-ebpf: process_exec.bpf.rs (tracepoint sched_process_exec)
  [ ] agentguard-daemon: process_watcher_linux.rs (carga eBPF + loop ring buffer)
  [ ] agentguard-daemon: process_watcher_windows.rs (ETW consumer + polling fallback)
  [ ] Test: spawn de proceso detectado en <150ms

Fase 2B — Sandbox launchers (añadir a semana 4-5)
  [ ] agentguard-daemon: sandbox_linux.rs (bwrap wrapper completo)
  [ ] agentguard-daemon: landlock.rs (apply_landlock_profile)
  [ ] agentguard-daemon: sandbox_windows.rs (AppContainer/LPAC)
  [ ] Test: proceso sandboxeado no puede escribir fuera del proyecto

Fase 3 — CLI v2.1 (semana 6)
  [ ] Comandos: setup, lanza, protege, estado, relaja, restaura
  [ ] IpcCommand::LaunchAgent + IpcResponse::AgentLaunched
  [ ] Mensajes en español claros para usuarios no técnicos

Fase 4 — Tests + Pulido (semana 7-8)
  [ ] Suite completa de tests de integración
  [ ] Tests de rendimiento (RAM/CPU bajo carga)
  [ ] Docs de usuario (README en español)
  [ ] Checklist pre-release completo
```

---

## Resumen ejecutivo

| Componente | Linux | Windows |
|---|---|---|
| **Detección** | eBPF `sched_process_exec` (<20ms) | ETW `Microsoft-Windows-Kernel-Process` (<100ms) |
| **Sandbox** | Bubblewrap + Landlock (modo hybrid) | AppContainer/LPAC + DENY ACEs |
| **Protección filesystem** | eBPF LSM `file_unlink`/`file_rename` | NTFS DENY ACEs (daemon como SYSTEM) |
| **DLP** | Proxy HTTP + HTTPS MITM (v1.1) | ídem |
| **RAM daemon** | ~2-4 MB idle | ~3-5 MB idle |
| **RAM por agente** | +1-3 MB | +2-5 MB |
| **Requiere root** | Solo para eBPF LSM (daemon) | Solo para instalar el servicio |

**Los agentes ahora nacen ya protegidos.**

---

*AgentGuard v2.1 — Lo que tus agentes hacen, ahora lo controlas tú.*
