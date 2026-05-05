# AgentGuard — Especificación Técnica Completa

> **Documento de referencia para implementación automatizada**
> Versión 1.0 — Prioridad: Linux > Windows

---

## Índice

1. [Visión del producto](#1-visión-del-producto)
2. [Requisitos no negociables](#2-requisitos-no-negociables)
3. [Arquitectura general](#3-arquitectura-general)
4. [Estructura del repositorio](#4-estructura-del-repositorio)
5. [Stack técnico completo](#5-stack-técnico-completo)
6. [Módulo 1 — Kernel Guard (Linux eBPF)](#6-módulo-1--kernel-guard-linux-ebpf)
7. [Módulo 2 — Kernel Guard (Windows)](#7-módulo-2--kernel-guard-windows)
8. [Módulo 3 — (Eliminado: macOS fuera de scope)](#8-módulo-3--kernel-guard-macos)
9. [Módulo 4 — Vault (snapshots)](#9-módulo-4--vault-snapshots)
10. [Módulo 5 — DLP Proxy (API key leaks)](#10-módulo-5--dlp-proxy-api-key-leaks)
11. [Módulo 6 — Daemon principal](#11-módulo-6--daemon-principal)
12. [Módulo 7 — CLI](#12-módulo-7--cli)
13. [Módulo 8 — UI Tauri](#13-módulo-8--ui-tauri)
14. [Módulo 9 — Auto-updater](#14-módulo-9--auto-updater)
15. [Configuración (config.toml)](#15-configuración-configtoml)
16. [Instaladores y packaging](#16-instaladores-y-packaging)
17. [Modelo de licencias](#17-modelo-de-licencias)
18. [Pipeline CI/CD](#18-pipeline-cicd)
19. [Orden de implementación obligatorio](#19-orden-de-implementación-obligatorio)
20. [Tests mínimos requeridos](#20-tests-mínimos-requeridos)

---

## 1. Visión del producto

**AgentGuard** es un daemon de seguridad escrito en Rust que protege el sistema del usuario contra acciones destructivas o filtraciones de datos causadas por agentes de IA (Claude Code, Cursor, Copilot, etc.).

> **Ubicación de datos del daemon:**
> - Vault y logs cuando corre como servicio system-wide: `/var/lib/agentguard/`
> - Config de usuario: `~/.agentguard/config.toml`
> - CA root para HTTPS MITM: `~/.agentguard/ca/` (modo usuario) o
>   `/var/lib/agentguard/ca/` (modo servicio)

### Problema que resuelve

- Agentes de IA que borran archivos críticos durante sesiones de trabajo
- Agentes de IA que filtran API keys, tokens y secretos en requests HTTP salientes
- El usuario no quiere usar VMs ni entornos de sandbox complejos

### Propuesta de valor

- Instala y olvídate — corre en segundo plano
- Protección real a nivel de kernel (imposible de saltar desde userspace)
- <10 MB RAM, <0.1% CPU en idle
- Open source (módulos kernel bajo GPL, daemon bajo BSL-1.1)
- Precio: €5/mes por máquina

---

## 2. Requisitos no negociables

### Rendimiento

- RAM máxima en idle: **10 MB**
- CPU máxima en idle: **0.1%**
- CPU máxima en evento activo: **2%**
- Tiempo de arranque del daemon: **<500ms**
- Latencia de detección de violación: **<50ms**

### Seguridad

- La protección de filesystem **DEBE** operar a nivel de kernel
- Un proceso corriendo como el mismo usuario **NO DEBE** poder desactivar la protección
- El daemon userspace puede ser matado sin que eso anule la protección de kernel
- En Linux, usar **eBPF LSM hooks** (kernel ≥5.7, que cubre Ubuntu 22.04+, Debian 12+, Fedora 38+)
- En Windows, usar **Job Objects + SYSTEM service + NTFS DENY ACEs**

### Compatibilidad

| OS | Versión mínima | Mecanismo kernel |
|---|---|---|
| Linux | Ubuntu 22.04 / Debian 12 / Fedora 38 | eBPF LSM (aya) |
| Windows | Windows 10 21H2 (build 19044) | Job Objects + SYSTEM Service |

### Código

- **Lenguaje principal:** Rust (edición 2021)
- **Sin unsafe salvo donde sea estrictamente necesario** (FFI con kernel, documentar cada uso)
- `cargo clippy` sin warnings en CI
- `cargo fmt` aplicado siempre
- Todos los errores manejados con `thiserror` — **cero `.unwrap()` en producción**

---

## 3. Arquitectura general

```
┌─────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                         │
│                                                         │
│  Linux: eBPF LSM programs (cargados via aya)            │
│    └─ file_guard.bpf.rs  → intercepta unlink/rename     │
│    └─ net_guard.bpf.rs   → intercepta sendmsg           │
│                                                         │
│  Windows: SYSTEM Service                                │
│    └─ Administra NTFS ACLs + Job Objects               │
│                                                         │
│  System Extension                                │
│    └─                        │
└────────────────────────┬────────────────────────────────┘
                         │ ring buffer / perf events
┌────────────────────────▼────────────────────────────────┐
│                   USER SPACE                            │
│                                                         │
│  agentguard-daemon (Rust, tokio async)                  │
│    ├─ kernel_loader    → carga/descarga programas eBPF  │
│    ├─ vault            → snapshots automáticos          │
│    ├─ dlp_proxy        → proxy HTTP/S para DLP          │
│    ├─ rules_engine     → evalúa config.toml             │
│    ├─ alerter          → notificaciones nativas          │
│    └─ ipc_server       → socket Unix/Named Pipe → UI    │
│                                                         │
│  agentguard-cli        → wrapper del IPC                │
│  agentguard-ui (Tauri) → UI gráfica opcional            │
└─────────────────────────────────────────────────────────┘
```

### Flujo de instalación (terminal-first)

```
Usuario ejecuta:  curl -fsSL https://get.agentguard.io | bash
    │
    ▼
Script detecta SO + arquitectura
    │
    ├── Linux   → descarga agentguard-cli + agentguard-linux + eBPF bytecode
    ├──  agentguard-cli + agentguard-macos
    └── Windows → descarga agentguard-cli + agentguard-windows
    │
    ▼
Instala + configura servicio (systemd/Windows Service)
    │
    ▼
Listo.  agentguard status   (CLI)
        agentguard protect ~/Documents
```

### Flujo de una violación (Linux)

```
Agente AI llama unlink("/home/user/Documents/importante.md")
    │
    ▼
eBPF LSM hook file_unlink() intercepta la syscall en kernel
    │
    ▼
¿Está la ruta en zonas protegidas? (BPF map consultado en kernel)
    │
    ├─ NO → permite, retorna 0
    │
    └─ SÍ → retorna -EPERM (denegado inmediatamente)
              + envía evento a ring buffer
                    │
                    ▼
              Daemon lee evento del ring buffer
                    │
                    ▼
              Alerta desktop + log + opcional kill del proceso
```

---

## 4. Estructura del repositorio

> **Arquitectura v2**: crates separados por sistema operativo. El installer detecta el SO y solo descarga el binario necesario (~5-8 MB en vez de un monolito de 40 MB).

```
agentguard/
│
├── Cargo.toml                    # workspace (8 crates + eBPF excluido)
├── Cargo.lock
├── LICENSE-GPL                   # GPL v2 (módulos kernel eBPF)
├── LICENSE-BSL                   # BSL 1.1 (daemon, CLI, UI)
├── README.md
├── PlanDeImplementacion.md       # Plan detallado de fases
├── CHANGELOG.md
├── .github/
│   └── workflows/
│       └── ci.yml                # build matrix: Linux + Windows
│
├── crates/
│   │
│   ├── agentguard-common/        # Tipos compartidos (no_std + std), IPC protocol
│   │   └── src/lib.rs
│   │
│   ├── agentguard-core/          # Lógica compartida del daemon (NUEVO v2)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── config.rs         # Deserialización config.toml
│   │       ├── vault.rs          # Snapshots BLAKE3
│   │       ├── dlp/              # Proxy HTTP/HTTPS + patterns DLP
│   │       ├── ca.rs             # CA root local + leaf cert issuer
│   │       ├── events.rs         # SecurityEvent enum
│   │       ├── guard.rs          # Trait KernelGuard (contrato, sin impls)
│   │       ├── ipc_server.rs     # Socket Unix JSON-line IPC
│   │       └── updater.rs        # Auto-update (Fase 7)
│   │
│   ├── agentguard-linux/         # BINARIO: daemon Linux (eBPF LSM + notify fallback)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # Entry point Linux
│   │       └── guard/
│   │           ├── ebpf.rs       # EbpfGuard (aya)
│   │           └── userspace.rs  # UserspaceGuard (notify fallback)
│   │
│   ├── agentguard-windows/       # BINARIO: daemon Windows (Fase 4)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       └── guard.rs          # WindowsGuard (NTFS DENY ACEs + Job Objects)
│   │
│   ├──         # BINARIO: daemon macOS (Fase 5)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       └── guard.rs          # 
│   │
│   ├── agentguard-ebpf/          # Programas eBPF (kernel, nightly)
│   │   ├── Cargo.toml            # target = bpfel-unknown-none
│   │   └── src/
│   │       ├── file_guard.rs     # LSM hooks: file_unlink, file_rename, file_open
│   │       └── net_guard.rs      # LSM hook: socket_connect (stub)
│   │
│   ├── agentguard-cli/           # BINARIO: CLI cross-platform (único para todos)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs           # clap derive → IPC → output formateado
│   │
│   ├── agentguard-installer/     # Scripts de instalación por SO (NUEVO v2)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs           # Bootstrap binary (detecta SO, descarga, instala)
│   │
│   └── agentguard-ui/            # Tauri v2 app (Fase 6 — opcional, terminal-first)
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs
│
├── packaging/
│   ├── linux/
│   │   └── agentguard.service    # systemd unit
│   ├── windows/
│   │   └── installer.iss         # Inno Setup script
│   └── macos/
│       └── systemd.plist
│
├── scripts/
│   ├── build-ebpf.sh             # Compila bytecode eBPF
│   └── check-no-panic.sh         # CI guard: prohíbe .unwrap()/panic!()
│
└── tests/
    ├── fixtures/
    │   └── sandbox/              # Datos sintéticos para tests
    └── integration/              # Tests E2E por módulo
```
```

---

## 5. Stack técnico completo

### Crates principales (daemon)

```toml
# crates/agentguard-daemon/Cargo.toml
[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# eBPF userspace (Linux only)
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

# Filesystem watch (fallback userspace + macOS)
notify = { version = "6", features = ["macos_fsevent"] }

# HTTP proxy para DLP (hyper 1.x)
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"
bytes = "1"
tokio-rustls = "0.26"
rustls = "0.23"
rustls-pemfile = "2"
# Generación de CA root local para HTTPS MITM
rcgen = "0.13"

# Serialización
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling
thiserror = "1"
anyhow = "1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# IPC
tokio-unix-socket = "0.1"         # Linux
interprocess = "2"                 # Cross-platform (incluye Windows Named Pipes)

# Notificaciones nativas
notify-rust = "4"                  # Linux
# Windows: usar win32 API directamente

# Hashing para checksums del vault e integridad de updates
# IMPORTANTE: el vault usa BLAKE3 (rápido, deduplicación).
# Los binarios de release usan SHA-256 (`sha256sum` en install.sh y
# en el manifiesto del release de GitHub) por compatibilidad con
# herramientas estándar. NO mezclar los dos.
blake3 = "1"
sha2 = "0.10"

# Regex para DLP patterns
regex = "1"

# Config paths
dirs = "5"

# Auto-update HTTP client
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# Semver para comparar versiones
semver = "1"

# Windows-specific
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_JobObjects",
    "Win32_System_Threading",
    "Win32_Storage_FileSystem",
    "Win32_System_Services",
] }

[features]
default = []
ebpf = ["aya", "aya-log"]
```

### Crates eBPF

```toml
# crates/agentguard-ebpf/Cargo.toml
[dependencies]
aya-bpf = "0.1"
aya-log-ebpf = "0.1"
agentguard-common = { path = "../agentguard-common" }
```

### Tipos comunes

```toml
# crates/agentguard-common/Cargo.toml
[dependencies]
# Solo no_std compatible — este crate compila también para BPF
```

---

## 6. Módulo 1 — Kernel Guard (Linux eBPF)

### Objetivo

Interceptar en el kernel las syscalls de eliminación y modificación de archivos en zonas protegidas. **Imposible de saltar desde userspace.**

### Requisitos del sistema

- Kernel ≥ 5.7 con `CONFIG_BPF_LSM=y`
- Verificar en runtime con `uname -r` y leyendo `/boot/config-$(uname -r)`
- Si no disponible → fallback a `notify` + advertencia al usuario

### agentguard-common/src/lib.rs

```rust
// Tipos compartidos entre eBPF y userspace
// DEBE ser no_std compatible

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub event_type: EventType,
    pub path: [u8; 256],
    pub comm: [u8; 16],  // nombre del proceso
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum EventType {
    FileDelete = 1,
    FileWrite = 2,
    FileRename = 3,
    NetworkSend = 4,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub data_len: u32,
    pub data: [u8; 512],  // primeros 512 bytes del payload
    pub comm: [u8; 16],
}
```

### agentguard-ebpf/src/file_guard.rs

```rust
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
    BpfContext,
};
use aya_log_ebpf::info;
use agentguard_common::{FileEvent, EventType};

// Mapa de PREFIJOS protegidos (no de archivos individuales).
// Cada entrada es un prefijo de ruta canónico (ej: "/home/user/Documents").
// Esto evita el problema de tener que añadir cada archivo del directorio al mapa
// y elimina la posibilidad de colisión por hash truncado.
//
// El verifier de eBPF no permite bucles arbitrarios sobre strings, así que
// el mapa contiene un array fijo de prefijos y comparamos byte a byte hasta
// MAX_PREFIX_LEN. La consulta es O(N) sobre N prefijos (típicamente <32),
// lo cual es aceptable para LSM hooks de filesystem.

pub const MAX_PREFIX_LEN: usize = 256;
pub const MAX_PREFIXES: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathPrefix {
    pub len: u32,
    pub bytes: [u8; MAX_PREFIX_LEN],
}

// Array map indexado por slot — poblado desde userspace.
#[map]
static PROTECTED_PREFIXES: Array<PathPrefix> = Array::with_max_entries(MAX_PREFIXES, 0);

// Contador de cuántos slots están en uso (escrito desde userspace).
#[map]
static PREFIX_COUNT: Array<u32> = Array::with_max_entries(1, 0);

// Ring buffer para enviar eventos a userspace
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB

#[lsm(hook = "file_unlink")]
pub fn file_unlink(ctx: LsmContext) -> i32 {
    match try_file_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // en caso de error interno, permitir (fail-open para no romper el sistema)
    }
}

fn try_file_unlink(ctx: &LsmContext) -> Result<i32, ()> {
    // Resolver la ruta absoluta del dentry vía bpf_d_path.
    // bpf_d_path SÍ está disponible en hooks LSM desde kernel 5.10+.
    // Para 5.7-5.9 (raros hoy en día) hacemos fallback a get_name_kern.
    let mut path_buf = [0u8; MAX_PREFIX_LEN];
    let path_len = resolve_path(ctx, &mut path_buf)?;
    
    if is_protected_prefix(&path_buf, path_len) {
        send_file_event(ctx, EventType::FileDelete, &path_buf, path_len)?;
        // DENEGAR — imposible de saltar desde userspace
        return Ok(-1); // -EPERM
    }
    
    Ok(0) // permitir
}

#[inline(always)]
fn is_protected_prefix(path: &[u8; MAX_PREFIX_LEN], path_len: u32) -> bool {
    let count = unsafe { PREFIX_COUNT.get(0).copied().unwrap_or(0) };
    let count = count.min(MAX_PREFIXES);
    
    // El verifier exige un bound estático en el bucle.
    for i in 0..MAX_PREFIXES {
        if i >= count { break; }
        let Some(prefix) = (unsafe { PROTECTED_PREFIXES.get(i) }) else { continue };
        if prefix.len == 0 || prefix.len > path_len { continue; }
        if path_len > MAX_PREFIX_LEN as u32 { continue; }
        
        let plen = (prefix.len as usize).min(MAX_PREFIX_LEN);
        let mut matched = true;
        for j in 0..MAX_PREFIX_LEN {
            if j >= plen { break; }
            if path[j] != prefix.bytes[j] { matched = false; break; }
        }
        if matched { return true; }
    }
    false
}

#[lsm(hook = "file_rename")]
pub fn file_rename(ctx: LsmContext) -> i32 {
    // Misma lógica — renombrar fuera de zona protegida equivale a borrar
    match try_file_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// También proteger escritura en archivos críticos (.env, etc.)
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // Solo bloquear si el flag es O_WRONLY o O_RDWR
    // y la ruta está en PROTECTED_WRITE_PATHS (mapa separado)
    0 // implementar según la misma lógica
}

fn resolve_path(ctx: &LsmContext, out: &mut [u8; MAX_PREFIX_LEN]) -> Result<u32, ()> {
    // El primer argumento de file_unlink LSM hook es `struct path *dir`,
    // el segundo es `struct dentry *dentry`. Construimos un struct path
    // temporal apuntando al dentry y lo pasamos a bpf_d_path.
    //
    // Pseudocódigo (la implementación real usa aya_bpf::helpers::bpf_d_path
    // y bpf_probe_read_kernel para leer el dentry desde el contexto):
    //
    //   let dentry: *const dentry = ctx.arg(1);
    //   let dir: *const path = ctx.arg(0);
    //   let mnt = bpf_probe_read_kernel(&(*dir).mnt)?;
    //   let synthetic = path { mnt, dentry };
    //   let len = bpf_d_path(&synthetic, out.as_mut_ptr(), out.len() as u32)?;
    //
    // bpf_d_path está allowlistado para los hooks LSM file_* desde 5.10.
    // Si retorna error, fail-open (permitir) para no romper el sistema.
    let len = unsafe { aya_bpf::helpers::gen::bpf_d_path(
        ctx.arg::<*const _>(0) as *mut _,
        out.as_mut_ptr() as *mut _,
        out.len() as u32,
    ) };
    if len < 0 { return Err(()); }
    Ok(len as u32)
}

fn send_file_event(
    ctx: &LsmContext,
    event_type: EventType,
    path: &[u8; MAX_PREFIX_LEN],
    path_len: u32,
) -> Result<(), ()> {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).pid = ctx.pid();
            (*event).uid = ctx.uid();
            (*event).event_type = event_type;
            // copiar comm y path con bpf_get_current_comm y bpf_d_path
        }
        entry.submit(0);
    }
    Ok(())
}

// Entry point requerido por eBPF
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### agentguard-ebpf/src/net_guard.rs

```rust
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};
use agentguard_common::{NetworkEvent, EventType};

#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0); // 2MB

// NOTA: La detección de API keys en contenido de paquetes es compleja en eBPF puro
// La arquitectura correcta es:
// 1. Este hook detecta procesos de agentes AI conocidos haciendo conexiones
// 2. El DLP real se hace en el proxy userspace (Módulo 5)
// 3. Este hook puede bloquear conexiones de procesos no autorizados a hosts externos
//    si se configura una lista blanca de hosts permitidos

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    // Si el proceso está en la lista de agentes monitorizados
    // Y el destino no está en la lista blanca
    // → denegar y notificar al proxy DLP
    0 // por defecto permitir — la detección de contenido la hace el proxy
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### kernel_loader.rs (en daemon, solo Linux)

```rust
#[cfg(target_os = "linux")]
pub mod ebpf_loader {
    use aya::{Bpf, BpfLoader, include_bytes_aligned};
    use aya::maps::{HashMap, RingBuf};
    use aya::programs::{Lsm, ProgramError};
    use std::path::PathBuf;
    use tokio::task;
    
    // Los bytecodes eBPF se embedden en el binario del daemon en compile time
    static FILE_GUARD_BPF: &[u8] = 
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/file_guard.bpf.o"));
    static NET_GUARD_BPF: &[u8] = 
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net_guard.bpf.o"));

    pub struct EbpfGuard {
        bpf_file: Bpf,
        bpf_net: Bpf,
    }

    impl EbpfGuard {
        pub async fn load(protected_paths: &[PathBuf]) -> Result<Self, anyhow::Error> {
            // Verificar que el kernel soporta eBPF LSM
            check_ebpf_lsm_support()?;
            
            let mut bpf_file = BpfLoader::new()
                .btf(aya::Btf::from_sys_fs().ok().as_ref())
                .load(FILE_GUARD_BPF)?;
            
            // Cargar y attachar el programa LSM
            let program: &mut Lsm = bpf_file
                .program_mut("file_unlink")
                .ok_or_else(|| anyhow::anyhow!("file_unlink program not found in BPF object"))?
                .try_into()?;
            let btf = aya::Btf::from_sys_fs()?;
            program.load("file_unlink", &btf)?;
            program.attach()?;
            
            // Poblar el array de prefijos protegidos.
            // Cada prefijo se canonicaliza (resolve symlinks, sin trailing slash)
            // antes de escribirlo al mapa.
            let mut prefixes_map: aya::maps::Array<_, PathPrefix> =
                aya::maps::Array::try_from(bpf_file.map_mut("PROTECTED_PREFIXES")?)?;
            let mut count_map: aya::maps::Array<_, u32> =
                aya::maps::Array::try_from(bpf_file.map_mut("PREFIX_COUNT")?)?;

            let mut written: u32 = 0;
            for path in protected_paths {
                if written >= MAX_PREFIXES { break; }
                let canonical = std::fs::canonicalize(path)?;
                let bytes = canonical.as_os_str().as_bytes();
                if bytes.len() > MAX_PREFIX_LEN {
                    tracing::warn!("path too long, skipping: {:?}", canonical);
                    continue;
                }
                let mut prefix = PathPrefix { len: bytes.len() as u32, bytes: [0; MAX_PREFIX_LEN] };
                prefix.bytes[..bytes.len()].copy_from_slice(bytes);
                prefixes_map.set(written, prefix, 0)?;
                written += 1;
            }
            count_map.set(0, written, 0)?;

            let bpf_net = BpfLoader::new()
                .load(NET_GUARD_BPF)?;
            
            Ok(Self { bpf_file, bpf_net })
        }
        
        pub async fn listen_events(
            &mut self,
            tx: tokio::sync::mpsc::Sender<SecurityEvent>,
        ) -> Result<(), anyhow::Error> {
            // Leer del ring buffer de forma asíncrona y enviar eventos al daemon principal
            let map = self.bpf_file.map_mut("FILE_EVENTS")
                .ok_or_else(|| anyhow::anyhow!("FILE_EVENTS map not found"))?;
            let mut ring_buf = RingBuf::try_from(map)?;
            
            loop {
                while let Some(item) = ring_buf.next() {
                    match parse_file_event(&item) {
                        Ok(ev) => { let _ = tx.send(ev).await; }
                        Err(e) => tracing::warn!(error = %e, "failed to parse BPF event"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        
        pub async fn add_protected_path(&mut self, path: &PathBuf) -> Result<(), anyhow::Error> {
            let mut prefixes_map: aya::maps::Array<_, PathPrefix> =
                aya::maps::Array::try_from(self.bpf_file.map_mut("PROTECTED_PREFIXES")?)?;
            let mut count_map: aya::maps::Array<_, u32> =
                aya::maps::Array::try_from(self.bpf_file.map_mut("PREFIX_COUNT")?)?;

            let count = count_map.get(&0, 0)?;
            if count >= MAX_PREFIXES {
                anyhow::bail!("max protected prefixes reached ({MAX_PREFIXES})");
            }

            let canonical = std::fs::canonicalize(path)?;
            let bytes = canonical.as_os_str().as_bytes();
            if bytes.len() > MAX_PREFIX_LEN {
                anyhow::bail!("path exceeds MAX_PREFIX_LEN ({MAX_PREFIX_LEN})");
            }
            let mut prefix = PathPrefix { len: bytes.len() as u32, bytes: [0; MAX_PREFIX_LEN] };
            prefix.bytes[..bytes.len()].copy_from_slice(bytes);
            prefixes_map.set(count, prefix, 0)?;
            count_map.set(0, count + 1, 0)?;
            Ok(())
        }
    }

    fn check_ebpf_lsm_support() -> Result<(), anyhow::Error> {
        // 1. Leer /sys/kernel/security/lsm — debe contener "bpf"
        let lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map_err(|e| anyhow::anyhow!("cannot read /sys/kernel/security/lsm: {e}"))?;
        if !lsm.split(',').any(|m| m.trim() == "bpf") {
            anyhow::bail!(
                "kernel does not have BPF LSM enabled (lsm=\"{}\"). \
                 Add `lsm=...,bpf` to kernel cmdline or boot a kernel with CONFIG_BPF_LSM=y.",
                lsm.trim()
            );
        }
        // 2. Comprobar que estamos como root o con CAP_BPF + CAP_SYS_ADMIN.
        //    (En systemd lo garantiza AmbientCapabilities.)
        Ok(())
    }
}
```

---

## 7. Módulo 2 — Kernel Guard (Windows)

### Estrategia

Sin driver firmado (que requiere EV cert), la protección se implementa con dos mecanismos combinados que dan ~95% de seguridad:

1. **SYSTEM Service con DENY ACEs en NTFS** — el daemon corre como SYSTEM y pone ACEs de denegación explícita en las carpetas protegidas para el usuario normal
2. **Job Objects** — cuando se detecta un proceso de agente AI, se mete en un Job Object con restricciones

### windows_guard.rs

```rust
#[cfg(target_os = "windows")]
pub mod windows_guard {
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::*;
    use windows::Win32::Security::Authorization::*;
    use windows::Win32::System::JobObjects::*;
    use windows::Win32::Storage::FileSystem::*;
    use std::path::PathBuf;

    pub struct WindowsGuard {
        protected_paths: Vec<PathBuf>,
        job_handle: Option<HANDLE>,
    }

    impl WindowsGuard {
        pub fn new() -> Self {
            Self {
                protected_paths: Vec::new(),
                job_handle: None,
            }
        }

        /// Aplica DENY ACE para el usuario actual en la ruta protegida.
        /// El daemon debe correr como SYSTEM o Administrador para hacer esto.
        /// El usuario no puede modificar ACLs que SYSTEM ha puesto.
        pub fn protect_path(&self, path: &PathBuf) -> Result<(), anyhow::Error> {
            // 1. Obtener el SID del usuario actual
            // 2. Construir una DENY ACE: FILE_DELETE | FILE_DELETE_CHILD
            // 3. Aplicar con SetNamedSecurityInfoW
            // 4. Propagar a subdirectorios recursivamente
            
            // Código con windows-rs:
            unsafe {
                // SetNamedSecurityInfoW(
                //     path_wide.as_ptr(),
                //     SE_FILE_OBJECT,
                //     DACL_SECURITY_INFORMATION,
                //     None, None,
                //     Some(dacl_with_deny_ace),
                //     None,
                // )?;
            }
            
            tracing::info!("Protected path (Windows DACL): {:?}", path);
            Ok(())
        }

        /// Desprotege temporalmente (requiere autenticación del usuario en UI)
        pub fn unprotect_path(&self, path: &PathBuf) -> Result<(), anyhow::Error> {
            // Remover la DENY ACE — solo el daemon (SYSTEM) puede hacer esto
            Ok(())
        }

        /// Cuando se detecta un proceso de agente AI (por nombre o PID),
        /// asignarlo a un Job Object con restricciones.
        pub fn restrict_process(&mut self, pid: u32) -> Result<(), anyhow::Error> {
            unsafe {
                let job = CreateJobObjectW(None, None)?;
                
                let mut basic_limits = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
                // Matar el job si el proceso hace demasiadas operaciones de filesystem
                // No permite crear procesos hijo que escapen el job
                basic_limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 
                    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
                
                SetInformationJobObject(
                    job,
                    JobObjectBasicLimitInformation,
                    &basic_limits as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
                )?;
                
                let process_handle = OpenProcess(
                    PROCESS_ALL_ACCESS,
                    false,
                    pid,
                )?;
                
                AssignProcessToJobObject(job, process_handle)?;
                self.job_handle = Some(job);
            }
            Ok(())
        }

        /// Detectar procesos de agentes AI conocidos por nombre
        pub fn detect_agent_processes() -> Vec<u32> {
            // Iterar snapshots con CreateToolhelp32Snapshot
            // Buscar: "claude.exe", "cursor.exe", "code.exe" con extensiones AI, etc.
            // La lista es configurable via config.toml (agent_process_names)
            vec![]
        }
    }

    /// El daemon en Windows debe instalarse como Windows Service corriendo como SYSTEM
    /// Usar la crate `windows-service` para esto
    pub mod service {
        pub fn install_service() -> Result<(), anyhow::Error> {
            // sc.exe create AgentGuard binPath= "agentguard-daemon.exe --service"
            // start= auto type= own
            Ok(())
        }
        
        pub fn service_main() {
            // Implementar el loop del Windows Service
            // Registrarse con RegisterServiceCtrlHandlerExW
            // Manejar SERVICE_CONTROL_STOP correctamente
        }
    }
}
```

---

## 9. Módulo 4 — Vault (snapshots)

### Objetivo

Antes de cada sesión de trabajo con un agente AI, hacer un snapshot de las zonas protegidas. Si algo sale mal, restaurar con un comando.

### Diseño

- **No usa Git** — implementación propia más simple y sin dependencias
- Almacena snapshots en `~/.agentguard/vault/`
- Formato: directorio con timestamp + manifesto JSON + archivos copiados con hash
- Cada archivo en el snapshot es identificado por su hash BLAKE3

### vault.rs

```rust
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tokio::fs;
use blake3::Hasher;

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,           // UUID v4
    pub timestamp: u64,       // Unix timestamp
    pub label: String,        // "pre-session" | "manual" | "scheduled"
    pub files: Vec<FileEntry>,
    pub total_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub original_path: PathBuf,
    pub hash: String,          // BLAKE3 hex
    pub size: u64,
    pub permissions: u32,      // modo octal
}

pub struct Vault {
    vault_dir: PathBuf,
}

impl Vault {
    pub fn new() -> Result<Self, anyhow::Error> {
        let vault_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("No home dir"))?
            .join(".agentguard")
            .join("vault");
        
        std::fs::create_dir_all(&vault_dir)?;
        Ok(Self { vault_dir })
    }

    /// Crear snapshot de una lista de rutas protegidas
    pub async fn create_snapshot(
        &self,
        protected_paths: &[PathBuf],
        label: &str,
    ) -> Result<Snapshot, anyhow::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let snapshot_dir = self.vault_dir.join(&id);
        fs::create_dir_all(&snapshot_dir).await?;
        
        let mut files = Vec::new();
        let mut total_size = 0u64;
        
        for protected_path in protected_paths {
            // Copiar recursivamente los archivos
            let entries = collect_files(protected_path).await?;
            for entry_path in entries {
                let content = fs::read(&entry_path).await?;
                let hash = blake3::hash(&content).to_hex().to_string();
                let size = content.len() as u64;
                
                // Guardar el archivo usando el hash como nombre (deduplicación)
                let stored_path = snapshot_dir.join(&hash);
                if !stored_path.exists() {
                    fs::write(&stored_path, &content).await?;
                }
                
                total_size += size;
                files.push(FileEntry {
                    original_path: entry_path,
                    hash,
                    size,
                    permissions: get_permissions(&entry_path),
                });
            }
        }
        
        let snapshot = Snapshot {
            id: id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            label: label.to_string(),
            files,
            total_size,
        };
        
        // Guardar manifesto
        let manifest_path = snapshot_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&snapshot)?;
        fs::write(manifest_path, manifest_json).await?;
        
        tracing::info!("Snapshot created: {} ({} files, {} bytes)", 
                       id, snapshot.files.len(), snapshot.total_size);
        Ok(snapshot)
    }

    /// Restaurar snapshot por ID
    pub async fn restore(&self, snapshot_id: &str) -> Result<(), anyhow::Error> {
        let snapshot_dir = self.vault_dir.join(snapshot_id);
        let manifest_path = snapshot_dir.join("manifest.json");
        
        let manifest_content = fs::read_to_string(&manifest_path).await?;
        let snapshot: Snapshot = serde_json::from_str(&manifest_content)?;
        
        // Antes de restaurar, hacer snapshot del estado actual (por si acaso)
        tracing::info!("Creating safety snapshot before restore...");
        
        for file_entry in &snapshot.files {
            let stored = snapshot_dir.join(&file_entry.hash);
            let content = fs::read(&stored).await?;
            
            // Crear directorios padre si no existen
            if let Some(parent) = file_entry.original_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            
            fs::write(&file_entry.original_path, content).await?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(file_entry.permissions);
                fs::set_permissions(&file_entry.original_path, perms).await?;
            }
            
            tracing::info!("Restored: {:?}", file_entry.original_path);
        }
        
        Ok(())
    }

    /// Listar todos los snapshots
    pub async fn list(&self) -> Result<Vec<Snapshot>, anyhow::Error> {
        let mut snapshots = Vec::new();
        let mut entries = fs::read_dir(&self.vault_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let manifest = entry.path().join("manifest.json");
            if manifest.exists() {
                let content = fs::read_to_string(&manifest).await?;
                if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&content) {
                    snapshots.push(snapshot);
                }
            }
        }
        
        // Ordenar por timestamp descendente
        snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(snapshots)
    }

    /// Eliminar snapshots más viejos que N días (limpieza automática)
    pub async fn cleanup(&self, keep_days: u64) -> Result<(), anyhow::Error> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() - (keep_days * 86400);
        
        for snapshot in self.list().await? {
            if snapshot.timestamp < cutoff {
                let snapshot_dir = self.vault_dir.join(&snapshot.id);
                fs::remove_dir_all(snapshot_dir).await?;
                tracing::info!("Cleaned up old snapshot: {}", snapshot.id);
            }
        }
        Ok(())
    }
}

async fn collect_files(path: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
    let mut files = Vec::new();
    
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(files);
    }
    
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
            } else {
                files.push(entry_path);
            }
        }
    }
    
    Ok(files)
}

fn get_permissions(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map(|m| m.mode()).unwrap_or(0o644)
    }
    #[cfg(windows)]
    { 0o644 }
}
```

---

## 10. Módulo 5 — DLP Proxy (API key leaks)

### Objetivo

Proxy HTTP/HTTPS local que intercepta todo el tráfico saliente de los procesos de agentes AI y bloquea requests que contengan API keys u otros secretos.

### Flujo

```
Proceso agente AI
    │
    │ (configurado con HTTP_PROXY=127.0.0.1:7771)
    ▼
DLP Proxy (127.0.0.1:7771)
    │
    ├─ Escanear headers + body con reglas DLP
    │       ├─ MATCH → bloquear + alertar + loggear (NUNCA loggear el valor, solo "found: OpenAI Key")
    │       └─ NO MATCH → reenviar al destino real
    │
    ▼
Internet
```

### Patrones DLP por defecto

> **Importante (v1.0):** el proxy DLP **debe** soportar HTTPS desde el día 1.
> Sin MITM TLS el proxy es inútil — el 99% del tráfico a APIs de IA es HTTPS.
>
> Estrategia:
> 1. En la primera ejecución, generar un par CA root con `rcgen` y guardarlo
>    en `~/.agentguard/ca/` con permisos 600.
> 2. El instalador (`install.sh` / Inno Setup) añade la CA al trust store del
>    sistema (Linux: `update-ca-certificates`; Windows: `certutil -addstore`;
>    `security add-trusted-cert`). Mostrar consentimiento explícito.
> 3. El proxy genera certs leaf on-the-fly por hostname firmados por la CA
>    local cuando recibe un `CONNECT host:443`.
> 4. La CA root **nunca** sale de la máquina y es desinstalada al hacer
>    `agentguard uninstall`.

```rust
pub const DEFAULT_DLP_PATTERNS: &[(&str, &str)] = &[
    // (nombre, regex)
    ("OpenAI API Key",     r"sk-[a-zA-Z0-9]{48,}"),
    ("OpenAI Project Key", r"sk-proj-[a-zA-Z0-9\-_]{50,}"),
    ("Anthropic API Key",  r"sk-ant-[a-zA-Z0-9\-_]{80,}"),
    ("GitHub Token",       r"ghp_[a-zA-Z0-9]{36}"),
    ("GitHub OAuth",       r"gho_[a-zA-Z0-9]{36}"),
    ("AWS Access Key",     r"AKIA[A-Z0-9]{16}"),
    ("AWS Secret Key",     r"[a-zA-Z0-9/+]{40}"),  // heurística, combinada con contexto
    ("Google API Key",     r"AIza[a-zA-Z0-9\-_]{35}"),
    ("Stripe Live Key",    r"sk_live_[a-zA-Z0-9]{99}"),
    ("Stripe Test Key",    r"sk_test_[a-zA-Z0-9]{99}"),
    ("Twilio Auth Token",  r"[a-f0-9]{32}"),
    ("Private Key Block",  r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("Bearer Token",       r#"[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}"#),
];
```

### dlp_proxy.rs

```rust
use hyper::{Body, Client, Request, Response, Server, Uri};
use hyper::service::{make_service_fn, service_fn};
use regex::Regex;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct DlpProxy {
    port: u16,
    patterns: Arc<Vec<(String, Regex)>>,
    action: DlpAction,
}

#[derive(Clone, Debug)]
pub enum DlpAction {
    Block,   // bloquear el request y alertar
    Alert,   // dejar pasar pero alertar
    Log,     // solo loggear
}

pub struct DlpViolation {
    pub pattern_name: String,
    pub process_name: String,
    pub destination: String,
    pub timestamp: u64,
    // NUNCA incluir el valor real del secreto en el log
}

impl DlpProxy {
    pub fn new(port: u16, custom_patterns: Vec<(String, String)>, action: DlpAction) 
        -> Result<Self, anyhow::Error> 
    {
        let mut patterns = Vec::new();
        
        // Cargar patrones por defecto
        for (name, pattern) in DEFAULT_DLP_PATTERNS {
            patterns.push((name.to_string(), Regex::new(pattern)?));
        }
        
        // Cargar patrones custom del usuario
        for (name, pattern) in custom_patterns {
            patterns.push((name, Regex::new(&pattern)?));
        }
        
        Ok(Self {
            port,
            patterns: Arc::new(patterns),
            action,
        })
    }

    pub async fn start(&self) -> Result<(), anyhow::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let patterns = self.patterns.clone();
        let action = self.action.clone();
        
        let make_svc = make_service_fn(move |_conn| {
            let patterns = patterns.clone();
            let action = action.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_request(req, patterns.clone(), action.clone())
                }))
            }
        });
        
        let server = Server::bind(&addr).serve(make_svc);
        tracing::info!("DLP Proxy listening on http://{}", addr);
        server.await?;
        Ok(())
    }
}

async fn handle_request(
    req: Request<Body>,
    patterns: Arc<Vec<(String, Regex)>>,
    action: DlpAction,
) -> Result<Response<Body>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    
    // Escanear headers
    let headers_str = format!("{:?}", parts.headers);
    // Escanear body (solo texto — no escanear binario/imágenes)
    let body_str = String::from_utf8_lossy(&body_bytes);
    
    let content_to_scan = format!("{}\n{}", headers_str, body_str);
    
    for (name, pattern) in patterns.iter() {
        if pattern.is_match(&content_to_scan) {
            // ¡VIOLACIÓN DETECTADA!
            tracing::warn!(
                "DLP VIOLATION: {} detected in request to {}",
                name,
                parts.uri
            );
            
            // Enviar alerta al daemon principal via canal interno
            // (sin loggear el valor real del secreto)
            
            match action {
                DlpAction::Block => {
                    // Retornar respuesta de error sin reenviar
                    return Ok(Response::builder()
                        .status(403)
                        .body(Body::from(format!(
                            "AgentGuard DLP: Request blocked — {} detected. Check your agent's prompt for credential leaks.",
                            name
                        )))
                        .unwrap());
                }
                DlpAction::Alert => {
                    // Dejar pasar pero ya alertamos
                    break;
                }
                DlpAction::Log => {
                    break;
                }
            }
        }
    }
    
    // Reenviar el request al destino real
    let uri = parts.uri.clone();
    let client = Client::new();
    let rebuilt = Request::from_parts(parts, Body::from(body_bytes));
    
    match client.request(rebuilt).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!("Proxy forward error: {}", e);
            Ok(Response::builder()
                .status(502)
                .body(Body::from("AgentGuard Proxy: upstream error"))
                .unwrap())
        }
    }
}

// Para HTTPS: usar CONNECT tunneling o MITM con certificado local autofirmado
// El certificado se genera en la primera instalación y se añade al almacén del sistema
pub async fn handle_connect_tunnel(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // Implementar HTTPS MITM tunnel para inspeccionar tráfico SSL
    // Requiere generar CA root cert en instalación y añadirlo a system trust store
    todo!("HTTPS MITM — implementar en v1.1")
}
```

---

## 11. Módulo 6 — Daemon principal

### daemon.rs

```rust
use tokio::sync::mpsc;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AgentGuardDaemon {
    config: Arc<RwLock<Config>>,
    vault: Arc<Vault>,
    event_tx: mpsc::Sender<SecurityEvent>,
    event_rx: mpsc::Receiver<SecurityEvent>,
}

#[derive(Debug)]
pub enum SecurityEvent {
    FileViolation {
        path: String,
        process: String,
        pid: u32,
        event_type: ViolationType,
        timestamp: u64,
    },
    DlpViolation {
        pattern_name: String,
        destination: String,
        process: String,
        timestamp: u64,
    },
    SystemError {
        message: String,
    },
}

#[derive(Debug)]
pub enum ViolationType {
    DeleteAttempt,
    WriteAttempt,
    RenameAttempt,
}

impl AgentGuardDaemon {
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let config = self.config.read().await;
        
        // 1. Cargar kernel protection según OS
        #[cfg(target_os = "linux")]
        {
            let mut ebpf = ebpf_loader::EbpfGuard::load(&config.protected_dirs).await?;
            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                ebpf.listen_events(tx).await;
            });
        }
        
        #[cfg(target_os = "windows")]
        {
            let guard = windows_guard::WindowsGuard::new();
            for path in &config.protected_dirs {
                guard.protect_path(path)?;
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            for path in &config.protected_dirs {
                macos_guard::protect_with_uchg(path)?;
            }
        }
        
        // 2. Iniciar DLP proxy en background
        let dlp_config = config.dlp.clone();
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            match DlpProxy::new(dlp_config.port, dlp_config.custom_patterns, dlp_config.action) {
                Ok(proxy) => {
                    if let Err(e) = proxy.start().await {
                        tracing::error!(error = %e, "DLP proxy stopped");
                        let _ = event_tx.send(SecurityEvent::SystemError {
                            message: format!("DLP proxy stopped: {e}"),
                        }).await;
                    }
                }
                Err(e) => tracing::error!(error = %e, "DLP proxy failed to start"),
            }
        });
        
        // 3. Iniciar IPC server para CLI/UI
        let ipc_config = self.config.clone();
        tokio::spawn(async move {
            if let Err(e) = ipc_server::start(ipc_config).await {
                tracing::error!(error = %e, "IPC server stopped");
            }
        });
        
        // 4. Snapshot inicial si configurado
        if config.vault.snapshot_on_start {
            drop(config); // liberar lock
            let config = self.config.read().await;
            self.vault.create_snapshot(
                &config.protected_dirs,
                "startup"
            ).await?;
        }
        
        // 5. Loop principal de eventos
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
        let config = self.config.read().await;
        
        match &event {
            SecurityEvent::FileViolation { path, process, pid, event_type, timestamp } => {
                tracing::warn!(
                    "BLOCKED: {:?} on {} by {} (PID {})",
                    event_type, path, process, pid
                );
                
                // Notificación de escritorio
                if config.alerts.desktop_notifications {
                    self.send_desktop_notification(
                        "AgentGuard: Acción bloqueada",
                        &format!("El agente '{}' intentó modificar una zona protegida: {}", 
                                 process, path)
                    ).await;
                }
                
                // Guardar en log de incidentes
                self.log_incident(&event).await;
                
                // Matar el proceso si configurado
                if config.on_violation.kill_process {
                    if let Err(e) = self.kill_process(*pid).await {
                        tracing::error!("Failed to kill process {}: {}", pid, e);
                    }
                }
            }
            
            SecurityEvent::DlpViolation { pattern_name, destination, process, .. } => {
                tracing::warn!(
                    "DLP: {} detected in traffic from {} to {}",
                    pattern_name, process, destination
                );
                
                if config.alerts.desktop_notifications {
                    self.send_desktop_notification(
                        "AgentGuard: Posible leak bloqueado",
                        &format!("'{}' detectado en tráfico de {}. Request bloqueado.", 
                                 pattern_name, process)
                    ).await;
                }
                
                self.log_incident(&event).await;
            }
            
            SecurityEvent::SystemError { message } => {
                tracing::error!("System error: {}", message);
            }
        }
    }

    async fn kill_process(&self, pid: u32) -> Result<(), anyhow::Error> {
        #[cfg(unix)]
        {
            unsafe { libc::kill(pid as i32, libc::SIGKILL); }
        }
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::*;
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
                TerminateProcess(handle, 1)?;
            }
        }
        Ok(())
    }

    async fn send_desktop_notification(&self, title: &str, body: &str) {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = notify_rust::Notification::new()
                .summary(title)
                .body(body)
                .icon("security-high")
                .show();
        }
        // Windows: usar win32 ToastNotification API
    }

    async fn log_incident(&self, event: &SecurityEvent) {
        if let Err(e) = self.try_log_incident(event).await {
            // Última línea de defensa: escribir a stderr vía tracing.
            // NUNCA hacer panic en este código path.
            tracing::error!(error = %e, "failed to persist incident to disk");
        }
    }

    async fn try_log_incident(&self, event: &SecurityEvent) -> Result<(), anyhow::Error> {
        use tokio::io::AsyncWriteExt;
        let log_path = self.incidents_log_path()?;
        let entry = serde_json::to_string(event)?;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log_path)
            .await?;
        file.write_all(format!("{}\n", entry).as_bytes()).await?;
        Ok(())
    }

    fn incidents_log_path(&self) -> Result<std::path::PathBuf, anyhow::Error> {
        // En modo daemon-as-root usamos /var/lib/agentguard/.
        // En modo user-session usamos ~/.agentguard/.
        let base = if cfg!(unix) && nix::unistd::geteuid().is_root() {
            std::path::PathBuf::from("/var/lib/agentguard")
        } else {
            dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("no home dir available"))?
                .join(".agentguard")
        };
        std::fs::create_dir_all(&base)?;
        Ok(base.join("incidents.jsonl"))
    }
}

/// IPC server — socket Unix en Linux, Named Pipe en Windows
mod ipc_server {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub enum IpcCommand {
        Status,
        AddProtectedPath { path: String },
        RemoveProtectedPath { path: String },
        ListSnapshots,
        RestoreSnapshot { id: String },
        CreateSnapshot { label: String },
        ListIncidents { last_n: usize },
        Pause { duration_seconds: u64 },
        Resume,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub enum IpcResponse {
        Status {
            protected: bool,
            protected_paths: Vec<String>,
            incidents_count: u64,
            version: String,
        },
        Snapshots(Vec<super::SnapshotInfo>),
        Incidents(Vec<serde_json::Value>),
        Ok,
        Error(String),
    }

    pub async fn start(config: std::sync::Arc<tokio::sync::RwLock<super::Config>>) 
        -> Result<(), anyhow::Error> 
    {
        // Usar interprocess crate para cross-platform IPC
        // Socket path: ~/.agentguard/daemon.sock (Linux)
        //              \\.\pipe\AgentGuard (Windows)
        Ok(())
    }
}
```

---

## 12. Módulo 7 — CLI

### agentguard-cli/src/main.rs

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Protect your filesystem and secrets from AI agents gone rogue"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current protection status
    Status,
    
    /// Protect a directory or file
    Protect {
        /// Path to protect
        path: String,
        /// Only watch (don't block)
        #[arg(long)]
        watch_only: bool,
    },
    
    /// Remove protection from a path
    Unprotect {
        path: String,
    },
    
    /// Snapshot management
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommands,
    },
    
    /// Show recent security incidents
    Incidents {
        /// Number of recent incidents to show
        #[arg(short, long, default_value = "20")]
        last: usize,
        
        /// Show only file violations
        #[arg(long)]
        files_only: bool,
        
        /// Show only DLP violations
        #[arg(long)]
        dlp_only: bool,
    },
    
    /// Update AgentGuard to latest version
    Update,
    
    /// Start/stop/restart the daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonCommands,
    },
    
    /// Pause protection temporarily (requires confirmation)
    Pause {
        /// Duration in minutes
        #[arg(short, long, default_value = "30")]
        minutes: u64,
    },
    
    /// Resume protection after pause
    Resume,
}

#[derive(Subcommand)]
enum SnapshotCommands {
    /// Create a new snapshot
    Create {
        #[arg(short, long, default_value = "manual")]
        label: String,
    },
    /// List all snapshots
    List,
    /// Restore a snapshot
    Restore {
        /// Snapshot ID (or 'latest')
        id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Delete old snapshots
    Cleanup {
        #[arg(long, default_value = "30")]
        keep_days: u64,
    },
}

#[derive(Subcommand)]
enum DaemonCommands {
    Start,
    Stop,
    Restart,
    Logs {
        #[arg(short, long, default_value = "50")]
        lines: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    
    // Conectar al daemon via IPC
    let mut client = ipc_client::connect().await?;
    
    match cli.command {
        Commands::Status => {
            let status = client.send(IpcCommand::Status).await?;
            print_status(status);
        }
        Commands::Protect { path, watch_only } => {
            // Validar que el path existe
            // Enviar al daemon
            println!("✓ Protected: {}", path);
        }
        Commands::Incidents { last, files_only, dlp_only } => {
            // Obtener y formatear incidentes
            print_incidents_table(client.send(IpcCommand::ListIncidents { last_n: last }).await?);
        }
        // ... resto de comandos
        _ => {}
    }
    
    Ok(())
}

fn print_status(status: IpcResponse) {
    // Salida tipo:
    // ┌─────────────────────────────────┐
    // │  AgentGuard v0.1.0              │
    // │  Status: ✓ PROTECTED            │
    // │                                 │
    // │  Protected paths (3):           │
    // │    ~/Documents                  │
    // │    ~/Projects/omk-backend       │
    // │    ~/.ssh                       │
    // │                                 │
    // │  Incidents (24h): 2             │
    // └─────────────────────────────────┘
}
```

---

## 13. Módulo 8 — UI Tauri

### tauri.conf.json

```json
{
  "productName": "AgentGuard",
  "version": "0.1.0",
  "identifier": "io.agentguard.app",
  "build": {
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build",
    "devUrl": "http://localhost:1420",
    "frontendDist": "../ui/dist"
  },
  "app": {
    "windows": [
      {
        "label": "main",
        "title": "AgentGuard",
        "width": 900,
        "height": 600,
        "minWidth": 800,
        "minHeight": 500,
        "resizable": true,
        "decorations": true
      }
    ],
    "systemTray": {
      "iconPath": "icons/tray.png",
      "iconAsTemplate": true,
      "menuOnLeftClick": false
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": ["icons/32x32.png", "icons/128x128.png", "icons/icon.icns", "icons/icon.ico"]
  }
}
```

### UI — 3 pantallas únicamente

#### Design system

```css
/* Minimalista, oscuro, técnico */
:root {
  --bg: #0f0f0f;
  --surface: #1a1a1a;
  --border: #2a2a2a;
  --text: #e8e8e8;
  --text-muted: #888;
  --accent: #22c55e;     /* verde = protegido */
  --danger: #ef4444;     /* rojo = violación */
  --warning: #f59e0b;    /* amarillo = alerta */
  --font: 'Inter', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}
```

#### Pantalla 1 — Dashboard

```
┌──────────────────────────────────────────────────────┐
│  🛡 AgentGuard                          v0.1.0  [?] │
├──────────────────────────────────────────────────────┤
│                                                      │
│          ●  PROTECTED                                │
│     Kernel protection active                         │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  3 paths     │  │  2 incidents │  │  4 snapsh. │ │
│  │  protected   │  │  last 24h    │  │  stored    │ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
│                                                      │
│  Recent activity                                     │
│  ─────────────────────────────────────────────────  │
│  14:32  BLOCKED  cursor deleted ~/Documents/arch.md  │
│  13:11  DLP      OpenAI key in request to openai.com │
│  12:00  SNAPSHOT pre-session (automatic)             │
│                                                      │
│  [Snapshot now]              [Pause 30min]           │
└──────────────────────────────────────────────────────┘
```

#### Pantalla 2 — Protected Zones

```
┌──────────────────────────────────────────────────────┐
│  Protected Zones                        [+ Add path] │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ● ~/Documents              KERNEL  [Remove]         │
│  ● ~/Projects/omk-backend   KERNEL  [Remove]         │
│  ● ~/.ssh                   KERNEL  [Remove]         │
│  ○ ~/.env                   FILE    [Remove]         │
│                                                      │
│  ─────────────────────────────────────────────────  │
│  Snapshots                                           │
│                                                      │
│  2025-01-15 14:30  pre-session  [Restore] [Delete]   │
│  2025-01-15 12:00  manual       [Restore] [Delete]   │
│  2025-01-14 09:15  startup      [Restore] [Delete]   │
│                                                      │
└──────────────────────────────────────────────────────┘
```

#### Pantalla 3 — Incidents

```
┌──────────────────────────────────────────────────────┐
│  Security Incidents         [All ▼] [Export CSV]     │
├────────────────┬────────────┬──────────┬────────────-┤
│  Time          │ Type       │ Process  │ Detail       │
├────────────────┼────────────┼──────────┼─────────────┤
│  14:32:11      │ FILE DEL   │ cursor   │ ~/Doc/a.md   │
│  13:11:44      │ DLP        │ code     │ OpenAI Key   │
│  11:55:02      │ FILE WRITE │ claude   │ ~/.env       │
└────────────────┴────────────┴──────────┴─────────────┘
```

### Tauri Commands (backend → frontend bridge)

```rust
// crates/agentguard-ui/src/main.rs

#[tauri::command]
async fn get_status() -> Result<StatusResponse, String> {
    // Conectar al daemon IPC y obtener status
    ipc_client::get_status().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_protected_path(path: String) -> Result<(), String> {
    ipc_client::add_path(&path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_snapshot(label: String) -> Result<String, String> {
    ipc_client::create_snapshot(&label).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn restore_snapshot(id: String) -> Result<(), String> {
    ipc_client::restore_snapshot(&id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_incidents(last_n: usize) -> Result<Vec<Incident>, String> {
    ipc_client::get_incidents(last_n).await.map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            get_status,
            add_protected_path,
            create_snapshot,
            restore_snapshot,
            get_incidents,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AgentGuard");
}
```

---

## 14. Módulo 9 — Auto-updater

### Mecanismo

1. Daemon comprueba `https://github.com/tuorg/agentguard/releases/latest` cada 24h
2. Compara versión actual (semver) con la del release
3. Si hay nueva versión: descarga el binario para el OS/arch actual
4. Verifica SHA256 (publicado en `checksums.txt` del release)
5. Reemplaza el binario en caliente (en Linux atomically via rename)
6. Reinicia el daemon

### updater.rs

```rust
use semver::Version;
use reqwest::Client;

const GITHUB_RELEASES_API: &str = 
    "https://api.github.com/repos/tuorg/agentguard/releases/latest";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Updater {
    client: Client,
    check_interval: std::time::Duration,
}

impl Updater {
    pub async fn check_and_update(&self) -> Result<bool, anyhow::Error> {
        let release = self.fetch_latest_release().await?;
        let latest = Version::parse(&release.tag_name.trim_start_matches('v'))?;
        let current = Version::parse(CURRENT_VERSION)?;
        
        if latest > current {
            tracing::info!("New version available: {} (current: {})", latest, current);
            self.download_and_apply(&release).await?;
            return Ok(true);
        }
        
        Ok(false)
    }

    async fn fetch_latest_release(&self) -> Result<GithubRelease, anyhow::Error> {
        let release: GithubRelease = self.client
            .get(GITHUB_RELEASES_API)
            .header("User-Agent", format!("AgentGuard/{}", CURRENT_VERSION))
            .send()
            .await?
            .json()
            .await?;
        Ok(release)
    }

    async fn download_and_apply(&self, release: &GithubRelease) -> Result<(), anyhow::Error> {
        // 1. Determinar el asset correcto para el OS/arch actual
        let target = get_target_triple(); // e.g., "x86_64-unknown-linux-gnu"
        let asset = release.assets.iter()
            .find(|a| a.name.contains(&target))
            .ok_or_else(|| anyhow::anyhow!("No asset for target {}", target))?;
        
        // 2. Descargar el binario
        let bytes = self.client.get(&asset.browser_download_url)
            .send().await?.bytes().await?;
        
        // 3. Verificar SHA256
        let checksums = self.fetch_checksums(release).await?;
        verify_checksum(&bytes, &asset.name, &checksums)?;
        
        // 4. Escribir el nuevo binario en una ruta temporal
        let current_exe = std::env::current_exe()?;
        let tmp_path = current_exe.with_extension("tmp");
        tokio::fs::write(&tmp_path, &bytes).await?;
        
        // 5. Reemplazar atómicamente
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp_path, 
                std::fs::Permissions::from_mode(0o755)).await?;
            tokio::fs::rename(&tmp_path, &current_exe).await?;
        }
        
        // 6. Reiniciar el daemon
        // Señal SIGUSR1 al proceso actual → el systemd unit tiene Restart=always
        
        Ok(())
    }
}

fn get_target_triple() -> String {
    format!("{}-{}-{}",
        std::env::consts::ARCH,
        std::env::consts::FAMILY,
        std::env::consts::OS
    )
}

fn verify_checksum(data: &[u8], filename: &str, checksums: &str) -> Result<(), anyhow::Error> {
    let expected = checksums.lines()
        .find(|l| l.contains(filename))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| anyhow::anyhow!("Checksum not found for {}", filename))?;
    
    let actual = blake3::hash(data).to_hex().to_string();
    
    if actual != expected {
        anyhow::bail!("Checksum mismatch! Expected {}, got {}", expected, actual);
    }
    
    Ok(())
}
```

---

## 15. Configuración (config.toml)

Ubicación:
- Linux: `~/.agentguard/config.toml`
- Windows: `%APPDATA%\AgentGuard\config.toml`

```toml
[agentguard]
version = "1"

# Rutas protegidas — NUNCA se pueden borrar mientras el daemon esté activo
protected_dirs = [
    "~/Documents",
    "~/Projects",
    "~/.ssh",
]

# Archivos individuales protegidos contra escritura
protected_files = [
    "~/.env",
    "~/.netrc",
    "~/.aws/credentials",
]

# Identificación de procesos "agente AI".
#
# Reglas: NO usar solo el nombre del ejecutable — "node" y "python" son
# demasiado genéricos y bloquearían workflows normales del usuario.
# Cada entrada combina nombre + heurísticas (argv, parent, env vars).
[[agent_processes]]
name = "cursor"
match = { exe = "cursor" }

[[agent_processes]]
name = "claude-code"
match = { exe_any = ["claude", "claude-code"] }

[[agent_processes]]
name = "vscode-copilot"
# VS Code solo cuenta si tiene la extensión Copilot/Cline cargada.
match = { exe = "code", argv_contains_any = ["copilot", "cline", "continue"] }

[[agent_processes]]
name = "aider"
match = { exe = "aider" }

[[agent_processes]]
name = "node-agent"
# Solo procesos Node lanzados por un terminal de un agente conocido,
# o con env var AGENTGUARD_AGENT=1 (que el wrapper de la CLI puede setear).
match = { exe = "node", env_has = "AGENTGUARD_AGENT" }

[[agent_processes]]
name = "python-agent"
match = { exe_any = ["python", "python3"], env_has = "AGENTGUARD_AGENT" }

[on_violation]
# Matar el proceso si intenta tocar zona protegida
kill_process = false  # false por defecto — puede ser disruptivo

# Crear snapshot automático cuando se detecta una violación
snapshot_on_violation = true

[alerts]
desktop_notifications = true
sound = false
# webhook para integraciones (Slack, Discord, etc.)
webhook_url = ""

[vault]
# Snapshot automático al arrancar el daemon
snapshot_on_start = true

# Snapshot automático periódico
auto_snapshot_interval_hours = 6

# Cuántos días conservar snapshots
keep_days = 30

# Dónde guardar los snapshots
# Por defecto: ~/.agentguard/vault/
vault_dir = ""

[dlp]
enabled = true
proxy_port = 7771
action = "block"  # "block" | "alert" | "log"

# Patrones adicionales del usuario (además de los built-in)
[[dlp.custom_patterns]]
name = "Mi API Key Interna"
regex = "mycompany-[a-zA-Z0-9]{32}"

[updates]
auto_check = true
check_interval_hours = 24
auto_install = false  # notificar pero no instalar automáticamente
channel = "stable"    # "stable" | "beta"
```

---

## 16. Instaladores y packaging

### Linux — install.sh

```bash
#!/bin/bash
set -e

REPO="tuorg/agentguard"
VERSION="latest"
ARCH=$(uname -m)
OS="linux"

echo "Installing AgentGuard..."

# 1. Detectar arquitectura
case $ARCH in
    x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# 2. Descargar binario
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/agentguard-${TARGET}.tar.gz"
curl -L "$DOWNLOAD_URL" -o /tmp/agentguard.tar.gz

# 3. Verificar checksum
CHECKSUMS_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"
curl -L "$CHECKSUMS_URL" -o /tmp/checksums.txt
(cd /tmp && sha256sum --check --ignore-missing checksums.txt)

# NOTA: SHA-256 se usa para los binarios de release (compatible con sha256sum
# y herramientas estándar). El vault interno usa BLAKE3 — son contextos
# distintos y no se mezclan.

# 4. Instalar binarios
tar -xzf /tmp/agentguard.tar.gz -C /tmp
sudo install -m 755 /tmp/agentguard-daemon /usr/local/bin/
sudo install -m 755 /tmp/agentguard /usr/local/bin/

# 5. Verificar soporte eBPF
KERNEL=$(uname -r)
echo "Checking eBPF LSM support (kernel $KERNEL)..."
if grep -q "CONFIG_BPF_LSM=y" /boot/config-"$KERNEL" 2>/dev/null; then
    echo "✓ eBPF LSM supported — maximum protection active"
    PROTECTION_MODE="kernel-ebpf"
else
    echo "⚠ eBPF LSM not available — falling back to userspace watcher"
    echo "  For maximum protection, upgrade to Ubuntu 22.04+ or Debian 12+"
    PROTECTION_MODE="userspace"
fi

# 6. Instalar systemd service
sudo tee /etc/systemd/system/agentguard.service > /dev/null <<EOF
[Unit]
Description=AgentGuard — AI Agent Security Daemon
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/agentguard-daemon
Restart=always
RestartSec=1
User=root
Environment=PROTECTION_MODE=${PROTECTION_MODE}

[Install]
WantedBy=multi-user.target
EOF

# 7. Arrancar
sudo systemctl daemon-reload
sudo systemctl enable --now agentguard

# 8. Crear config por defecto si no existe
CONFIG_DIR="$HOME/.agentguard"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    agentguard init --defaults
fi

echo ""
echo "✓ AgentGuard installed successfully!"
echo "  Status: agentguard status"
echo "  Protect a folder: agentguard protect ~/Documents"
echo "  UI: agentguard-ui (or find it in your app launcher)"
```

### Windows — installer.iss (Inno Setup)

```iss
[Setup]
AppName=AgentGuard
AppVersion={#AppVersion}
AppPublisher=AgentGuard
AppPublisherURL=https://agentguard.io
DefaultDirName={autopf}\AgentGuard
DefaultGroupName=AgentGuard
OutputBaseFilename=agentguard-setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "dist\agentguard-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\agentguard.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\AgentGuard.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Instalar como Windows Service
Filename: "{app}\agentguard-daemon.exe"; Parameters: "install-service"; \
    StatusMsg: "Installing AgentGuard service..."; Flags: runhidden

; Arrancar el servicio
Filename: "sc.exe"; Parameters: "start AgentGuard"; \
    StatusMsg: "Starting AgentGuard..."; Flags: runhidden

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop AgentGuard"; Flags: runhidden
Filename: "{app}\agentguard-daemon.exe"; Parameters: "uninstall-service"; Flags: runhidden

[Icons]
Name: "{group}\AgentGuard"; Filename: "{app}\AgentGuard.exe"
Name: "{userstartup}\AgentGuard"; Filename: "{app}\AgentGuard.exe"
```

### systemd unit (Linux)

```ini
# /etc/systemd/system/agentguard.service
[Unit]
Description=AgentGuard — AI Agent Security Daemon
Documentation=https://agentguard.io/docs
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/agentguard-daemon --config /etc/agentguard/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
# Correr como root para poder cargar eBPF LSM y modificar ACLs
User=root
# Pero limitar capacidades solo a las necesarias
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
NoNewPrivileges=true
# El daemon necesita escribir el vault y los logs.
# Como corre system-wide (no por usuario), usamos /var/lib/agentguard.
# ProtectHome=true para que NO toque /home (los snapshots se hacen leyendo
# /home y escribiendo en /var/lib/agentguard/vault).
StateDirectory=agentguard
LogsDirectory=agentguard
RuntimeDirectory=agentguard
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/agentguard /var/log/agentguard /run/agentguard
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## 17. Modelo de licencias

```
agentguard/
├── crates/agentguard-ebpf/    → GPL v2 (obligatorio — código kernel Linux)
├── crates/agentguard-common/  → MIT (tipos compartidos, sin restricciones)
├── crates/agentguard-daemon/  → BSL 1.1 (propietario, source-available)
├── crates/agentguard-cli/     → BSL 1.1
└── crates/agentguard-ui/      → BSL 1.1
```

**BSL 1.1 (Business Source License):**
- El código fuente es visible y auditable
- Los usuarios individuales pueden usarlo libremente
- No se puede usar para ofrecer un servicio competidor comercial sin licencia
- Automáticamente se convierte en MIT después de 4 años

**Por qué esta combinación:**
- Genera confianza: el código de seguridad es auditable
- Protege el negocio: nadie puede copiar y vender el producto
- Compatible con GPL del módulo eBPF

---

## 18. Pipeline CI/CD

### .github/workflows/ci.yml

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings

  test-linux:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace --exclude agentguard-ebpf

  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace --exclude agentguard-ebpf

  build-ebpf:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rust-src
          targets: bpfel-unknown-none
      - run: cargo build -p agentguard-ebpf --target bpfel-unknown-none -Z build-std=core
```

### .github/workflows/release.yml

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            artifact: agentguard-x86_64-linux.tar.gz
          - os: ubuntu-22.04
            target: aarch64-unknown-linux-gnu
            artifact: agentguard-aarch64-linux.tar.gz
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: agentguard-x86_64-windows.zip
          - os: macos-latest
            target: 
            artifact: agentguard-x86_64-macos.tar.gz
          - os: macos-latest
            target: 
            artifact: agentguard-aarch64-macos.tar.gz

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Build
        run: cargo build --release --target ${{ matrix.target }}
      
      - name: Package (Linux)
        if: runner.os != 'Windows'
        run: |
          tar czf ${{ matrix.artifact }} \
            -C target/${{ matrix.target }}/release \
            agentguard-daemon agentguard
      
      - name: Package (Windows)
        if: runner.os == 'Windows'
        run: |
          Compress-Archive -Path target/${{ matrix.target }}/release/agentguard-daemon.exe,target/${{ matrix.target }}/release/agentguard.exe -DestinationPath ${{ matrix.artifact }}
      
      - uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: ${{ matrix.artifact }}

  publish:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      
      - name: Generate checksums
        run: sha256sum **/*.tar.gz **/*.zip > checksums.txt
      
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            **/*.tar.gz
            **/*.zip
            checksums.txt
```

---

## 19. Orden de implementación obligatorio

> El plan detallado con fases, gates y entregables está en [`PlanDeImplementacion.md`](./PlanDeImplementacion.md).
> Resumen de fases:

### Fase 0 — Reorganización de crates

Separar el daemon monolítico en `agentguard-core` (lógica compartida) + `agentguard-linux` / `agentguard-windows` / `agentguard-macos` (binarios por SO).

### Fase 1 — Core completo

Vault, DLP proxy, CA local, IPC server, eventos, trait KernelGuard. Todo en `agentguard-core`.

### Fase 2 — Linux daemon (MVP)

eBPF LSM + userspace fallback. Primer binario funcional que bloquea `unlink` real.

### Fase 3 — CLI + Installer cross-platform (terminal-first)

CLI con todos los comandos. Installer que detecta SO y descarga solo lo necesario. `curl | bash` → listo.

### Fase 4 — Windows daemon

NTFS DENY ACEs + Job Objects + Windows Service.

### Fase 5 — 

Eliminada del MVP.

### Fase 6 — UI Tauri (opcional)

Dashboard + Zones + Incidents. Complementa la CLI, no la reemplaza.

### Fase 7 — Auto-updater

Check GitHub releases, SHA256 verify, reemplazo atómico, reload.

---

## 20. Tests mínimos requeridos

### Tests unitarios (cada módulo)

```rust
// tests/integration/test_file_protection.rs

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_vault_create_and_restore() {
        let tmp = TempDir::new().unwrap();
        let test_file = tmp.path().join("test.md");
        std::fs::write(&test_file, "original content").unwrap();
        
        let vault = Vault::new_with_dir(tmp.path().join("vault")).unwrap();
        let snapshot = vault.create_snapshot(
            &[test_file.parent().unwrap().to_path_buf()],
            "test"
        ).await.unwrap();
        
        // Simular borrado
        std::fs::remove_file(&test_file).unwrap();
        assert!(!test_file.exists());
        
        // Restaurar
        vault.restore(&snapshot.id).await.unwrap();
        assert!(test_file.exists());
        assert_eq!(std::fs::read_to_string(&test_file).unwrap(), "original content");
    }
    
    #[tokio::test]
    async fn test_dlp_blocks_api_key() {
        // Iniciar proxy en puerto de test
        let proxy = DlpProxy::new(7779, vec![], DlpAction::Block).unwrap();
        tokio::spawn(async move { proxy.start().await.unwrap(); });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        // Hacer request con API key en el body
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http("http://127.0.0.1:7779").unwrap())
            .build()
            .unwrap();
        
        let response = client.post("http://httpbin.org/post")
            .body("Authorization: sk-1234567890abcdef1234567890abcdef1234567890abcdef")
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 403);
        assert!(response.text().await.unwrap().contains("AgentGuard DLP"));
    }
    
    #[tokio::test]
    async fn test_dlp_allows_clean_request() {
        // Mismo setup pero con body limpio
        let response = client.post("http://httpbin.org/post")
            .body("Hello world, no secrets here")
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
    }
}
```

### Checklist de verificación pre-release

```
[ ] unlink en zona protegida → retorna EPERM en Linux (eBPF activo)
[ ] API key en request HTTP → bloqueado por DLP proxy
[ ] Snapshot → restore → archivos idénticos (verificar hash)
[ ] Daemon sobrevive a kill -9 → systemd lo reinicia en <2s
[ ] Protección persiste después de matar el daemon userspace (kernel sigue activo)
[ ] CLI: todos los comandos tienen output legible
[ ] Config inválida → error descriptivo, no panic
[ ] Update check → descarga → verifica checksum → rechaza si no coincide
[ ] RAM en idle < 10 MB (medir con /proc/PID/status en Linux)
[ ] CPU en idle < 0.1% (medir con top durante 5 minutos)
```

---

## Notas finales para el implementador

1. **eBPF antes que todo.** Es la pieza diferenciadora. Sin ella el producto es otro watcher de userspace como hay miles.

2. **Cero panics en producción.** Usar `thiserror` + `anyhow`. Cada `?` es un manejo de error. Cero `.unwrap()` fuera de tests.

3. **El vault es el killer feature de confianza.** Los usuarios pagan por la paz mental de "puedo restaurar con un comando". Hacerlo infalible.

4. **El DLP proxy debe ser transparente.** El usuario configura `HTTP_PROXY=127.0.0.1:7771` en su entorno y olvida que existe. No debe añadir más de 5ms de latencia.

5. **Logging estructurado siempre.** `tracing` con JSON en producción. Los incidentes nunca deben contener el valor real de un secreto, solo su tipo y ubicación.

6. **Configurar el proxy del sistema en la instalación.** En Linux: añadir `export HTTP_PROXY=...` al perfil del shell. En Windows: configurar el proxy del sistema. Así funciona para todos los agentes automáticamente.

---

*AgentGuard — Lo que tus agentes hacen, ahora lo controlas tú.*