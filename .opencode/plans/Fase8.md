# Fase 8 — Windows Hardening & Completion

> **Propósito:** Cerrar los gaps críticos y altos del daemon Windows (Fase 4)
> detectados en `state.md`.
>
> La Fase 4 implementó la protección base (NTFS DENY ACEs + Job Objects + ETW)
> pero dejó 3 piezas como stubs que bloquean funcionalidad core del sandbox v2.1
> y la comunicación CLI↔daemon.

---

## Tareas

```
[ ] 8.1  AppContainer/LPAC sandbox real
[ ] 8.2  Named Pipes IPC (daemon + CLI)
[ ] 8.3  PEB introspección (cmdline + cwd)
[ ] 8.4  Tests E2E en Windows
[ ] 8.5  Installer + armonización de docs
```

### Build matrix

| Fase 8 afecta | Crate | Archivo(s) |
|---|---|---|
| ✓ | `agentguard-windows` | `Cargo.toml`, `src/sandbox.rs`, `src/guard.rs`, `src/process_watcher.rs`, `src/main.rs` |
| ✓ | `agentguard-cli` | `src/main.rs` |
| ✓ | `agentguard-core` | `src/ipc_server.rs` |
| ✓ | `agentguard-installer` | `src/main.rs` |
| ✓ | `agentguard-common` | `src/lib.rs` |
| — | (resto) | Sin cambios |

---

## 8.1 AppContainer/LPAC sandbox real

**Archivo principal:** `crates/agentguard-windows/src/sandbox.rs` (122 líneas)

### Situación actual

El archivo tiene las estructuras (`SandboxLauncher`, `SandboxCapabilities`) pero
`launch()` siempre retorna error:

```rust
// sandbox.rs:33-38
pub async fn launch(&self, _agent_exe: &str, _project_dir: &Path,
    _with_extra_isolation: bool) -> Result<u32, anyhow::Error> {
    anyhow::bail!(
        "AppContainer sandbox not yet available (requires future windows crate version)"
    )
}
```

`check_capabilities()` hardcodea `appcontainer_available: false`.

### Causa raíz

`windows-rs` v0.58 no expone `SECURITY_CAPABILITIES`, `CreateAppContainerProfile`,
ni `DeleteAppContainerProfile`. Estas APIs existen desde v0.60+.

### Plan de implementación

#### 8.1.1 Actualizar windows-rs a >= 0.60

**Archivo:** `crates/agentguard-windows/Cargo.toml:31`

Actualizar `windows = { version = "0.58"` → `"0.60"`. Añadir features nuevas:

```toml
windows = { version = "0.60", features = [
    # ... existentes ...
    "Win32_Security_AppContainer",   # CreateAppContainerProfile
    "Win32_System_ProcessStatus",    # NtQueryInformationProcess
    "Win32_System_Threading",
    "Win32_System_Kernel",
] }
```

**Riesgo:** windows-rs 0.60 puede tener breaking changes. Revisar diff de APIs usadas
en `guard.rs` (`SetNamedSecurityInfoW`, `SetEntriesInAclW`, etc.).

#### 8.1.2 Implementar `SandboxLauncher::launch()` real

**Archivo:** `crates/agentguard-windows/src/sandbox.rs`

Flujo completo:

```
launch(agent_exe, project_dir, with_extra_isolation)
  │
  ├─ 1. Derivar nombres únicos del AppContainer
  │     profile_name = format!("AgentGuard.{hash}")
  │     display_name  = format!("AgentGuard AI Agent — {agent_exe}")
  │
  ├─ 2. create_or_get_appcontainer(profile_name, display_name)
  │     └─ CreateAppContainerProfile() → SID del AppContainer
  │        Si ERROR_ALREADY_EXISTS → DeriveAppContainerSidFromAppContainerName()
  │
  ├─ 3. Aplicar DENY ACEs para el SID del AppContainer en project_dir
  │     └─ Igual que apply_deny_aces() de guard.rs, pero con el SID del container
  │        (la función apply_deny_aces existe, aceptarla con SID parametrizable)
  │
  ├─ 4. Construir SECURITY_CAPABILITIES
  │     └─ capabilities.AppContainerSid = sid
  │     └─ capabilities.Capabilities = [  ] (vacío = sin capabilities especiales)
  │        Si with_extra_isolation → capabilities.Capabilities.push("lpacCom")
  │
  ├─ 5. Construir STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_LIST
  │     └─ InitializeProcThreadAttributeList()
  │     └─ UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, ...)
  │
  ├─ 6. Inyectar variables de entorno del proxy DLP
  │     └─ HTTP_PROXY, HTTPS_PROXY, NO_PROXY
  │
  ├─ 7. CreateProcessW() con EXTENDED_STARTUPINFO_PRESENT
  │     └─ lpCommandLine = agent_exe + args
  │     └─ lpCurrentDirectory = project_dir
  │
  └─ 8. Retornar PID del proceso lanzado
```

#### 8.1.3 Implementar `SandboxCapabilities::check_capabilities()` real

```rust
pub fn check_capabilities() -> SandboxCapabilities {
    // AppContainer: Windows 8+
    let appcontainer_available = detect_windows_version() >= (6, 2);
    // ETW: siempre disponible en Windows pero requiere admin
    let etw_available = true;
    SandboxCapabilities { appcontainer_available, etw_available }
}
```

#### 8.1.4 Actualizar `effective_mode()` y `report()`

Reflejar `"sandbox"` cuando AppContainer está disponible, no `"monitor"` forzado.

### Gate 8.1

```
[ ] cargo build -p agentguard-windows (0 errores, 0 warnings)
[ ] En VM Windows 10/11: agentguard-windows.exe --protect C:\test → sandbox_mode = "sandbox"
[ ] Lanzar notepad.exe dentro del AppContainer → verificar que no puede escribir en C:\test
[ ] Verificar que el proceso hijo hereda HTTP_PROXY del container
```

---

## 8.2 Named Pipes IPC (daemon + CLI)

### Situación actual

| Componente | Transporte actual | Problema |
|---|---|---|
| **Windows daemon** (`main.rs:578`) | Unix socket en `%TEMP%\agentguard-{USER}.sock` | No es estándar en Windows; permisos dependen de filesystem |
| **CLI Windows** (`cli/main.rs:19-53`) | `StubStream` → siempre `NotConnected` | **CLI totalmente roto en Windows** |
| **Core IPC** (`ipc_server.rs`) | `std::os::unix::net::UnixListener` | No compila en Windows (`#[cfg(unix)]` implícito) |

### Plan de implementación

#### 8.2.1 Añadir soporte de Named Pipe al IPC server (core)

**Archivo:** `crates/agentguard-core/src/ipc_server.rs`

El método `start()` actual acepta `PathBuf` para el socket Unix. Añadir un método
alternativo `start_named_pipe(pipe_name: &str)` que:

```rust
#[cfg(windows)]
pub fn start_named_pipe(&self, pipe_name: &str) -> io::Result<IpcShutdown> {
    let full_name = format!(r"\\.\pipe\{}", pipe_name);
    // Crear hilo dedicado que:
    // 1. CreateNamedPipeW(full_name, PIPE_ACCESS_DUPLEX, ...)
    // 2. ConnectNamedPipe() en loop
    // 3. Leer una línea → execute() → escribir respuesta → DisconnectNamedPipe()
    // 4. Repetir
}
```

Wrapper cross-platform en `IpcServer`:

```rust
pub fn start_platform(&self, socket_or_pipe: &str) -> io::Result<IpcShutdown> {
    #[cfg(unix)]
    { self.start(PathBuf::from(socket_or_pipe)) }
    #[cfg(windows)]
    { self.start_named_pipe(socket_or_pipe) }
}
```

#### 8.2.2 Actualizar el daemon Windows para usar Named Pipe

**Archivo:** `crates/agentguard-windows/src/main.rs:577-578`

```rust
// Antes (Unix socket)
let ipc_socket_path = std::env::temp_dir().join(format!("{ipc_pipe_name}.sock"));
let ipc_handle = match ipc_server.start(ipc_socket_path.clone()) { ... }

// Después (Named Pipe)
let ipc_handle = match ipc_server.start_named_pipe("agentguard") {
    Ok(h) => h,
    Err(e) => { error!("IPC failed: {}", e); return Ok(()); }
};
```

Añadir constantes:

```rust
const IPC_PIPE_NAME: &str = "agentguard";
```

#### 8.2.3 Implementar Named Pipe client en CLI Windows

**Archivo:** `crates/agentguard-cli/src/main.rs:19-53`

Reemplazar `StubStream` con transporte real.

**Opción preferida:** usar el crate `interprocess` que ya es dependencia del
workspace y soporta `LocalSocketStream` en Windows (mapea a named pipes
automáticamente con el prefijo `\\.\pipe\`):

```rust
#[cfg(windows)]
mod transport {
    use interprocess::local_socket::LocalSocketStream;
    use std::io;
    use std::path::Path;

    pub fn connect(path: &Path) -> io::Result<LocalSocketStream> {
        LocalSocketStream::connect(path.to_str().unwrap_or(r"\\.\pipe\agentguard"))
    }
}
```

#### 8.2.4 Armonizar constantes IPC en common

**Archivo:** `crates/agentguard-common/src/lib.rs`

Añadir constante cross-platform:

```rust
#[cfg(unix)]
pub const IPC_DEFAULT_PATH: &str = ".agentguard/agentguard.sock";
#[cfg(windows)]
pub const IPC_DEFAULT_PATH: &str = r"\\.\pipe\agentguard";
```

### Gate 8.2

```
[ ] cargo build -p agentguard-windows -p agentguard-cli (0 errores)
[ ] En VM Windows: agentguard-windows.exe --service iniciado → \\.\pipe\agentguard existe
[ ] agentguard status → respuesta StatusData completa (no NotConnected)
[ ] agentguard ping → Pong
[ ] agentguard protect C:\test → OK
```

---

## 8.3 PEB introspección (cmdline + cwd)

### Situación actual

| Función | Archivo:Línea | Qué hace |
|---|---|---|
| `read_process_command_line()` | `guard.rs:665` | `None` (stub) |
| `read_process_cwd()` | `process_watcher.rs:211` | `String::new()` (stub, marcado TODO) |

Las estructuras PEB ya están definidas en `guard.rs:334-373` (`Peb`, `RtlUserProcessParameters`, `UnicodeString`), y `ReadProcessMemory` está wrappeado en `guard.rs:671-687` (`win32_read_process_mem`).

### Causa raíz

windows-rs v0.58 no expone `NtQueryInformationProcess`. Con v0.60+ (task 8.1.1),
`PROCESS_BASIC_INFORMATION` y `NtQueryInformationProcess` quedan disponibles en
`Win32::System::ProcessStatus`.

### Plan de implementación

#### 8.3.1 Implementar `read_process_command_line()`

**Archivo:** `crates/agentguard-windows/src/guard.rs:665-669`

```rust
pub fn read_process_command_line(process: HANDLE) -> Option<String> {
    // 1. NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, ...)
    //    → Obtener pbi.PebBaseAddress
    //
    // 2. ReadProcessMemory(peb_addr) → Peb struct
    //    → Peb.process_parameters → RtlUserProcessParameters*
    //
    // 3. ReadProcessMemory(process_params_addr, offsetof(command_line.Buffer), ...)
    //    → Leer solo el campo command_line de la struct remota
    //
    // 4. Convertir UTF-16 buffer → String
    //
    // 5. Retornar Some(cmdline)
}
```

#### 8.3.2 Implementar `read_process_cwd()`

**Archivo:** `crates/agentguard-windows/src/process_watcher.rs:211-215`

Misma técnica, leyendo `RtlUserProcessParameters.CurrentDirectory`:

```
// Reutilizar lógica de guard.rs o extraer helper común:
// fn read_unicode_string_remote(process: HANDLE, remote_ustr: *const UnicodeString) -> Option<String>
```

#### 8.3.3 Extraer helpers reutilizables a un módulo `helpers`

**Nuevo archivo:** `crates/agentguard-windows/src/helpers.rs`

```rust
#[cfg(windows)]
pub(crate) mod win32 {
    pub fn read_process_memory_safe(...) -> Option<Vec<u8>>
    pub fn remote_unicode_string(process: HANDLE, base: *const c_void,
        field_offset: usize) -> Option<String>
}
```

Refactorizar `guard.rs` y `process_watcher.rs` para usar estos helpers.

#### 8.3.4 Actualizar `scan_and_contain_agents()` para usar cmdline real

**Archivo:** `crates/agentguard-windows/src/guard.rs:786`

Actualmente la rama `None` fallback a `matches_agent_exe_only`. Con la
implementación real, `None` solo se alcanza en casos de error (proceso ya terminó,
ACCESS_DENIED). Mantener el fallback para esos casos.

#### 8.3.5 Actualizar ETW event_callback para usar cwd real

**Archivo:** `crates/agentguard-windows/src/process_watcher.rs:184`

```rust
// Antes
let cwd = read_process_cwd(process_id);

// Después: reutilizar helper de helpers.rs
let cwd = read_process_cwd_from_pid(process_id);
```

### Gate 8.3

```
[ ] cargo build -p agentguard-windows (0 errores)
[ ] Test unitario: cmdline de notepad.exe se lee correctamente
[ ] Test unitario: cwd de un proceso lanzado coincide con CreateProcess lpCurrentDirectory
[ ] Agent matching por argv funciona → "claude-code.exe --agent-mode" detectado
```

---

## 8.4 Tests E2E en Windows

### Situación actual

7 tests unitarios en `guard.rs` — todos son de matching cross-platform (funciones
puras, sin llamadas Win32). **0 tests que validen protecciones reales.**

### Plan de implementación

#### 8.4.1 Test: DENY ACEs bloquean operaciones reales

**Nuevo archivo:** `crates/agentguard-windows/tests/deny_aces.rs`

```rust
#[cfg(windows)]
#[tokio::test]
async fn deny_aces_prevent_file_deletion() { ... }

#[cfg(windows)]
#[tokio::test]
async fn deny_aces_prevent_directory_deletion() { ... }

#[cfg(windows)]
#[tokio::test]
async fn deny_aces_prevent_file_write() { ... }

#[cfg(windows)]
#[tokio::test]
async fn deny_aces_observed_rename() { ... }

#[cfg(windows)]
#[tokio::test]
async fn remove_protected_path_restores_access() { ... }

#[cfg(windows)]
#[tokio::test]
async fn deny_aces_inherit_to_subdirectories() { ... }
```

Tests requeridos:
- **Borrado de archivo:** `remove_file()` → `PermissionDenied`
- **Borrado de directorio:** `remove_dir()` → `PermissionDenied`
- **Escritura:** `File::create()` con write → `PermissionDenied`
- **Rename:** `rename()` dentro del dir protegido → observado por notify
- **remove_deny_aces:** Después de `remove_protected_path()`, el borrado funciona
- **Herencia:** Archivo creado en subdirectorio hereda ACEs

#### 8.4.2 Test: Job Objects contienen procesos

**Nuevo archivo:** `crates/agentguard-windows/tests/job_objects.rs`

```rust
#[cfg(windows)]
#[tokio::test]
async fn job_object_kills_on_close() { ... }

#[cfg(windows)]
#[tokio::test]
async fn job_object_die_on_unhandled_exception() { ... }
```

#### 8.4.3 Test: ETW detecta creación de procesos

**Nuevo archivo:** `crates/agentguard-windows/tests/etw_detection.rs`

```rust
#[cfg(windows)]
#[tokio::test]
async fn etw_detects_known_agent_spawn() { ... }

#[cfg(windows)]
#[tokio::test]
async fn etw_ignores_non_agent_process() { ... }
```

#### 8.4.4 Test: AppContainer sandbox aísla el proceso

```rust
#[cfg(windows)]
#[tokio::test]
async fn appcontainer_blocks_write_to_protected_path() { ... }

#[cfg(windows)]
#[tokio::test]
async fn appcontainer_allows_read_from_protected_path() { ... }
```

### Gate 8.4

```
[ ] En VM Windows 10/11: cargo test -p agentguard-windows → ≥15 tests pass
[ ] 6 tests de DENY ACEs pasan (bloqueo real)
[ ] 2 tests de Job Objects pasan
[ ] 2 tests de ETW pasan
[ ] 2 tests de AppContainer pasan
[ ] 3 tests de integración (daemon completo)
```

---

## 8.5 Installer + armonización de docs

### 8.5.1 Actualizar installer Windows

**Archivo:** `crates/agentguard-installer/src/main.rs:231-235`

Actualmente solo imprime un mensaje. Actualizar para:

```
install_windows():
  1. Detectar arquitectura (x86_64 / aarch64)
  2. Descargar agentguard-setup-{version}.exe de GitHub Releases
  3. Verificar SHA256
  4. Ejecutar el instalador Inno Setup con /VERYSILENT
```

#### 8.5.2 Verificar installer.iss existente

**Archivo:** `packaging/windows/installer.iss` (ya existe, 107 líneas)

Verificar que:
- Los paths de binarios apuntan a `target/release/` correcto
- `agentguard init --output` funciona como paso post-install
- El registro como servicio usa el nombre correcto

#### 8.5.3 Armonizar estado de Fase 4 en documentación

**Archivo:** `PlanDeImplementacion.md:237-253`

Actualizar `Fase 4` para reflejar estado real post-Fase 8:
- Marcar 4.8 (test E2E) como completado
- Añadir nota de tasks 8.1-8.5 como "completado en Fase 8"

**Archivo:** `AGENTS.md` (tabla de fases)

Unificar con `PlanDeImplementacion.md`. Actualizar conteo de tests.

**Archivo:** `state.md`

Marcar gaps de Windows como cerrados.

### Gate 8.5

```
[ ] cargo build -p agentguard-installer (0 errores)
[ ] En VM Windows: cargo run -p agentguard-installer → descarga e instala
[ ] PlanDeImplementacion.md y AGENTS.md consistentes en estado de Fase 4
[ ] state.md actualizado con gaps cerrados
```

---

## Verificación post-fase

```bash
# Build
cargo build --workspace --exclude agentguard-ebpf

# Tests (en Linux, los tests de Windows se compilan pero no ejecutan llamadas Win32)
cargo test --workspace --exclude agentguard-ebpf

# Clippy
cargo clippy --workspace --exclude agentguard-ebpf -- -D warnings

# No unwrap/expect/panic
grep -rn "\.unwrap\(\)\|\.expect(" crates/*/src  # 0 hits

# eBPF (sin cambios en esta fase, verificar que sigue compilando)
./scripts/build-ebpf.sh
```

### Métricas objetivo post-fase 8

| Métrica | Antes | Después |
|---|---|---|
| Tests agentguard-windows | 7 | ≥20 |
| AppContainer sandbox | STUB | Funcional |
| CLI Windows ↔ daemon | Roto | Funcional |
| PEB cmdline | STUB | Funcional |
| PEB cwd | STUB (TODO) | Funcional |
| Instalador Windows | Mensaje placeholder | Descarga + install |

---

## Riesgos específicos de Fase 8

| Riesgo | Probabilidad | Mitigación |
|---|---|---|
| **windows-rs 0.60 breaking changes** | Media | Revisar CHANGELOG de windows-rs; compilar `guard.rs` primero (usa más APIs Win32) |
| **AppContainer requiere Windows 10 build 15063+** | Baja | Detectar versión en `check_capabilities()` y degradar a `monitor` |
| **PEB lectura falla en procesos 32-bit desde 64-bit** | Media | Usar `Wow64SuspendThread` + `NtQueryInformationProcess(ProcessWow64Information)` si es necesario |
| **Named Pipes requieren permisos de admin para `\\.\pipe\`** | Baja | El daemon ya corre como SYSTEM/Admin. Verificar que usuarios no-admin pueden conectar. |
| **interprocess crate no soporta named pipes bien** | Media | Si falla, implementar manualmente con `CreateFileW` + `WaitNamedPipeW` sin dependencia extra |

---

## Orden de ejecución recomendado

```
8.1.1 (actualizar windows-rs)
  │
  ├─► 8.3.1 + 8.3.2 + 8.3.3 (PEB: depende de v0.60)
  │
  ├─► 8.1.2 + 8.1.3 + 8.1.4 (AppContainer: depende de v0.60)
  │
  └─► 8.2.1 + 8.2.2 + 8.2.3 + 8.2.4 (Named Pipes: independiente)
        │
        └─► 8.4 (Tests: depende de todo lo anterior)
              │
              └─► 8.5 (Docs/installer: no tiene dependencias técnicas)
```
