# WINDOWSEC.md — Especificación del backend Windows de AgentGuard

> **Versión:** 1.0 — **Fase 4** (en desarrollo)
> **Stack:** Rust edition 2021 + `windows-rs` 0.58 + `notify` 6 + `tokio`
> **Protección estimada:** ~95% sin driver kernel firmado

---

## Índice

1. [Arquitectura general](#1-arquitectura-general)
2. [Modelo de seguridad](#2-modelo-de-seguridad)
3. [NTFS DENY ACEs](#3-ntfs-deny-aces)
4. [Job Objects](#4-job-objects)
5. [Detección de procesos agente](#5-detección-de-procesos-agente)
6. [Eventos de filesystem](#6-eventos-de-filesystem-readdirectorychangesw)
7. [IPC via Named Pipes](#7-ipc-via-named-pipes)
8. [Windows Service](#8-windows-service)
9. [DP y configuración](#9-dp-y-configuración)
10. [Instalador y distribución](#10-instalador-y-distribución)
11. [Limitaciones y riesgos](#11-limitaciones-y-riesgos)
12. [Comparativa con Linux/eBPF](#12-comparativa-con-linuxebpf)
13. [Roadmap Fase 4](#13-roadmap-fase-4)

---

## 1. Arquitectura general

```
┌─────────────────────────────────────────────────────────────┐
│                    KERNEL SPACE (NTFS)                       │
│                                                             │
│  NTFS Driver aplica DENY ACEs en ACL de cada directorio     │
│  └─ Operaciones denegadas: DELETE, FILE_DELETE_CHILD,       │
│     FILE_WRITE_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES,  │
│     WRITE_DAC, WRITE_OWNER                                  │
│  └─ ACEs heredadas a subdirectorios y archivos              │
│  └─ Aplicadas por SYSTEM — el usuario NO puede quitarlas    │
│                                                             │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                   USER SPACE                                 │
│                                                             │
│  agentguard-windows.exe (SYSTEM / Administrator)            │
│    ├─ WindowsGuard──────────────────────────────────────    │
│    │   ├─ NTFS DENY ACEs    → SetNamedSecurityInfoW         │
│    │   ├─ Job Objects       → CreateJobObjectW              │
│    │   ├─ Process Detection → CreateToolhelp32Snapshot      │
│    │   └─ File Watcher      → ReadDirectoryChangesW/notify  │
│    ├─ DLP Proxy (HTTP/HTTPS MITM)                           │
│    ├─ Vault (snapshots BLAKE3)                              │
│    ├─ IPC Server (Named Pipe)                               │
│    └─ Event Loop (tokio::select!)                            │
│                                                             │
│  agentguard-cli.exe (cualquier usuario)                     │
│    └─ Conecta al daemon via Named Pipe                      │
└─────────────────────────────────────────────────────────────┘
```

### Flujo de una violación

```
Agente AI intenta DeleteFile("C:\Users\nini\Docs\importante.md")
    │
    ▼
NTFS Driver verifica la DACL del directorio
    │
    ├─ ¿Hay DENY ACE para el usuario actual?
    │       │
    │       └─ SÍ → ERROR_ACCESS_DENIED (0x5)
    │              La operación se DENIEGA en kernel.
    │              El agente NO puede modificar la ACE
    │              porque el owner de la ACE es SYSTEM.
    │
    └─ NO → Permite la operación
              │
              ▼
         ReadDirectoryChangesW notifica al daemon
              │
              ▼
         Daemon emite SecurityEvent::FileViolation
              │
              ▼
         Si on_violation.snapshot_on_violation → snapshot reactivo
```

---

## 2. Modelo de seguridad

### Threat model

| Atacante | Mecanismo | Efectividad |
|---|---|---|
| Proceso agente AI (usuario normal) | NTFS DENY ACEs + Job Object | ~95% |
| Proceso agente AI (Admin) | Job Object + detección | ~70% |
| Proceso agente AI (SYSTEM) | Solo detección post-hoc | ~10% |
| Malware con driver kernel | Nada (sin driver firmado) | 0% |
| Arranque desde otro OS | Nada (fuera de scope) | 0% |

### Lo que SÍ protege

- **DELETE** — borrar archivos en directorios protegidos
- **FILE_DELETE_CHILD** — borrar subdirectorios
- **FILE_WRITE_DATA** — modificar contenido
- **FILE_WRITE_EA** — modificar atributos extendidos
- **FILE_WRITE_ATTRIBUTES** — modificar atributos (readonly, hidden, etc.)
- **WRITE_DAC** — cambiar los permisos del directorio
- **WRITE_OWNER** — cambiar el propietario

### Lo que NO protege

- **Lectura** — el agente puede leer archivos. Es intencionado; AgentGuard protege contra DESTRUCCIÓN/EXFILTRACIÓN, no contra lectura local.
- **Ejecución** — el agente puede ejecutar binarios en directorios protegidos.
- **Creación de archivos** — el agente puede crear nuevos archivos en la zona (se detecta via watcher).
- **Renombrar hacia fuera de la zona** — el rename de `zona/file.md` a `otra-parte/file.md` no es interceptado por las ACEs (que están en el directorio origen, no en el destino). Se detecta via watcher post-hoc.
- **Procesos con token de Admin/SYSTEM** — pueden modificar las ACEs. El Job Object contiene pero no previene.

### Nivel de confianza

El backend declara `ProtectionLevel::KernelDenial` porque el driver NTFS aplica las ACEs a nivel de kernel. Esto es correcto: una DENY ACE aplicada por SYSTEM no puede ser removida por un proceso del mismo usuario sin privilegios de administrador. Sin embargo, a diferencia de Linux/eBPF —que intercepta la syscall en el kernel en tiempo real—, las ACEs solo previenen las operaciones que pasan por el DACL check de NTFS. Un rename o un hardlink seguido de unlink pueden eludirlas en ciertos casos.

---

## 3. NTFS DENY ACEs

### Visión general

El daemon (corriendo como SYSTEM o Administrator) aplica Access Control Entries de tipo DENY en la Discretionary Access Control List (DACL) de cada directorio protegido. Las ACEs se heredan automáticamente a subdirectorios y archivos (`SUB_CONTAINERS_AND_OBJECTS_INHERIT`).

El usuario objetivo se identifica obteniendo el SID del proceso actual via `OpenProcessToken(GetCurrentProcess())` seguido de `GetTokenInformation(TOKEN_USER)`. En producción, el daemon corre como SYSTEM y aplica las ACEs para el usuario interactivo (el que ejecuta al agente AI), obteniendo su SID via `LookupAccountNameW`.

### Permisos denegados

```rust
const DENY_PERMISSIONS: u32 = DELETE              // 0x00010000
    | FILE_DELETE_CHILD                             // 0x00000040
    | FILE_WRITE_DATA                               // 0x00000002
    | FILE_WRITE_EA                                 // 0x00000010
    | FILE_WRITE_ATTRIBUTES                         // 0x00000100
    | WRITE_DAC                                     // 0x00040000
    | WRITE_OWNER;                                  // 0x00080000
```

Total: 7 permisos denegados. Intencionadamente se excluyen:
- `READ_CONTROL` — necesario para que el agente pueda verificar sus propios permisos
- `FILE_READ_DATA` — el agente debe poder leer para trabajar
- `FILE_EXECUTE` — el agente puede necesitar ejecutar herramientas
- `SYNCHRONIZE` — necesario para operaciones de sincronización de handles

### Flujo de apply

1. `std::fs::canonicalize(path)` — resuelve symlinks, normaliza a ruta absoluta
2. `GetNamedSecurityInfoW(DACL_SECURITY_INFORMATION)` — obtiene la DACL actual
3. `get_current_user_sid()` — obtiene el SID vía `OpenProcessToken` + `GetTokenInformation(TOKEN_USER)`
4. Construye `TRUSTEE_W { TrusteeForm: TRUSTEE_IS_SID, ptstrName: sid_ptr }`
5. Construye `EXPLICIT_ACCESS_W { grfAccessPermissions: DENY_PERMISSIONS, grfAccessMode: DENY_ACCESS, grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT }`
6. `SetEntriesInAclW(&[ea], old_dacl, &mut new_dacl)` — merge de la ACE con la DACL existente
7. `SetNamedSecurityInfoW(DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, ..., new_dacl)` — aplica la nueva DACL
8. `LocalFree` de los buffers devueltos por las APIs

### Flujo de remove

1. Obtiene la DACL actual (`GetNamedSecurityInfoW`)
2. Si `ERROR_ACCESS_DENIED` → skip (el directorio ya no es accesible)
3. Construye `EXPLICIT_ACCESS_W` con `grfAccessMode: REVOKE_ACCESS` (mismos permisos que se denegaron)
4. `SetEntriesInAclW` — elimina las ACEs de AgentGuard de la DACL
5. `SetNamedSecurityInfoW` — aplica la DACL limpia
6. `LocalFree` de buffers

### Obtención del SID del usuario

```rust
fn get_current_user_sid() -> Result<Vec<u16>, String> {
    // 1. OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)
    // 2. GetTokenInformation(token, TOKEN_USER, buf, size)
    // 3. token_user.User.Sid → copiar bytes a Vec<u16>
    // 4. CloseHandle(token)
}
```

### Consideraciones

- **Canonicalización**: `canonicalize` resuelve symlinks y da paths absolutos. Si el sistema tiene symlinks/junctions en la zona protegida, la ACE se aplica al destino real.
- **Memoria**: `LocalFree` es obligatorio para los buffers devueltos por `GetNamedSecurityInfoW` y `SetEntriesInAclW`. El código hace 3 releases en apply y 2 en remove.
- **PROTECTED_DACL_SECURITY_INFORMATION**: se usa junto con `DACL_SECURITY_INFORMATION` para evitar que ACEs heredadas de padres sobrescriban las DENY ACEs.
- **Non-UTF8 paths**: `Path::to_str()` falla para paths con caracteres no-UTF8 (raro en Windows moderno pero posible). Se maneja con error.

---

## 4. Job Objects

### Visión general

Cuando se detecta un proceso que coincide con los patrones de agente AI, se le asigna a un Job Object con restricciones. Si el daemon muere, el Job Object se destruye y todos los procesos contenidos son terminados automáticamente (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).

### Creación del Job Object

```rust
fn create_restricted_job() -> Result<HANDLE, GuardError> {
    let job = CreateJobObjectW(None, None)?;
    let limits = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        LimitFlags:
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE       // Si el daemon muere → matar procesos
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION // Crash → matar
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,       // Limitar número de procesos
        ActiveProcessLimit: 1,                       // Solo 1 proceso en el job
        // Resto de campos en 0 (sin límites adicionales)
        ..
    };
    SetInformationJobObject(job, JobObjectBasicLimitInformation, &limits, size_of_val(&limits))?;
    Ok(job)
}
```

### Límites aplicados

| Límite | Valor | Efecto |
|---|---|---|
| `KILL_ON_JOB_CLOSE` | Activado | Si el daemon se cierra, todos los procesos en el job mueren |
| `DIE_ON_UNHANDLED_EXCEPTION` | Activado | Si el proceso crashea (panic, segfault), muere en vez de mostrar diálogo de error |
| `ActiveProcessLimit` | 1 | Solo 1 proceso puede estar en el job a la vez |

### Asignación de procesos

```rust
fn contain_process(job: HANDLE, pid: u32) -> Result<(), String> {
    let process = OpenProcess(
        PROCESS_SET_QUOTA | PROCESS_TERMINATE,  // permisos mínimos
        false,                                    // no heredable
        pid,
    )?;
    AssignProcessToJobObject(job, process)?;
    CloseHandle(process);
    Ok(())
}
```

### Notas

- **Un proceso por job**: `ActiveProcessLimit=1` significa que cada agente AI detectado necesita su propio Job Object. En la implementación actual se usa un solo job global para todos los procesos, lo cual puede fallar al intentar asignar un segundo proceso. **Pendiente**: crear un job por proceso agente.
- **Sin límites de recursos**: no se aplican límites de CPU, RAM, o I/O porque el objetivo es contención de seguridad, no limitación de recursos.
- **Procesos hijo**: si el agente crea procesos hijo, heredan la membresía del Job Object (comportamiento por defecto de Windows).

---

## 5. Detección de procesos agente

### Mecanismo

Cada 5 segundos (`PROCESS_SCAN_INTERVAL_MS = 5_000`), se toma un snapshot del sistema y se itera sobre todos los procesos para encontrar los que coinciden con los patrones de agente configurados en `config.toml`.

### Flujo

```
tokio::spawn(async loop {
    1. sleep(5s)
    2. CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
    3. Process32FirstW + Process32NextW en bucle
    4. Para cada proceso:
       a. Extraer szExeFile (nombre del .exe)
       b. matches_agent(patterns, exe_name)?
       c. Si match y no tracked → contain_process(job, pid)
    5. CloseHandle(snapshot)
    6. Limpiar tracked_pids: OpenProcess(PROCESS_QUERY_INFORMATION)
       para cada PID → si falla, proceso ya terminó → removemos
})
```

### Algoritmo de matching

```rust
fn matches_agent(patterns: &[AgentProcess], exe_name: &str) -> bool {
    let lower = exe_name.to_lowercase();
    patterns.iter().any(|p| {
        // Match por nombre principal
        lower.contains(&p.name.to_lowercase())
        // Match por nombres alternativos de ejecutable
        || p.r#match.exe_any.iter().any(|e| {
            lower.contains(&e.to_lowercase())
        })
    })
}
```

### Configuración de patrones

```toml
# En config.toml (sección global)
[[agent_processes]]
name = "claude"                    # Match "claude.exe", "claude-code.exe", etc.
match.exe = "Claude.exe"           # (opcional) match exacto
match.exe_any = ["code.exe", "cursor.exe"]  # Alternativas
match.argv_contains_any = ["--agent"]       # (no implementado)
match.env_has = "COPILOT_AGENT=1"           # (no implementado)
```

### CSV

| Patrón | Coincide con |
|---|---|
| `cursor` | cursor.exe, Cursor.exe, CursorAI.exe |
| `claude` | claude.exe, claude-code.exe, claude-internal.exe |
| `code` | code.exe, code-insiders.exe, Code - Insiders.exe |
| `copilot` | copilot.exe, GitHubCopilot.exe |

### Pendiente (Fase 4.2 completa)

- [ ] Matching por `argv_contains_any` — escanear la línea de comandos del proceso
- [ ] Matching por `env_has` — verificar variables de entorno del proceso
- [ ] Lista de exclusión (`agent_exclude`) — procesos que nunca deben contenerse
- [ ] Soporte para `match.exe` (ruta exacta, no substring)

---

## 6. Eventos de filesystem (ReadDirectoryChangesW)

### Mecanismo

Windows no tiene `inotify` ni `fanotify`. En su lugar se usa `ReadDirectoryChangesW` a través de la crate `notify` (v6) con watcher recomendado para la plataforma.

### Flujo

```rust
let (notify_tx, notify_rx) = std::sync::mpsc::channel();
let mut watcher = notify::recommended_watcher(move |res| {
    let _ = notify_tx.send(res);
})?;

for path in &paths {
    watcher.watch(path, notify::RecursiveMode::Recursive)?;
}

// En un task separado (spawn_blocking porque notify es sync)
while let Ok(res) = notify_rx.recv() {
    match res {
        Ok(event) => {
            for ev in translate_notify_event(event) {
                watch_tx.blocking_send(ev)?;
            }
        }
        Err(e) => warn!(...),
    }
}
```

### Traducción de eventos

| Evento `notify` | `ViolationKind` |
|---|---|
| `EventKind::Remove(RemoveKind::File)` | `DeleteAttempt` |
| `EventKind::Remove(RemoveKind::Folder)` | `DeleteAttempt` |
| `EventKind::Modify(ModifyKind::Name(_))` | `RenameAttempt` |
| `EventKind::Modify(ModifyKind::Data(_))` | `WriteAttempt` |
| `EventKind::Create(_)` | `CreateAttempt` |
| Otros | Ignorados |

### Limitaciones de ReadDirectoryChangesW

1. **Post-hoc**: detecta el evento DESPUÉS de que ocurre. No puede denegar la operación.
2. **Buffer overflow**: si se generan más eventos de los que el buffer puede contener, se pierden. `notify` maneja esto emitiendo un evento `Rescan`.
3. **No informa PID**: `ReadDirectoryChangesW` no incluye el PID del proceso que causó el cambio. El campo `pid` en los eventos será 0 y `process` será `"<unknown>"`. Para obtener esta info en Windows se necesitaría ETW tracing o un minifilter driver.
4. **No distingue entre usuarios**: si múltiples procesos modifican el mismo directorio, no se sabe cuál fue.
5. **Dependencia de `notify`**: la crate abstrae diferencias entre macOS/Linux/Windows pero añade overhead.

---

## 7. IPC via Named Pipes

### Estrategia

En Linux/macOS se usa Unix Domain Socket. En Windows no existe equivalente nativo, así que hay dos opciones:

1. **Named Pipes** (`\\.\pipe\agentguard-{USERNAME}`): nativo de Windows, seguro, soporta ACLs
2. **Unix Domain Sockets en Windows 10+**: disponible desde build 17063. Requiere Windows 10 1803+.

### Implementación actual

La implementación actual en `main.rs` usa Unix Domain Sockets en el directorio temporal:

```rust
let ipc_socket_path = std::env::temp_dir().join(format!("agentguard-{user}.sock"));
```

Esto funciona en Windows 10 build 17063+ gracias al soporte nativo de `AF_UNIX` que Microsoft añadió. El daemon usa `IpcServer` de `agentguard-core` que internamente usa `UnixListener`.

### Paths

| Modo | Pipe path |
|---|---|
| Elevated (SYSTEM) | `%TEMP%\agentguard-{USERNAME}.sock` |
| User | `%TEMP%\agentguard-{USERNAME}.sock` |

### Seguridad del pipe

**Pendiente**: la implementación actual no configura ACLs en el socket Unix. En producción, debería:
1. Usar Named Pipes con `PIPE_ACCESS_INBOUND` + `FILE_FLAG_FIRST_PIPE_INSTANCE`
2. Configurar DACL para permitir solo al usuario propietario
3. O usar Unix socket con `chmod` equivalente via `SetSecurityInfo`

---

## 8. Windows Service

### Requisito de elevación

El daemon DEBE correr como SYSTEM o Administrator elevado para poder:
1. Aplicar `SetNamedSecurityInfoW` (requiere `WRITE_DAC` sobre el directorio)
2. Crear Job Objects con `KILL_ON_JOB_CLOSE`
3. Abrir otros procesos con `PROCESS_SET_QUOTA` para `AssignProcessToJobObject`

### Detección de elevación

```rust
fn is_elevated() -> bool {
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
    GetTokenInformation(token, TokenElevation, &mut elevation, size, &mut size)?;
    elevation.TokenIsElevated != 0
}
```

### Modos de operación

| Modo | Elevado | Paths | Efectividad |
|---|---|---|---|
| **Servicio SYSTEM** | Sí | `C:\ProgramData\AgentGuard\` | ~95% |
| **Admin CLI** | Sí | `C:\ProgramData\AgentGuard\` | ~95% |
| **Usuario normal** | No | `~\.agentguard\` | ~5% (solo watcher + DLP) |

### Instalación como servicio

```powershell
# Registrar el servicio (desde instalador)
sc.exe create AgentGuard `
    binPath= "C:\Program Files\AgentGuard\agentguard-windows.exe" `
    start= auto `
    type= own `
    obj= LocalSystem

# Iniciar
sc.exe start AgentGuard
```

### Service Control Handler

**Pendiente**: implementar el handler de SCM para responder a `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_PAUSE`, `SERVICE_CONTROL_CONTINUE`. Esto requiere usar la crate `windows-service` o implementar `RegisterServiceCtrlHandlerExW` manualmente. Actualmente el daemon solo responde a Ctrl+C, no a señales de SCM.

### Señales

| Señal | Implementado | Acción |
|---|---|---|
| Ctrl+C | ✓ | Graceful shutdown: cierra pipe, libera handles |
| SERVICE_CONTROL_STOP | ✗ (pendiente) | Graceful shutdown via SCM |
| SIGTERM/SIGINT | ✗ (no existe en Windows) | N/A |

---

## 9. DP y configuración

### Paths por modo de ejecución

| Recurso | Elevated (SYSTEM) | Usuario normal |
|---|---|---|
| Config | `C:\ProgramData\AgentGuard\config.toml` | `~\.agentguard\config.toml` |
| Vault | `C:\ProgramData\AgentGuard\vault\` | `~\.agentguard\vault\` |
| CA cert + key | `C:\ProgramData\AgentGuard\ca\` | `~\.agentguard\ca\` |
| Incidents log | `C:\ProgramData\AgentGuard\incidents.jsonl` | `~\.agentguard\incidents.jsonl` |
| IPC socket | `%TEMP%\agentguard-{USERNAME}.sock` | `%TEMP%\agentguard-{USERNAME}.sock` |

### Determinación del modo

```rust
fn default_config_path() -> PathBuf {
    if is_elevated() {
        PathBuf::from(r"C:\ProgramData\AgentGuard\config.toml")
    } else {
        dirs::home_dir().join(".agentguard").join("config.toml")
    }
}
```

### Estructura del directorio `C:\ProgramData\AgentGuard\`

```
C:\ProgramData\AgentGuard\
├── config.toml
├── incidents.jsonl
├── ca\
│   ├── root-cert.pem     (permisos: SYSTEM+R, Admin+R)
│   └── root-key.pem      (permisos: SYSTEM+RW, Admin nada)
└── vault\
    └── {snapshot-uuid}\
        ├── manifest.json
        └── {blake3-hash}  (archivos con nombre = hash BLAKE3)
```

### Configuración DLP en Windows

```toml
# En config.toml de Windows
[dlp]
enabled = true
proxy_port = 7771

[on_violation]
snapshot_on_violation = true
```

Los agentes AI deben configurarse para usar el proxy:
```powershell
$env:HTTP_PROXY = "http://127.0.0.1:7771"
$env:HTTPS_PROXY = "http://127.0.0.1:7771"
```

---

## 10. Instalador y distribución

### Estrategia de instalación

```
Usuario ejecuta:  irm https://get.agentguard.io | iex
    │
    ▼
install.ps1 detecta arquitectura (x64/arm64)
    │
    ▼
Descarga de GitHub Releases:
    ├── agentguard-cli.exe      (cross-platform, ~5 MB)
    └── agentguard-windows.exe  (Windows daemon, ~8 MB)
    │
    ▼
Verifica SHA256 checksum (contra el manifest JSON del release)
    │
    ▼
Copia binarios a C:\Program Files\AgentGuard\
    │
    ▼
Ejecuta como Admin:
    sc.exe create AgentGuard `
        binPath= "C:\Program Files\AgentGuard\agentguard-windows.exe" `
        start= auto
    │
    ▼
Genera config.toml con `agentguard init --defaults`
    │
    ▼
Añade CA root al trust store:
    certutil -addstore -f "ROOT" "C:\ProgramData\AgentGuard\ca\root-cert.pem"
    │
    ▼
Listo: agentguard status
```

### Inno Setup installer

```iss
; packaging/windows/installer.iss (PENDIENTE — Fase 4.6)
[Setup]
AppName=AgentGuard
AppVersion=0.2.0
DefaultDirName={pf}\AgentGuard
DefaultGroupName=AgentGuard
PrivilegesRequired=admin

[Files]
Source: "agentguard-windows.exe"; DestDir: "{app}"
Source: "agentguard-cli.exe"; DestDir: "{app}"

[Run]
Filename: "sc.exe"; Parameters: "create AgentGuard binPath= ""{app}\agentguard-windows.exe"" start= auto"; StatusMsg: "Registrando servicio..."
Filename: "sc.exe"; Parameters: "start AgentGuard"; StatusMsg: "Iniciando servicio..."
Filename: "{app}\agentguard-cli.exe"; Parameters: "init --defaults"; StatusMsg: "Generando configuración..."

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop AgentGuard"; StatusMsg: "Deteniendo servicio..."
Filename: "sc.exe"; Parameters: "delete AgentGuard"; StatusMsg: "Eliminando servicio..."
Filename: "certutil.exe"; Parameters: "-delstore ROOT ""AgentGuard DLP Local Root CA"""; StatusMsg: "Eliminando CA..."
```

### Requisitos de firma de código

Para distribución pública en Windows:

| Elemento | Requiere firma | Certificado |
|---|---|---|
| instalador .exe | Sí (SmartScreen) | EV Code Signing (~$300/año) |
| agentguard-windows.exe | Sí (SmartScreen) | EV Code Signing |
| agentguard-cli.exe | Sí (SmartScreen) | EV Code Signing |
| instalador .msi | Recomendado | EV Code Signing |

Sin firma EV, Windows SmartScreen muestra "Windows protected your PC" y el usuario debe hacer clic en "More info" → "Run anyway". Esto reduce drásticamente la tasa de instalación.

### CI/CD para Windows

```yaml
# .github/workflows/ci.yml (job windows)
build-windows:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo build --release -p agentguard-windows -p agentguard-cli
    - run: cargo test -p agentguard-windows -p agentguard-cli
    - name: Sign binaries
      run: signtool sign /fd SHA256 /f cert.pfx /p ${{ secrets.PFX_PASSWORD }} *.exe
    - uses: actions/upload-artifact@v4
```

---

## 11. Limitaciones y riesgos

### Limitaciones conocidas

| # | Limitación | Impacto | Mitigación |
|---|---|---|---|
| 1 | Sin driver kernel | No se interceptan syscalls en tiempo real. Dependencia total de NTFS ACLs. | Job Objects + watcher como capas adicionales. |
| 2 | `ReadDirectoryChangesW` post-hoc | No deniega operaciones, solo observa. | Las DENY ACEs SON la capa de denegación real. El watcher es solo para alertas. |
| 3 | PID desconocido en eventos | Los eventos `FileViolation` reportan `pid=0` y `process="<unknown>"`. | ETW tracing o minifilter driver en versión futura. |
| 4 | `rename` fuera de zona | Si el archivo se renombra a un path fuera de la zona protegida, el rename en el destino no tiene ACE de denegación. | El watcher detecta el rename (origen). Snapshot reactivo mitiga el daño. |
| 5 | `hardlink + delete` | Crear hardlink en otra ubicación y luego borrar el original elude ACEs en el directorio protegido. | El watcher detecta el delete. Snapshot reactivo recupera. |
| 6 | Un solo Job Object | Con `ActiveProcessLimit=1`, un segundo agente AI no puede ser contenido. | Pendiente: crear un job por proceso. |
| 7 | Sin detección por argv/env | Solo se matchea por nombre de ejecutable. Un agente renombrado no se detecta. | Pendiente: implementar `argv_contains_any` y `env_has`. |
| 8 | El usuario Admin puede quitar ACEs | Si el agente corre como Admin, puede usar `icacls /reset`. | Muy raro — los agentes AI típicamente corren como usuario normal. |
| 9 | Sin auto-updater en Windows | Fase 7 no implementada. | El usuario debe descargar manualmente nuevas versiones. |

### Riesgos de seguridad

| Riesgo | Severidad | Probabilidad | Plan |
|---|---|---|---|
| Malware con driver kernel desactiva NTFS | Crítica | Baja | Fuera de scope para v1. Requiere ELAM driver + Microsoft signing. |
| Agente AI descubre que está en un Job Object y usa `CreateProcess` con `CREATE_BREAKAWAY_FROM_JOB` | Alta | Media | `JOB_OBJECT_LIMIT_BREAKAWAY_OK` NO está seteado. |
| Agente AI usa `token stealing` para ejecutar como SYSTEM | Crítica | Baja | Requiere SeDebugPrivilege, que el usuario normal no tiene. |
| Buffer overflow en `ReadDirectoryChangesW` | Media | Baja | `notify` maneja el evento `Rescan`. Aumentar buffer size en producción. |
| IPC socket accesible por otros usuarios | Alta | Media | Pendiente: configurar DACL en el socket. |

---

## 12. Comparativa con Linux/eBPF

| Característica | Linux (eBPF) | Windows (NTFS ACEs) |
|---|---|---|
| **Nivel de protección** | Kernel-level — intercepta syscalls | Kernel-level — driver NTFS aplica ACEs |
| **Denegación en tiempo real** | ✓ (hook LSM retorna -EPERM) | ✓ (NTFS deniega en el driver) |
| **Identificación del proceso** | ✓ (`bpf_get_current_pid_tgid`, `bpf_get_current_comm`) | ✗ (PID desconocido en watcher) |
| **Eventos asíncronos** | Ring buffer (eficiente, ~1MB) | `ReadDirectoryChangesW` (buffer limitado) |
| **Overhead CPU idle** | < 0.1% | < 0.5% (watcher + scan periódico) |
| **RAM idle** | < 10 MB | ~15 MB (Windows overhead) |
| **Dependencias** | Kernel ≥ 5.7, `CONFIG_BPF_LSM=y` | Windows 10 build 19044+, NTFS |
| **Firma requerida** | No (BPF en kernel propio) | Sí (EV cert para distribución) |
| **Mecanismo de contención** | eBPF LSM hooks | Job Objects |
| **Detección de agentes** | `bpf_get_current_comm` en kernel | `CreateToolhelp32Snapshot` cada 5s |
| **Fallback** | `notify` userspace si no BPF LSM | Solo NTFS ACEs (sin fallback watcher) |
| **Protección contra Admin** | Parcial (Admin puede descargar BPF) | No (Admin puede quitar ACEs) |
| **Arranque** | < 500ms | < 1s |
| **Latencia de detección** | < 50ms | 0ms (denegación) / 5s (detección) |

---

## 13. Roadmap Fase 4

Basado en `PlanDeImplementacion.md` §Fase 4 y el estado actual del código.

### Completado ✓

| Tarea | Estado | Descripción |
|---|---|---|
| 4.1 `guard.rs` | ✓ | `WindowsGuard` con `SetNamedSecurityInfoW` (DENY ACEs). Apply + remove. `KernelGuard` trait implementado. |
| 4.2 Detección de procesos | ✓ Parcial | `CreateToolhelp32Snapshot` + iteración + matching. Falta argv/env. |
| 4.3 Job Objects | ✓ Parcial | `CreateJobObjectW` + `SetInformationJobObject` + `AssignProcessToJobObject`. Falta job por proceso. |
| `main.rs` | ✓ | Entry point completo: config, vault, CA, guard, DLP, IPC, event loop, graceful shutdown. |
| CI/CD | ✓ | Workspace compila en Windows via `windows-rs` 0.58. |

### Pendiente □

| Tarea | Prioridad | Descripción |
|---|---|---|
| 4.4 Windows Service | Alta | Integrar `RegisterServiceCtrlHandlerExW` en `main.rs`. Responder a `SERVICE_CONTROL_STOP`. |
| 4.5 Release build | Alta | `cargo build --release -p agentguard-windows` funcional. Binario standalone. |
| 4.6 Inno Setup installer | Alta | `packaging/windows/installer.iss`. Instala servicio, CA en trust store, config defaults. |
| 4.7 Test E2E en VM | Alta | VM Windows 10/11 → instalar → proteger carpeta → intentar borrar → Access Denied. |
| Matching por argv/env | Media | Implementar `argv_contains_any` y `env_has` en `matches_agent`. |
| Job por proceso | Media | En vez de un solo job global, crear un Job Object por cada agente detectado. |
| ETW integration | Baja | `OpenTraceW` + `StartTraceW` para obtener PID en eventos de filesystem. |
| ACL en IPC socket | Media | `SetSecurityInfo` en el Named Pipe para restringir acceso. |
| System tray icon | Baja | Icono en la bandeja del sistema (parte de Fase 6, UI Tauri). |

### Criterio de finalización (Gate)

> En Windows 10/11, instalar AgentGuard → proteger una carpeta → intentar borrar un archivo dentro → **Access Denied**.
> El daemon corre como servicio SYSTEM y sobrevive reinicios. La CLI (`agentguard status`) reporta la protección activa.

---

## Referencias

- `crates/agentguard-windows/src/guard.rs` — Implementación completa del backend (738 líneas)
- `crates/agentguard-windows/src/main.rs` — Entry point del daemon (413 líneas)
- `crates/agentguard-core/src/guard.rs` — Trait `KernelGuard`
- `crates/agentguard-core/src/events.rs` — `SecurityEvent` y `ViolationKind`
- `crates/agentguard-core/src/config.rs` — `Config`, `AgentProcess`, `AgentMatch`
- `README.md` §7 — Especificación original del guard Windows
- `PlanDeImplementacion.md` §Fase 4 — Tareas y gates
- [Microsoft: SetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
- [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Microsoft: ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)
