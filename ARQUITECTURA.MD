# AgentGuard — Arquitectura Real (v1.0)

> Estado: Producción-ready para Linux + Windows · 124 tests · 0 warnings  
> Última actualización: Mayo 2026

---

## 1. Visión

AgentGuard protege al usuario de agentes IA no controlados interceptándolos en el kernel
antes de que ejecuten su primer opcode, o detectándolos vía `/proc` y aplicando sandbox
automático. Sin config manual — funciona out of the box.

**Principios:**
- **Fail-open**: si algo falla, el sistema sigue funcionando (no bloquea al usuario)
- **Degradación elegante**: sin root → userspace fallback (detecta pero no bloquea)
- **Zero overhead**: las restricciones se aplican en `exec()`. En steady state no hay overhead

---

## 2. Diagrama de Componentes

```
┌──────────────────────────────────────────────────────────────┐
│                     USUARIO                                   │
│  agentguard status | protect | pause | snapshot | incidents  │
└─────────────────────┬────────────────────────────────────────┘
                      │ IPC (JSON-line)
    ┌─────────────────┼──────────────────┐
    │                 ▼                  │
    │  ┌──────────────────────────┐     │
    │  │     agentguard-cli       │     │  agentguard-tui
    │  │   (clap + serde_json)    │     │  (ratatui + crossterm)
    │  └────────────┬─────────────┘     │
    │               │                   │
    ▼               ▼                   ▼
┌──────────────────────────────────────────────────────────────┐
│                    agentguard-core                            │
│  Config │ Vault(BLAKE3) │ DLP Proxy │ CA │ IPC Server        │
│  Events │ KernelGuard trait │ Updater                        │
└──────────────┬───────────────────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
    ▼                     ▼
┌───────────────┐  ┌──────────────────┐
│ agentguard-   │  │ agentguard-      │
│ linux         │  │ windows          │
│               │  │                  │
│ Guard backends│  │ Guard backends   │
│ ├─ EbpfGuard  │  │ └─ WindowsGuard  │
│ └─ Userspace  │  │    (NTFS DENY    │
│                │  │     ACEs + Job   │
│ Sandbox       │  │     Objects)     │
│ ├─ bwrap      │  │                  │
│ └─ Landlock   │  │ Sandbox          │
│                │  │ └─ AppContainer  │
│ Process       │  │    (userenv.dll) │
│ Watcher (eBPF)│  │                  │
│ Agent Scanner │  │ Process Watcher  │
│ (/proc)       │  │ (ETW + sysinfo)  │
└───────┬───────┘  └──────────────────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│              agentguard-ebpf                  │
│  file_guard: 12 LSM hooks + bprm_check_sec  │
│  net_guard: socket_connect (NET_RESTRICT)    │
│  process_exec: sched/sched_process_exec      │
└──────────────────────────────────────────────┘
```

---

## 3. Flujos de Detección y Protección

### 3.1 `bprm_check_security` — Bloqueo en exec (requiere root + eBPF)

```
execve("claude-code", argv, envp)
    │
    ▼  [kernel — eBPF LSM]
bprm_check_security hook
    │
    ├── Lee linux_binprm->file → extrae filename
    ├── Calcula FNV-1a hash del nombre
    ├── Busca en KNOWN_AGENTS_BPRM map
    │
    ├── No es agente → return 0 (exec continúa normal)
    │
    └── ES agente → return -1 (-EPERM)
            └── Emite FileEvent a BPRM_EVENTS ring buffer
                │
                ▼  [userspace — daemon]
            Daemon recibe evento → AgentDetected
            El proceso original recibe -EPERM de exec()
            El daemon relanza en bwrap (ver §5)
```

**Ventaja:** El agente **nunca ejecuta un solo opcode** fuera del sandbox.

### 3.2 `process_watcher` eBPF — Detección en tracepoint (root + eBPF)

```
sched_process_exec tracepoint
    │
    ├── Lee comm del proceso
    ├── Calcula FNV-1a hash
    ├── Busca en KNOWN_AGENTS map
    │
    └── ES agente → Emite AgentSpawnEvent a AGENT_SPAWN_EVENTS
            │
            ▼  [userspace — process_watcher]
        verify_pid_comm() → ¿PID sigue siendo el mismo?
        └── SI → kill(SIGTERM + SIGKILL) + relaunch en bwrap
        └── NO → descartar (PID fue reciclado)
```

### 3.3 Scanner `/proc` — Detección pasiva (sin root)

```
Cada 5 segundos (spawn_blocking):
    │
    ├── Itera /proc/<pid>/comm y /proc/<pid>/cmdline
    ├── Compara contra patrones builtin (cursor, claude, windsurf, etc.)
    │
    └── Match → Emite AgentDetected (solo log, NO mata)
```

**Por qué NO mata:** Si el agente YA está corriendo, matarlo destruye su contexto
y trabajo en curso. El scanner solo alerta. La protección real la da bprm_check_security
para nuevos exec.

---

## 4. Linux — Protecciones Implementadas

### 4.1 eBPF (root + kernel ≥5.7 con BPF LSM)

| Hook | Función |
|---|---|
| `bprm_check_security` | Bloquea exec de agentes IA antes del primer opcode |
| `file_unlink` | Bloquea borrado de archivos en dirs protegidos |
| `inode_rmdir` | Bloquea borrado de directorios protegidos |
| `inode_rename` / `file_rename` | Bloquea rename en dirs protegidos |
| `file_open` | Bloquea escritura en archivos protegidos |
| `inode_symlink` / `inode_create` / `inode_mkdir` / `inode_mknod` | Cierre de bypasses |
| `inode_link` | Bloquea hard links (bypass) |
| `inode_setattr` | Bloquea chmod/chown en paths protegidos |
| `file_truncate` | Bloquea truncate (bypass de escritura) |
| `socket_connect` | Bloquea conexiones IPv4 no-localhost (NET_RESTRICT_MODE) |
| `sched/sched_process_exec` | Tracepoint — detecta spawn de agentes |

### 4.2 Userspace (sin root)

| Componente | Mecanismo |
|---|---|
| Guard | `notify` (inotify) — observa operaciones en dirs protegidos |
| Scanner | `/proc` polling cada 5s — detecta agentes por comm/cmdline |
| Sandbox | `bwrap` — namespaces (PID, IPC, UTS, user, cgroup) + mounts readonly + tmpfs + `--die-with-parent` + `--init` |

### 4.3 Sandbox Linux (bwrap + Landlock)

```
bwrap \
  --ro-bind /usr /usr \       # Sistema readonly
  --ro-bind /lib /lib \
  --tmpfs /tmp \               # /tmp aislado
  --tmpfs /home \              # Sin acceso a home del usuario
  --bind <project> <project> \ # Solo el proyecto actual
  --unshare-pid \              # PID namespace
  --unshare-ipc \              # IPC namespace
  --unshare-uts \              # UTS namespace
  --unshare-user \             # User namespace
  --unshare-cgroup-try \       # Cgroup namespace
  --init \                     # Init process (reap zombies)
  --die-with-parent \          # Muere si el daemon muere
  --new-session                # Nueva sesión de proceso
```

Modo `hybrid`: bwrap + Landlock V3 (restricción FS a nivel kernel, irrevocable, sin root).

---

## 5. Windows — Protecciones Implementadas

### 5.1 AppContainer/LPAC Sandbox (admin)

```
launcher.exe recibe: ["claude-code.exe", <args>]
    │
    ├── 1. Crea/reutiliza AppContainer profile
    │      (CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName)
    ├── 2. Construye SECURITY_CAPABILITIES (capabilities vacías = LPAC)
    ├── 3. STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
    ├── 4. CreateProcessW con EXTENDED_STARTUPINFO_PRESENT
    └── 5. Retorna PID del proceso en sandbox
```

**LPAC (Less Privileged AppContainer):** Sin capabilities implícitas.
El proceso solo puede conectar a localhost (DLP proxy).

### 5.2 NTFS DENY ACEs

7 permisos denegados en directorios protegidos para el usuario objetivo:
`DELETE | FILE_DELETE_CHILD | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER`

Aplicados con `SetNamedSecurityInfoW` + `PROTECTED_DACL_SECURITY_INFORMATION`.
`resolve_target_sid()` detecta si el daemon corre como SYSTEM y busca el SID del
usuario interactivo vía `explorer.exe`.

### 5.3 Job Objects

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — si el daemon termina, el agente muere
- `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
- Un Job Object por proceso agente detectado

### 5.4 Detección de agentes

| Método | Mecanismo |
|---|---|
| ToolHelp snapshot | `CreateToolhelp32Snapshot` cada 5s |
| PEB command line | `NtQueryInformationProcess` + `ReadProcessMemory` |
| PEB CWD | CURDIR.DosPath vía PEB |
| ETW | `Microsoft-Windows-Kernel-Process` provider, EventID=1 |
| Polling fallback | `sysinfo` cada 500ms |

---

## 6. IPC y Comunicación

Protocolo: **JSON-line** (un comando JSON por línea, una respuesta JSON por línea).

| Plataforma | Transporte |
|---|---|
| Linux | Unix domain socket (`~/.agentguard/agentguard.sock`, `0600`) |
| Windows | Named Pipe (`\\.\pipe\agentguard`, `CreateNamedPipeW`/`CreateFileW`) |

**Comandos:** `Status`, `Protect`, `Unprotect`, `Snapshot{Create,List,Restore,Cleanup}`,
`Incidents`, `Pause`, `Resume`, `Ping`, `LaunchAgent`, `AddProtectedPath`.

**Implementación:** `IpcServer` (core) + `IpcClient` (CLI/TUI).

---

## 7. Stack Técnico

| Componente | Tecnología |
|---|---|
| Lenguaje | Rust edition 2021 (MSRV 1.75) |
| Async runtime | Tokio (multi-thread) |
| eBPF | aya 0.13 (userspace) + aya-ebpf 0.1 (kernel) |
| Serialización | serde + serde_json + toml |
| CLI | clap 4 (derive) |
| TUI | ratatui 0.29 + crossterm 0.28 |
| Crypto | BLAKE3 (vault), SHA2, rcgen (CA ECDSA P-256) |
| HTTP/DLP | hyper 1.x + rustls + tokio-rustls |
| Windows | windows-rs 0.58 (FFI raw para userenv.dll, ntdll.dll) |
| IPC | serde_json + interprocess + named pipes |
| Notificaciones | notify-rust (desktop) |
| Updater | ureq 3 + flate2 + tar |

---

## 8. Configuración y Defaults

AgentGuard funciona **sin archivo de configuración**. Los defaults incluyen:

```toml
# ── Directorios protegidos (sin config) ──
protected_dirs = ["~/Documents", "~/Projects", "~/Downloads",
                  "~/.ssh", "~/.config", "~/Desktop"]
protected_files = ["~/.env", "~/.netrc", "~/.aws/credentials",
                   "~/.gitconfig", "~/.npmrc"]

# ── Agentes IA detectados automáticamente ──
[[agent_processes]]
name = "cursor"       # Cursor IDE
name = "claude-code"  # Anthropic Claude Code
name = "vscode-copilot"  # VS Code + Copilot
name = "windsurf"     # Windsurf IDE
name = "aider"        # Aider AI
name = "opencode"     # OpenCode

# ── Sandbox ──
[sandbox]
modo_por_defecto = "sandbox"   # sandbox | hybrid | monitor
auto_detectar_agentes = true

# ── DLP ──
[dlp]
enabled = true
proxy_port = 7771
action = "block"
```

---

## 9. Auditoría de Seguridad

21 issues corregidos (Mayo 2026):

| Severidad | Issues | Ejemplos |
|---|---|---|
| 🔴 Crítica (3) | PID reuse race, Landlock silent failure, token handle leak | verify_pid_comm(), Err en NotEnforced, TokenGuard |
| 🟠 Alta (4) | DENY ACEs wrong SID, SE_SECURITY_NAME, LPAC stub, TOCTOU | resolve_target_sid(), enable_security_privilege() |
| 🟡 Media (7) | Network isolation doc, seccomp TODO, zombie leak, env race | --init, remove_var, PROTECTED_DACL en remove |
| 🟢 Baja (7) | Landlock docs, sid_bytes fix, ERROR_ACCESS_DENIED, AppContainer warning | Documentados y corregidos |

---

## 10. Limitaciones Conocidas

| Limitación | Impacto | Mitigación |
|---|---|---|
| eBPF requiere root + kernel ≥5.7 con BPF LSM | Sin root → solo userspace (detecta, no bloquea) | Degradación automática |
| NTFS DENY ACEs solo cubre escritura/borrado | No hay protección contra lectura en Windows | Requeriría driver kernel firmado |
| bwrap sin `--unshare-net` | Agente puede hacer conexiones directas (bypass DLP proxy) | Proxy inyectado vía env vars |
| Sin seccomp | Sin filtro de syscalls en bwrap | TODO documentado en sandbox.rs |
| Landlock per-thread | Solo restringe el hilo que llama `restrict_self()` | Documentado en landlock.rs |
| Scanner /proc no sandboxea | Solo detecta, no mata (respeta trabajo en curso) | Sandbox real vía bprm_check_security (root) |

---

## 11. Roadmap

El documento `docs/ROADMAP-V2.MD` describe features planeadas para v2.0:

- Binary displacement + inotify auto-heal (protección sin root)
- seccomp-BPF con USER_NOTIF (syscall filtering adaptativo)
- Perfiles OTA con firma Ed25519
- Windows Low IL + SetProcessMitigationPolicy (sandbox sin admin)
- bpf_link pinning a /sys/fs/bpf (persistencia si daemon muere)
- FD broker SCM_RIGHTS (acceso dinámico a rutas)
