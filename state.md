# Análisis Completo del Estado de HALO (AgentGuard)

> Fecha: 2026-05-05

---

## 1. Estado General del Proyecto

| Métrica | Valor |
|---|---|
| Líneas de código totales | ~12,000+ |
| Crates en workspace | 7 (+ eBPF excluido) |
| Tests totales | **102** (0 fallos) |
| Clippy warnings | 0 |
| `.unwrap()`/`.expect()` en prod | 0 |
| Fases completadas | 0, 1, 2, 3, 4, 6, 7 |
| Fases pendientes | 5 (macOS) |

### Estructura de crates

```
crates/
├── agentguard-common/       Tipos compartidos (no_std + std), IPC protocol
├── agentguard-core/         Lógica compartida del daemon (todas las plataformas)
├── agentguard-linux/        Binario Linux (eBPF + userspace fallback)
├── agentguard-windows/      Binario Windows (NTFS DENY ACEs + Job Objects + ETW)
├── agentguard-ebpf/         Programas eBPF kernel (compilación separada, nightly)
├── agentguard-tui/          TUI terminal (ratatui + crossterm)
├── agentguard-cli/          CLI cross-platform
├── agentguard-installer/    Bootstrap installer
```

---

## 2. Linux — Análisis Detallado

### Estado: **ALTO (Fase 2 completada, v2.1 completado)** — 90%

### Archivos (11 archivos, ~2,533 líneas Rust)

| Archivo | Líneas | Propósito |
|---|---|---|
| `Cargo.toml` | 69 | Dependencias, features, binario + lib |
| `build.rs` | 54 | Embebe bytecode eBPF en el binario (`--features ebpf`) |
| `src/main.rs` | 586 | Entry point: bootstrap del daemon, event loop, graceful shutdown |
| `src/lib.rs` | 11 | Re-exports de módulos |
| `src/guard.rs` | 43 | Selector de backend en runtime (`select_guard()`) |
| `src/guard/ebpf.rs` | 351 | Backend eBPF LSM: 12 hooks, ring buffer, mapas BPF |
| `src/guard/userspace.rs` | 215 | Fallback userspace: `notify` (inotify), solo observación |
| `src/guard/agents.rs` | 460 | Scanner `/proc`: comm, cmdline, exe, matching de patrones |
| `src/landlock.rs` | 72 | Landlock V3: restricción FS a nivel kernel |
| `src/sandbox.rs` | 290 | Bubblewrap (bwrap): namespaces + mounts readonly + tmpfs |
| `src/process_watcher.rs` | 276 | eBPF tracepoint `sched/sched_process_exec` |
| `tests/sandbox_integration.rs` | 75 | Tests de integración del sandbox |

### Backends de protección

| Backend | Mecanismo | Nivel | Bloquea? |
|---|---|---|---|
| `EbpfGuard` | 12 hooks LSM en kernel | `KernelDenial` | SI |
| `UserspaceGuard` | `notify` (inotify) | `UserspaceObservation` | NO (solo observa) |

### eBPF LSM hooks implementados (12)

| Hook | Handler | Protección |
|---|---|---|
| `file_unlink` | `try_deny_protected(FileDelete)` | Borrado de archivos |
| `inode_rmdir` | `try_deny_protected(FileDelete)` | Borrado de directorios |
| `inode_rename` | `try_deny_rename()` | Rename (src + dst) |
| `file_rename` | `try_deny_rename()` | Rename (src + dst) |
| `file_open` | `try_deny_write()` | Escritura en archivos protegidos |
| `inode_symlink` | `try_deny_protected(FileWrite)` | Symlink bypass |
| `inode_create` | `try_deny_protected(FileWrite)` | Creación de archivos |
| `inode_mkdir` | `try_deny_protected(FileWrite)` | Creación de directorios |
| `inode_mknod` | `try_deny_protected(FileWrite)` | Creación de dispositivos |
| `inode_link` | custom | Hard link bypass |
| `inode_setattr` | `try_deny_setattr()` | chmod/chown/utimes |
| `file_truncate` | `try_deny_write()` | Truncate bypass |

### eBPF Tracepoint

| Hook | Propósito |
|---|---|
| `sched/sched_process_exec` | Detección de agentes IA via hash FNV-1a en `KNOWN_AGENTS` |

### Sandbox

| Modo | Mecanismo | Requiere |
|---|---|---|
| `monitor` | Solo observación | Nada |
| `sandbox` | Bubblewrap (namespaces + mounts readonly + tmpfs aislado) | `bwrap` |
| `hybrid` | Bubblewrap + Landlock V3 | `bwrap` + kernel >= 5.13 |

### Otros subsistemas

| Componente | Estado |
|---|---|
| DLP Proxy (HTTP/HTTPS MITM) | Completo — CA local (rcgen ECDSA), 14 patrones de secretos |
| Vault (BLAKE3 dedup) | Completo — snapshots en `/var/lib/agentguard/vault` |
| IPC Server (Unix socket `0600`) | Completo — 13 comandos JSON-line |
| systemd service | Completo — hardening: `ProtectSystem=strict`, `NoNewPrivileges=true` |
| Install script | Completo — SHA256, instalación de CA en trust store |
| Desktop notifications | Completo — `notify-rust` |

### Protecciones de seguridad (25+)

1. `0600` en socket IPC y clave CA
2. systemd: `ProtectSystem=strict`, `NoNewPrivileges=true`, address families restringidas
3. Capacidades acotadas: `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_PERFMON`
4. Graceful degradation: eBPF falla → userspace; DLP falla → continúa sin DLP
5. Cierre de bypasses: symlink, hard link, truncate, setattr, mknod
6. Canonicalización de paths (previene symlink bypass)
7. Sandbox: namespaces aislados, mounts readonly, tmpfs, `--die-with-parent`
8. Landlock: restricción FS a nivel kernel sin root
9. Detección en tiempo real: tracepoint + killer + relanzamiento en sandbox
10. DLP: HTTPS MITM con CA local, bloqueo de secretos en tráfico saliente
11. Logging: JSONL append-only (`incidents.jsonl`)

### Lo que falta en Linux

| Gap | Impacto |
|---|---|
| **eBPF network guard** es un stub | `net_guard.bpf.o` se compila pero nunca se adjunta. `socket_connect` no bloquea nada. |
| **DLP a nivel kernel** inexistente | La protección DLP es solo userspace (proxy HTTP). No hay integración eBPF para tráfico de red. |
| **add/remove paths en eBPF** requiere reinicio | Solo el backend userspace soporta cambios dinámicos de paths protegidos. |

### Tests: 21 (18 unit + 3 integración)

---

## 3. Windows — Análisis Detallado

### Estado: **MEDIO (Fase 4 completada parcialmente)** — 60%

### Archivos (5 archivos, ~2,390 líneas Rust)

| Archivo | Líneas | Propósito |
|---|---|---|
| `Cargo.toml` | 48 | Dependencias, 14 features Win32 de windows-rs v0.58 |
| `src/main.rs` | 743 | Entry point: modo consola + Windows Service (SCM) + daemon core |
| `src/guard.rs` | 1151 | `WindowsGuard`: NTFS DENY ACEs + Job Objects + detección de agentes |
| `src/sandbox.rs` | 122 | AppContainer/LPAC sandbox (**STUB**) |
| `src/process_watcher.rs` | 326 | ETW process creation monitor + polling fallback (`sysinfo`) |

### Backend de protección: `WindowsGuard`

| Campo | Valor |
|---|---|
| `backend_name` | `"ntfs-deny-aces"` |
| `protection_level` | `KernelDenial` (Windows) / `UserspaceObservation` (non-Windows stub) |

### NTFS DENY ACEs — 7 permisos denegados

| Permiso | Efecto |
|---|---|
| `DELETE` | Bloquea borrado de archivos |
| `FILE_DELETE_CHILD` | Bloquea borrado dentro del directorio |
| `FILE_WRITE_DATA` | Bloquea escritura de datos |
| `FILE_WRITE_EA` | Bloquea escritura de atributos extendidos |
| `FILE_WRITE_ATTRIBUTES` | Bloquea modificación de atributos |
| `WRITE_DAC` | Bloquea cambio de ACL (previene auto-desprotección) |
| `WRITE_OWNER` | Bloquea cambio de propietario |

Usa `PROTECTED_DACL_SECURITY_INFORMATION` para que la herencia no sobrescriba.

### Job Objects — Contención por proceso

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — si el daemon termina, los agentes mueren
- `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
- Limpieza en `Drop` + reaper periódico de PIDs muertos

### Detección de agentes IA

| Método | Estado | Detalle |
|---|---|---|
| **ToolHelp snapshot** | COMPLETO | `CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW` cada 5s |
| **PEB command-line** | **STUB** | `read_process_command_line()` → siempre `None`. `NtQueryInformationProcess` no en windows-rs v0.58 |
| **PEB CWD** | **STUB** | `process_watcher.rs::read_process_cwd()` → string vacío. Marcado `TODO` |
| **ETW** | COMPLETO | `Microsoft-Windows-Kernel-Process` provider, EventID=1 |
| **Polling (sysinfo)** | COMPLETO | Fallback 500ms si ETW no disponible |

### Matching de agentes

| Tipo | Estado |
|---|---|
| `name` (substring en exe) | COMPLETO |
| `exe_any` (lista de nombres alternativos) | COMPLETO |
| `argv_contains_any` (argumentos de línea de comandos) | **PARCIAL** — solo funciona cuando el exe name coincide (PEB inaccesible impide leer argv de procesos arbitrarios) |

### Windows Service (SCM)

| Función | Estado |
|---|---|
| `StartServiceCtrlDispatcherW` | COMPLETO |
| `RegisterServiceCtrlHandlerExW` | COMPLETO |
| STOP / PAUSE / CONTINUE / INTERROGATE | COMPLETO |
| Instalación automática | **NO EXISTE** — manual vía `sc.exe create` |

### Subsistemas integrados desde core

| Componente | Estado |
|---|---|
| DLP Proxy (HTTP/HTTPS MITM) | COMPLETO — `127.0.0.1:7771`, CA local |
| Vault (BLAKE3 dedup) | COMPLETO — `C:\ProgramData\AgentGuard\vault\` |
| IPC Server | COMPLETO — Unix socket en `%TEMP%\agentguard-{USER}.sock` |
| Incident log (JSONL) | COMPLETO — `C:\ProgramData\AgentGuard\incidents.jsonl` |
| Elevation check | COMPLETO — `OpenProcessToken` + `TokenElevation` |

### Lo que falta en Windows

| Gap | Gravedad | Detalle |
|---|---|---|
| **AppContainer/LPAC sandbox** | **CRITICO** | `sandbox.rs::launch()` siempre retorna error. `SECURITY_CAPABILITIES` requiere windows-rs >= v0.60. Sin sandbox, los agentes IA detectados no pueden ser aislados automáticamente. |
| **PEB introspección** | **ALTO** | No se puede leer `cmdline` ni `cwd` de procesos. La detección de agentes se limita al nombre del ejecutable. |
| **Named Pipes** | **ALTO** | El daemon usa Unix socket en `%TEMP%`. El CLI de Windows tiene `StubStream` — no puede conectarse al daemon. No hay IPC funcional en Windows. |
| **Installer MSI/WiX** | **MEDIO** | No existe. El installer actual imprime "Download the MSI from GitHub releases". |
| **Sin hardening equivalente a systemd** | **MEDIO** | Linux tiene `ProtectSystem=strict` y 15+ restricciones. Windows no tiene equivalente. |
| **Sin protección contra lectura** | **BAJO** | NTFS DENY ACEs solo cubre escritura/borrado. En Linux, eBPF puede bloquear `file_open` para lectura. |

### Comparativa de protecciones Windows vs Linux

| Vector de ataque | Linux | Windows |
|---|---|---|
| Borrado de archivos | eBPF LSM (kernel) | NTFS DENY ACEs (FS) |
| Escritura en archivos | eBPF LSM (kernel) | NTFS DENY ACEs (FS) |
| Rename | eBPF LSM (kernel) | Notify observa (no bloquea) |
| Symlink bypass | eBPF LSM (kernel) | Sin protección |
| Hard link bypass | eBPF LSM (kernel) | Sin protección |
| Truncate bypass | eBPF LSM (kernel) | Sin protección |
| chmod/chown bypass | eBPF LSM (kernel) | WRITE_DAC/WRITE_OWNER denegados |
| Sandbox automático | bwrap + Landlock | **STUB** |
| Detección de agentes | comm + cmdline + exe | Solo exe name |
| DLP MITM | Proxy HTTPS localhost | Proxy HTTPS localhost |
| Monitor de procesos | eBPF tracepoint + /proc | ETW + ToolHelp + polling |

### Tests: 7 (todos en `guard.rs`, solo matching cross-platform)

---

## 4. Core / Common — Estado Detallado

### `agentguard-common` (334 líneas, 3 tests)

Tipos FFI `no_std` + IPC types `std`:

| Tipo | Propósito |
|---|---|
| `EventType`, `FileEvent`, `NetworkEvent` | Eventos del ring buffer BPF → daemon |
| `PathPrefix`, `AgentSpawnEvent` | Mapas BPF y tracepoint |
| `IpcCommand`, `IpcResponse` | Protocolo IPC JSON-line (13 comandos) |
| `SnapshotInfo`, `SandboxMode`, `SandboxedAgent` | Tipos compartidos CLI/TUI/daemon |

### `agentguard-core` (12 archivos, 68 tests)

| Módulo | Tests | Funcionalidad |
|---|---|---|
| `config.rs` | 9 | TOML parsing, validación de regex, expansión `~`, `DlpAction` |
| `events.rs` | 2 | `SecurityEvent` (5 variantes), JSON roundtrip, sin leaks de secretos |
| `vault.rs` | 10 | BLAKE3 content-addressed, dedup, snapshots, restore con permisos Unix |
| `ca.rs` | 8 | rcgen ECDSA P-256, CA root 10 años, `0600` clave privada, `0700` dir |
| `dlp/patterns.rs` | 10 | 14 patrones predefinidos (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, etc.) |
| `dlp/proxy.rs` | 9 | HTTP proxy + HTTPS MITM (CONNECT tunnel), bloqueo/alert/log |
| `dlp/tls.rs` | 5 | Leaf cert issuer, cache LRU 512 entradas, validación de hostname |
| `ipc_server.rs` | 8 | JSON-line Unix socket `0600`, 13 comandos, `IpcServerBuilder` |
| `updater.rs` | 4 | GitHub Releases, SHA256 verify, tar.gz, reemplazo atómico |
| `guard.rs` | 0 | `KernelGuard` trait + `ProtectionLevel` + `GuardError` |

---

## 5. CLI — Estado Detallado

### Estado: **ALTO** — 14 comandos, 11 tests

| Comando | IPC? | Descripción |
|---|---|---|
| `status` | Si | Backend, paths protegidos, incidentes, sandbox |
| `protect <path>` | Si | Proteger directorio o archivo |
| `unprotect <path>` | Si | Quitar protección |
| `snapshot create/list/restore/cleanup` | Si | Gestión de snapshots |
| `incidents --last N` | Si | Últimos incidentes de seguridad |
| `pause --minutes N` | Si | Pausar protección |
| `resume` | Si | Reanudar protección |
| `ping` | Si | Health check |
| `init` | No | Generar config.toml por defecto |
| `launch <agent>` | Si | Lanzar agente IA en sandbox |
| `check` | No | Verificar capacidades del sistema |
| `setup` | No | Wizard interactivo |
| `update` | No | Check/instalar updates |

### Transporte

| Plataforma | Transporte | Estado |
|---|---|---|
| Linux | Unix domain socket | COMPLETO |
| Windows | `StubStream` | **ROTO** — siempre retorna `NotConnected` |

---

## 6. TUI — Estado Detallado

### Estado: **ALTO** — ratatui + crossterm, 0 tests

| Tab | Contenido |
|---|---|
| Dashboard | Banner + stat cards + actividad reciente |
| Protected Zones | Directorios y archivos protegidos |
| Recent Incidents | Log de eventos de seguridad |
| Snapshots | Lista de snapshots del vault |

- Auto-refresh cada 5s
- Teclas: `1-4` tabs, `Tab`/`n` siguiente, `q` salir, `r` refresh, `p` pausar

---

## 7. eBPF — Estado Detallado

### Estado: **ALTO** — 13 hooks, 0 tests

| Programa | Hooks | Estado |
|---|---|---|
| `file_guard` | 12 LSM hooks | COMPLETO |
| `process_exec` | 1 tracepoint | COMPLETO |
| `net_guard` | `socket_connect` | **STUB** |

### Mapas BPF

| Mapa | Tipo | Tamaño | Propósito |
|---|---|---|---|
| `PROTECTED_PREFIXES` | Array | 64 | Prefijos de directorios protegidos |
| `PROTECTED_WRITE_PATHS` | Array | 64 | Archivos protegidos contra escritura |
| `FILE_EVENTS` | RingBuf | 1 MiB | Eventos de filesystem → userspace |
| `KNOWN_AGENTS` | HashMap | 128 | Hashes FNV-1a de agentes conocidos |
| `AGENT_SPAWN_EVENTS` | RingBuf | 512 KiB | Eventos de spawn → userspace |
| `NET_EVENTS` | RingBuf | 2 MiB | Eventos de red (sin usar) |

---

## 8. Problemas Estructurales Detectados

| # | Problema | Gravedad | Estado post-Fase 8 |
|---|---|---|---|
| 1 | **Fase 4 inconsistente**: `PlanDeImplementacion.md` dice "Pendiente", `AGENTS.md` dice "Completada" | BAJO (docs) | ✓ Armonizado |
| 2 | **CLI Windows roto**: `StubStream` no puede conectarse al daemon | ALTO | ✓ Resuelto (Named Pipe transport vía kernel32 FFI) |
| 3 | **AppContainer requiere windows-rs >= 0.60**: windows-rs v0.58 no tiene `SECURITY_CAPABILITIES` | CRITICO | ✓ Resuelto (FFI raw a userenv.dll) |
| 4 | **eBPF network guard es un stub silencioso**: se compila pero nunca se adjunta | MEDIO | Pendiente Linux |
| 5 | **0 tests e2e en Windows**: los 7 tests son solo de matching cross-platform | ALTO | ✓ Resuelto (15 tests E2E en tests/e2e.rs) |
| 6 | **Sin protección contra lectura en Windows**: DENY ACEs solo cubre escritura/borrado | BAJO | Pendiente (NTFS: solo escritura) |
| 7 | **TUI tiene 0 tests** | MEDIO | Pendiente |
| 8 | **Sin installer MSI/WiX para Windows** | MEDIO | ✓ Resuelto (installer.iss + install_windows funcional) |
| 9 | **Documentación de Fase 5 (macOS) inexistente**: no hay crate `agentguard-macos` | BAJO | Pendiente |

---

## 9. Resumen por Fase

| Fase | Descripción | Estado | Completitud |
|---|---|---|---|
| **0** | Reorganización de crates | ✓ | 100% |
| **1** | Core funcional | ✓ | 100% |
| **2** | Linux daemon (eBPF + userspace) | ✓ | 90% (falta network eBPF) |
| **3** | CLI + installer | ✓ | 95% (installer Windows descarga binarios) |
| **4** | Windows daemon | ✓ | 85% (Fase 8 cerró sandbox, PEB, IPC, tests) |
| **5** | macOS daemon | □ | 0% (pospuesto) |
| **6** | TUI | ✓ | 100% |
| **7** | Auto-updater | ✓ | 100% |
| **8** | Windows hardening | ✓ | 100% |

---

## 10. Recomendaciones Priorizadas

### Críticas (bloquean funcionalidad core)

1. **Implementar AppContainer/LPAC sandbox en Windows** — actualizar windows-rs a >= v0.60 para acceder a `SECURITY_CAPABILITIES`
2. **Migrar IPC de Windows a Named Pipes** + arreglar `StubStream` en CLI

### Altas (mejoran significativamente la seguridad)

3. **Implementar PEB introspección** — leer `cmdline` y `cwd` de procesos (requiere `NtQueryInformationProcess` + `ReadProcessMemory`)
4. **Añadir tests e2e para Windows** — validar DENY ACEs, Job Objects, ETW
5. **Activar eBPF network guard** — implementar bloqueo real en `socket_connect`

### Medias (completan el producto)

6. **Crear installer MSI/WiX para Windows**
7. **Añadir tests al TUI**
8. **Armonizar documentación de estado de fases** entre `PlanDeImplementacion.md` y `AGENTS.md`
