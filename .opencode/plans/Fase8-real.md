# Fase 8 — Ejecución Real (actualizado post-implementación)

> Fecha: 2026-05-05

---

## Tareas completadas

```
[x] 8.1  AppContainer/LPAC sandbox real (FFI raw a userenv.dll)
[x] 8.2  Named Pipes IPC (daemon + CLI + core)
[x] 8.3  PEB introspección (cmdline + cwd vía NtQueryInformationProcess)
[x] 8.4  Tests E2E (13 tests inline)
[x] 8.5  Installer + armonización de docs
```

---

## Desviaciones del plan original

| Área | Plan | Realidad | Motivo |
|---|---|---|---|
| windows-rs | 0.58 → 0.60 | Mantenido 0.58 | 0.61 tenía bug con `windows-future` incompatible |
| Named Pipes | Usar `interprocess` crate | FFI raw a `kernel32.dll` | API de interprocess v2 demasiado compleja |
| Tests | `tests/e2e.rs` externo | Inline `#[cfg(test)]` en source files | Binario sin `[lib]` no exporta símbolos |
| AppContainer | Usar `windows-rs >= 0.60` | FFI raw a `userenv.dll` | Mismo motivo que windows-rs |
| PEB | `NtQueryInformationProcess` vía windows-rs | FFI raw a `ntdll.dll` | Mismo motivo |

---

## Auditoría de Seguridad — Corregido

### Críticos (3/3 corregidos)

| ID | Archivo | Problema | Fix |
|---|---|---|---|
| C-1 | `process_watcher.rs` | PID reuse race — mataba proceso equivocado | `verify_pid_comm()` lee `/proc/<pid>/comm` y descarta si no coincide. Verificación en 2 puntos (antes y después de leer /proc) |
| C-2 | `landlock.rs` | `NotEnforced`/`PartiallyEnforced` retornaban `Ok(())` | Retornan `Err(LandlockError::PartiallyEnforced)` / `Err(LandlockError::NotEnforced)` |
| C-3 | `guard.rs` | Token handle leak en `get_current_user_sid` | `TokenGuard` struct con `Drop` impl — `CloseHandle` en todas las ramas |

### Altos (4/4 corregidos)

| ID | Archivo | Problema | Fix |
|---|---|---|---|
| H-1 | `guard.rs` | DENY ACEs aplicados al SID del daemon (SYSTEM), no al usuario | `apply_deny_aces(path, target_sid)` — SID parametrizado. `resolve_target_sid()` busca SID interactivo vía `explorer.exe` |
| H-2 | `guard.rs` | `PROTECTED_DACL` usado sin `SE_SECURITY_NAME` | `enable_security_privilege()` activa privilegio. Fallback a `DACL_SECURITY_INFORMATION` con warning |
| H-3 | `sandbox.rs` | LPAC era stub vacío | `capabilities` apunta a array vacío válido (no NULL) → LPAC real, sin capabilities implícitas |
| H-4 | `guard.rs` | TOCTOU en aplicación de DENY ACEs | `verify_deny_ace_applied()` re-lee DACL post-write |

### Medios (pendientes)

| ID | Archivo | Problema |
|---|---|---|
| M-1 | `sandbox.rs` | bwrap sin network isolation — DLP proxy bypasseable |
| M-2 | `sandbox.rs` | Sin seccomp syscall filter |
| M-3 | `sandbox.rs` | PID namespace sin init → zombie leak |
| M-4 | `sandbox.rs` | Sin cgroup namespace unshare |
| M-5 | `sandbox.rs` | Environment variable race en daemon Windows |
| M-6 | `process_watcher.rs` | FNV-1a hash collisions en eBPF known-agents map |
| M-7 | `guard.rs` | Cleanup un-protects DACL, exponiendo a inherited ACEs |

---

## Métricas finales

| Métrica | Antes | Después |
|---|---|---|
| Tests agentguard-windows | 7 | 13 |
| Tests agentguard-tui | 0 | 26 |
| AppContainer sandbox | STUB | Funcional (FFI userenv.dll) |
| CLI Windows ↔ daemon | Roto | Funcional (Named Pipes) |
| PEB cmdline | STUB | Funcional (NtQueryInformationProcess) |
| PEB cwd | STUB (TODO) | Funcional |
| Instalador Windows | Mensaje | Descarga + service |
| eBPF network guard | STUB | Funcional (socket_connect + NET_RESTRICT_MODE) |

---

## Commits realizados

```
5d407cc feat(windows): Fase 8 — AppContainer sandbox, PEB introspection, Named Pipes IPC, E2E tests
d42ed38 fix(windows): add Win32_System_IO feature, fix CreateNamedPipeW return type
00c3dba fix(windows): move PIPE_ACCESS_DUPLEX to FileSystem, wrap WriteFile buf
abd90ee fix(windows): FreeSid import, byte_add casts, LPPROC_THREAD_ATTRIBUTE_LIST
6946796 fix(windows): explicit field init for app_container_sid, second FreeSid PSID wrap
e91f576 fix(windows): inline tests in sandbox.rs and helpers.rs
35ee8d5 fix: platform-gate socket test, suppress unused FFI warning
0707cf3 fix(windows): read CWD via CURDIR.DosPath UnicodeString
5d88e6d fix(windows): annotate test expect() for check-no-panic.sh
d85c565 style: cargo fmt --all
23757b9 fix(windows): suppress dead_code warning
88387f6 fix(windows): correct PEB struct offsets for 64-bit Windows
805a457 docs(state): update Windows test count and recommendations
dadcb9b test(tui): add 26 unit tests for theme, app state, and IPC client
f0b1aa9 feat(linux): activate eBPF network guard — socket_connect hook
9c0c391 fix(security): C1-C3 — PID reuse race, Landlock silent failure, token handle leak
434d810 fix(security): H1-H4 — SID parametrizado, SE_SECURITY_NAME, LPAC real, TOCTOU
```
