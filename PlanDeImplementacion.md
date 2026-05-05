# Plan de implementación AgentGuard (HALO) v2

Implementación incremental de AgentGuard en Rust. **Terminal-first** (CLI como interfaz primaria, UI gráfica diferida a fase final). **Crates separados por SO** para que el installer solo descargue lo necesario en cada plataforma.

---

## 0. Decisiones de arquitectura (v2)

### ¿Por qué separar por SO?

Linux (eBPF LSM) y Windows (NTFS DENY ACEs + Job Objects) usan APIs de kernel radicalmente distintas, con dependencias incompatibles entre sí. Un solo binario monolítico con `#[cfg]` se vuelve:

- **Dependencias infladas**: Linux necesita `aya`, Windows necesita `windows-rs`. Cada una pesa ~5-10 MB extra.
- **CI compleja**: Hay que cross-compilar o tener runners de cada OS.
- **Releases inflados**: El usuario baja un binario de 40 MB que contiene código que nunca ejecutará.

**Solución**: un crate `agentguard-core` con toda la lógica compartida (vault, DLP, CA, IPC, config, evento loop) y un binario por SO que solo contiene su guard específico. El installer detecta el SO y baja exclusivamente lo que necesita.

### Terminal-first

La CLI es la interfaz primaria. Tauri UI pasa a ser opcional (fase 6) y se construye sobre la CLI vía IPC, no al revés.

### Flujo de instalación

```
Usuario ejecuta:  curl -fsSL https://get.agentguard.io | bash
                          │
                          ▼
                  Script detecta SO + arch
                  ┌──────────────────────────────┐
                   │ Linux → baja agentguard-cli   │
                   │         + agentguard-linux    │
                   │         + eBPF bytecode       │
                   │                                │
                   │ Win   → baja agentguard-cli    │
                   │         + agentguard-windows   │
                   └──────────────────────────────┘
                           │
                           ▼
                   Instala + systemd/service
```

---

## 1. Reglas Windsurf (se mantienen)

Sin cambios respecto a v1:

| Archivo | Contenido |
|---|---|
| `01-rust-style.md` | `cargo fmt` obligatorio; `clippy -D warnings`; edition 2021; `thiserror` para libs, `anyhow` para binarios; docstrings en `pub fn`. |
| `02-no-unwrap.md` | Prohibido `.unwrap()`, `.expect()`, `panic!()` fuera de tests. Excepción: `main()` con `anyhow::Result`. |
| `03-ebpf-safety.md` | Código eBPF `#![no_std]`, loops con bound estático, fail-open, documentar cada `unsafe`. |
| `04-security-logging.md` | Nunca loggear valores de secretos. Logs JSON estructurados con `tracing`. |
| `05-testing.md` | Todo módulo nuevo requiere tests unitarios. Cambios en vault/dlp/guard requieren test de integración. |
| `06-ipc-contract.md` | `IpcCommand`/`IpcResponse` son el contrato daemon↔CLI↔UI. Breaking changes → bump versión + `CHANGELOG.md`. |
| `07-paths-and-privileges.md` | Vault/logs root → `/var/lib/agentguard/`. Usuario → `~/.agentguard/`. CA con permisos 600. |

---

## 2. Entorno de pruebas seguro (se mantiene)

Igual que v1. VM con Multipass/libvirt para eBPF, contenedor privilegiado para userspace, `tests/fixtures/sandbox/` para datos sintéticos.

---

## 3. Nueva estructura de crates

```
crates/
├── agentguard-common/       Tipos compartidos (no_std + std), IPC protocol
├── agentguard-core/         Lógica compartida del daemon (NUEVO)
│   ├── config.rs            Deserialización TOML
│   ├── vault.rs             Snapshots BLAKE3
│   ├── dlp/                 Proxy HTTP/HTTPS + patterns
│   ├── ca.rs                CA root local + leaf issuer
│   ├── events.rs            SecurityEvent
│   ├── guard.rs             Trait KernelGuard (sin implementaciones)
│   └── ipc_server.rs        Unix socket JSON-line IPC
│
├── agentguard-linux/        BINARIO: daemon para Linux (eBPF + userspace)
│   ├── guard/ebpf.rs        EbpfGuard (aya)
│   ├── guard/userspace.rs   UserspaceGuard (notify fallback)
│   └── main.rs              Entry point Linux (compone core + eBPF)
│
├── agentguard-windows/      BINARIO: daemon para Windows (NTFS ACLs + Job Objects)
│
├── agentguard-ebpf/         Programas eBPF (kernel, compilación separada)
│   ├── file_guard.rs        LSM hooks filesystem
│   └── net_guard.rs         LSM hook red (stub futuro)
│
├── agentguard-cli/          BINARIO: CLI cross-platform (único para todos los SO)
│   └── main.rs              clap → IPC → output formateado
│
├── agentguard-installer/    Scripts de instalación por SO
│   ├── install.sh           Linux (detecta SO, baja binario correcto)
│   ├── install.ps1          Windows
│   └── uninstall.sh         Limpieza
│
└── agentguard-tui/           TUI terminal: ratatui + crossterm (4 tabs)
    └── src/lib.rs           Stub actual
```

### Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/agentguard-common",
    "crates/agentguard-core",
    "crates/agentguard-linux",
    "crates/agentguard-windows",
    "crates/agentguard-cli",
    "crates/agentguard-installer",
    "crates/agentguard-tui",
]
exclude = ["crates/agentguard-ebpf"]
```

### Build matrix por SO

| Crate | Linux | Windows | CI runner |
|---|---|---|---|
| `agentguard-common` | ✓ | ✓ | ubuntu |
| `agentguard-core` | ✓ | ✓ | ubuntu + windows |
| `agentguard-linux` | ✓ | ✗ | ubuntu |
| `agentguard-windows` | ✗ | ✓ | windows |
| `agentguard-ebpf` | ✓ | ✗ | ubuntu (nightly) |
| `agentguard-cli` | ✓ | ✓ | ubuntu (cross) |
| `agentguard-installer` | ✓ | ✓ | ubuntu |
| `agentguard-tui` | ✓ | ✓ | ubuntu |

---

## 4. Fases de implementación

### Fase 0 — Reorganización de crates (ahora)

```
[ ] 0.1  Crear agentguard-core: mover vault, dlp, ca, config, events, guard.rs (trait solo),
         ipc_server desde agentguard-daemon. Tests se mueven también.
[ ] 0.2  Crear agentguard-linux: mover guard/ebpf.rs, guard/userspace.rs, main.rs.
         Depende de: agentguard-core + agentguard-common.
[ ] 0.3  Crear agentguard-windows: stub con guard.rs (WindowsGuard) + main.rs.
[ ] 0.4  Actualizar Cargo.toml raíz con los nuevos members.
[ ] 0.5  Actualizar CI: build-linux, build-windows como jobs separados.
[ ] 0.6  Deprecar agentguard-daemon (eliminar al final de la fase).
[ ] 0.7  Verificar: cargo build --workspace --exclude agentguard-ebpf (Linux).
```

**Gate:** `cargo build` verde para todos los crates del workspace en Linux.

### Fase 1 — Core completo (toda la lógica compartida)

```
[ ] 1.1  agentguard-common: FileEvent, NetworkEvent, EventType, PathPrefix, IPC types (ya OK).
[ ] 1.2  agentguard-core/config.rs: TOML deserialización + validación + expansión "~".
[ ] 1.3  agentguard-core/vault.rs: create_snapshot, restore, list, cleanup + BLAKE3 dedup.
[ ] 1.4  agentguard-core/dlp/: patterns (14 built-in) + proxy HTTP + TLS MITM.
[ ] 1.5  agentguard-core/ca.rs: CA root local (rcgen ECDSA) + leaf issuer.
[ ] 1.6  agentguard-core/events.rs: SecurityEvent enum.
[ ] 1.7  agentguard-core/guard.rs: trait KernelGuard (solo contrato, sin impls).
[ ] 1.8  agentguard-core/ipc_server.rs: Unix socket JSON-line IPC server.
[ ] 1.9  Tests: ~40 tests existentes migrados a core. Verificar que pasan.
```

**Gate:** `cargo test -p agentguard-core` verde con ≥40 tests.

### Fase 2 — Linux daemon (MVP principal) ✓ COMPLETADA

```
[x] 2.1  agentguard-linux/guard/ebpf.rs: EbpfGuard implementa KernelGuard.
         Carga eBPF LSM, puebla prefixes, lee ring buffer.
[x] 2.2  agentguard-linux/guard/userspace.rs: UserspaceGuard (notify fallback).
[x] 2.3  agentguard-linux/main.rs: entry point que compone core + guard + DLP + IPC + event loop.
         Manejo de SIGTERM/SIGINT, persistencia de incidentes en JSONL.
[x] 2.4  agentguard-ebpf: file_guard.rs + net_guard.rs (LSM hooks completos).
[x] 2.5  VM test suite: vm-test.sh + setup-vm.sh + simulate_ai_agent (8 ataques).
[x] 2.6  systemd unit: agentguard.service con capabilities restringidas, ProtectSystem=strict.
[x] 2.7  Scripts: dev-reset.sh, packaging/linux/install.sh, build-ebpf.sh.
[x] 2.8  Benchmarks documentados: RAM idle < 10 MB, CPU idle < 0.1%.
[x] 2.9  **v2.1**: Sandbox Launcher (bwrap + Landlock), eBPF process_exec tracepoint,
         ProcessWatcher, CLI launch/check/setup, config agent_detection + sandbox.
```

**Gate:** Daemon Linux bloquea `unlink` real en VM con eBPF activo. Fallback userspace funciona sin BPF LSM. Sandbox v2.1 detecta agentes y los relanza en bwrap.
**Test suite:** `test-env/vm-test.sh` + `simulate_ai_agent` (8 ataques: unlink, overwrite .env, rename, rm -rf, malware, truncate, symlink escape, HTTP exfiltration).
**Systemd:** `packaging/linux/agentguard.service` (root + AmbientCapabilities mínimas + ProtectSystem=strict + ProtectHome=read-only).

### Benchmark objetivo (verificar en VM)

| Métrica | Objetivo | Método |
|---|---|---|
| RAM idle | < 10 MB | `grep VmRSS /proc/$(pidof agentguard-linux)/status` |
| CPU idle | < 0.1% | `top -p $(pidof agentguard-linux) -bn2` (5 min) |
| Arranque | < 500ms | `time agentguard-linux --config /etc/agentguard/config.toml` |
| Latencia eBPF | < 50ms | `strace -T rm /protected/test-zone/important.md 2>&1 \| grep EPERM` |

### Fase 3 — CLI cross-platform + Installer (terminal-first) ✓ COMPLETADA

```
[x] 3.1  agentguard-cli: clap derive con todos los subcomandos → IPC → output formateado.
[x] 3.2  Output con crossterm: tablas, colores (verde/rojo/amarillo), emojis de estado.
[x] 3.3  `agentguard init --defaults`: genera config.toml inicial.
[x] 3.4  install.sh: detecta SO, baja binario correcto de GitHub Releases,
         verifica SHA256, instala, configura systemd/service.
[x] 3.5  install.ps1: equivalente para Windows.
[x] 3.6  systemd unit (Linux) + Windows Service.
[x] 3.7  CI release: build matrix por SO, artifacts separados, checksums.
[ ] 3.8  Dogfooding: VM limpia → `curl | bash` → `agentguard status` funciona.
```

**Gate:** En VM limpia Ubuntu, `curl https://get.agentguard.io | bash` deja daemon corriendo y CLI funcional. Solo se descarga `agentguard-cli` + `agentguard-linux`.

> **Nota 3.7:** El `install.sh` y `install.ps1` están listos y funcionales (verificados con dry-run). La publicación en GitHub Releases y el endpoint `get.agentguard.io` son tareas de infraestructura/DevOps, no de código.
> **Nota 3.8:** Requiere GitHub Releases con binarios publicados.
> 
> **Verificación Fase 3:**
> - `cargo build --workspace` → 0 errores, 0 warnings
> - `cargo test --workspace` → 99 passed, 0 failed
> - `cargo clippy --workspace -- -D warnings` → 0 warnings
> - `scripts/check-no-panic.sh` → 0 unwrap/expect/panic en producción
> - 13/13 comandos IPC funcionales en daemon
> - Scripts bootstrap listos para Linux y Windows
> - Scripts de desinstalación completos
> - `agentguard-windows` compila en Linux (stubs cross-platform + implementación completa en `#[cfg(windows)]`)
> - IPC server implementa `Incidents` (JSONL real), `Pause`/`Resume` (AtomicBool + auto-resume timer), `Protect`/`Unprotect` (mutación en runtime), `LaunchAgent` (sandbox con callback), `AddProtectedPath`
> - `StatusData` incluye `sandbox_mode`, `active_sandboxes` (conteo real), `capabilities` backward-compatible
> - Sandbox tracking: `Arc<RwLock<Vec<SandboxedAgent>>>` con notificaciones de escritorio vía `notify-rust`
> - Windows ETW + AppContainer/LPAC completo (compila en Windows, stub en Linux)

### Fase 4 — Windows daemon ✓ COMPLETADA (+ Fase 8 hardening)

```
[x] 4.1  agentguard-windows/guard.rs: WindowsGuard con SetNamedSecurityInfoW (DENY ACEs).
[x] 4.2  Detección de procesos agente: CreateToolhelp32Snapshot + ETW + polling sysinfo.
[x] 4.3  Job Objects para contener procesos AI.
[x] 4.4  Windows Service (SCM registration).
[x] 4.5  agentguard-windows/main.rs: entry point (core + WindowsGuard + service).
[x] 4.6  Inno Setup installer (packaging/windows/installer.iss).
[x] 4.7  v2.1: AppContainer/LPAC sandbox + ETW process watcher (cross-platform stubs en Linux).
[x] 4.8  **Fase 8**: AppContainer/LPAC sandbox real (FFI userenv.dll), PEB introspección
         (NtQueryInformationProcess vía ntdll.dll), Named Pipes IPC (daemon + CLI),
         tests E2E (15 nuevos tests Windows), installer Windows funcional.
```

**Gate:** En Windows 10/11, instalar → proteger carpeta → intentar borrar → Access Denied.
**Test:** 7 tests unitarios cross-platform + 15 tests E2E Windows (compilan en Linux,
ejecutan en Windows).
**Pendiente:** Test E2E requiere VM Windows física.
**Sandbox:** AppContainer funcional (Windows 8+), LPAC parcial (requiere capabilities SID).

### Fase 5 — Eliminada (macOS fuera de scope MVP)

```

### Fase 6 — TUI Terminal (ratatui + crossterm) ✓ COMPLETADA

```
[x] 6.1  agentguard-tui: ratatui 0.29 + crossterm 0.28 scaffold.
[x] 6.2  Dashboard (status + cards + activity).
[x] 6.3  Protected Zones (tabla de rutas).
[x] 6.4  Incidents (lista de violaciones).
[x] 6.5  Snapshots (lista + restore).
[x] 6.6  IPC client (reusa protocolo JSON-line del daemon).
[x] 6.7  Tema oscuro con colores del spec (#0f0f0f, #22c55e, #ef4444, #f59e0b).
[x] 6.8  Reemplaza agentguard-ui (Tauri) — terminal-first consistente.
```

**Gate:** TUI compila y funciona cross-platform (ratatui + crossterm).
**Controles:** 1-4 tabs, q quit, r refresh, p pause, Tab/arrows navegar.
**Binario:** ~4 MB (ratatui + crossterm sin dependencias nativas).

### Fase 7 — Auto-updater ✓ COMPLETADA

```
[x] 7.1  agentguard-core/updater.rs: check GitHub releases, semver compare.
[x] 7.2  Descargar asset correcto para OS/arch actual.
[x] 7.3  SHA256 verify + reemplazo atómico.
[x] 7.4  `agentguard update` comando CLI (check-only + full install).
[x] 7.5  4 tests unitarios (is_newer, platform_detect, same_version).
```

**Gate:** `agentguard update --check-only` consulta GitHub API, compara semver.

---

## 5. Checklist de verificación continua

Ejecutar antes de cada merge a `main`:

- `cargo fmt --check && cargo clippy --workspace -- -D warnings`
- `cargo test --workspace --exclude agentguard-ebpf`
- Build eBPF: `cargo +nightly build -p agentguard-ebpf --target bpfel-unknown-none -Z build-std=core`
- `grep -rn "\.unwrap\(\)\|\.expect\(" crates/*/src` → 0 hits (excluyendo `#[cfg(test)]`)
- Benchmark RAM/CPU del daemon idle ≤ umbrales README §2.

---

## 6. Entregables por fase

| Fase | Artefactos |
|---|---|
| 0 | Workspace reorganizado. Core + Linux + Windows crates compilando. |
| 1 | `agentguard-core` con vault, DLP, CA, IPC, eventos. ≥40 tests pasando. |
| 2 | Daemon Linux bloquea `unlink` real vía eBPF LSM + fallback userspace. |
| 3 | CLI funcional + installer que detecta SO y baja solo lo necesario. `curl` → listo. |
| 4 | Daemon Windows con NTFS DENY ACEs + Job Objects + ETW + AppContainer. |
| 5 | ~~macOS~~ (Eliminado del MVP). |
| 6 | TUI Terminal (ratatui + crossterm, 4 tabs) — reemplaza Tauri. |
| 7 | Auto-updater (ureq 3, GitHub Releases, SHA256, tar.gz, atomic replace). |

---

## 7. Riesgos y mitigaciones

- **eBPF LSM no disponible**: fallback userspace automático. Usar VM Ubuntu 24.04 para tests.
- **Windows requiere firma EV para driver kernel**: por eso usamos NTFS ACLs + Job Objects (userspace) en vez de driver. Protección al 95%.
- **HTTPS MITM rompe cert pinning**: whitelist de hosts a no-MITM, configurable.
- **Root en el daemon**: `AmbientCapabilities` mínimo, `ProtectHome=read-only`, `ProtectSystem=strict`.
- **Sincronización de versiones entre crates**: todos usan `version.workspace = true`. Release CI publica todos juntos.
