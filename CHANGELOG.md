# Changelog

Todas las novedades notables de este proyecto se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
versionado [SemVer](https://semver.org/lang/es/).

## [Unreleased]

### Added — v2.1 Módulo 10: Sandbox Launcher + Detección Automática de Agentes IA

**Core types:**
- `agentguard-common`: `AgentSpawnEvent` (repr(C), no_std), `SandboxMode` enum, `SandboxedAgent` struct, `IpcCommand::LaunchAgent`/`AddProtectedPath`, `IpcResponse::AgentLaunched`, `StatusData` ampliado.
- `agentguard-core::events`: `SecurityEvent::AgentDetected` y `SecurityEvent::AgentSandboxed`.
- `agentguard-core::config`: `SandboxConfig`, `AgentDetection` + `KnownAgent`, `WindowsConfig`.

**IPC & tracking:**
- `agentguard-core::ipc_server`: `LaunchAgent` handler con callback inyectable, `AddProtectedPath` handler, builder con `launch_agent_fn()`, `active_sandboxes()`, `incidents_count()`. Contadores reales en `StatusData`.

**eBPF (kernel):**
- `agentguard-ebpf`: programa `process_exec` — tracepoint `sched_process_exec` con mapa `KNOWN_AGENTS` (hash FNV-1a) y ring buffer.

**Linux daemon:**
- `agentguard-linux::sandbox`: Bubblewrap sandbox launcher, namespaces, DLP proxy injection, `check_capabilities()`, degradación automática. 4 tests.
- `agentguard-linux::landlock`: Perfil Landlock ABI V3 (modo hybrid).
- `agentguard-linux::process_watcher`: Carga eBPF + loop ring buffer + lógica sandbox/monitor. 2 tests.
- `agentguard-linux::main`: Sandbox capabilities check, ProcessWatcher startup, desktop notifications (notify-rust), sandbox tracking, incident counter.

**Windows daemon (completo, compila en Linux como stub):**
- `agentguard-windows::process_watcher`: ETW consumer (`sched_process_exec` vía `StartTraceW`/`OpenTraceW`/`ProcessTrace`) + polling fallback (`sysinfo`).
- `agentguard-windows::sandbox`: AppContainer/LPAC sandbox (`CreateAppContainerProfile` + `CreateProcessW` con `SECURITY_CAPABILITIES` + DENY ACEs vía `SetNamedSecurityInfoW`).

**CLI:**
- Comandos `launch` (lanza agente en sandbox), `check` (verifica capacidades), `setup` (configuración interactiva).
- Config default actualizado con secciones v2.1.

**Tests:**
- 3 nuevos tests de integración en `agentguard-linux/tests/sandbox_integration.rs`.
- 99 tests totales (0 fallos).

**Verification:**
- `cargo build --workspace` → 0 errores, 0 warnings
- `cargo test --workspace` → 99 passed, 0 failed
- `cargo clippy --workspace -- -D warnings` → 0 warnings
- `scripts/check-no-panic.sh` → 0 unwrap/expect/panic

### Added — Fase 0 (bootstrap)
- Workspace Cargo con crates `agentguard-common`, `agentguard-daemon`, `agentguard-cli`, `agentguard-ebpf`, `agentguard-ui`.
- Reglas Windsurf en `.windsurf/rules/` (estilo Rust, no-unwrap, eBPF safety, security logging, testing, IPC contract, paths/privileges).
- Licencias dual (GPL v2 para `agentguard-ebpf`, BSL 1.1 para daemon/CLI/UI).
- Pipeline CI (`fmt` + `clippy` + `test` + `no-panic-guard` + build eBPF nightly).
- `scripts/check-no-panic.sh`: guard awk stateful que ignora bloques `#[cfg(test)]`.
- `docs/DEV_ENV.md`: setup host, Multipass, troubleshooting.
- `test-env/`: contenedor Docker privilegiado + `simulate_ai_agent.rs` (8 ataques) + `run-tests.sh` (suite de 12 pruebas).

### Added — Fase 1 (parcial: 1.1–1.4)
- `agentguard-common`: `FileEvent`, `NetworkEvent`, `PathPrefix`, `EventType`, constantes `MAX_PREFIX_LEN`, `MAX_PREFIXES`, `COMM_LEN`, `IPC_PROTOCOL_VERSION`.
- `agentguard-daemon::config`: carga y validación de `config.toml` (expansión de `~`, regex DLP, acción `block|alert|log`). Tests: 8.
- `agentguard-daemon::vault`: snapshot/restore/list/cleanup con deduplicación BLAKE3 y manifest JSON. Preserva permisos Unix. Tests unitarios: 7, integración: 3.
- `agentguard-daemon` bin: scaffold que carga config, crea vault, ejecuta startup snapshot y espera `SIGINT`.

### Added — Fase 1 (1.5 skeleton + 1.8 fallback)
- `agentguard-daemon::events`: `SecurityEvent` (FileViolation / DlpViolation / SystemError) + `ViolationKind`, con schema estable de JSON para `incidents.jsonl`. 2 tests (incluye guardarrail "el JSON NO contiene el valor del secreto").
- `agentguard-daemon::guard`: trait `KernelGuard` + `ProtectionLevel` (KernelDenial vs UserspaceObservation) + `select_guard()` que elige el mejor backend disponible.
- `agentguard-daemon::guard::userspace`: backend con `notify` que observa rutas y emite `SecurityEvent` por cada delete/rename/write/create. Funciona en cualquier kernel. 3 tests.
- `agentguard-daemon::guard::ebpf` (feature `ebpf`, Linux): skeleton con chequeo real de `/sys/kernel/security/lsm`. Devuelve `Unavailable` hasta cablear aya + build.rs.
- `main.rs`: event loop con `tokio::select!` que consume del guard, loggea la violación, y dispara snapshot reactivo si `on_violation.snapshot_on_violation`.

### Added — Fase 2.1 (DLP proxy HTTP)
- `agentguard-daemon::dlp::patterns`: catálogo de 14 patrones built-in (OpenAI, Anthropic, GitHub tokens, AWS, Google, Stripe, Slack, private keys), compilación de custom patterns del config, `first_match()` que devuelve solo el nombre (nunca el valor). 9 tests.
- `agentguard-daemon::dlp::proxy`: proxy HTTP con hyper 1.x, límite de 2 MiB para el escaneo de body, fail-open para uploads grandes, forward transparente con hyper-util. Respeta las 3 acciones (`block` / `alert` / `log`) y emite `DlpViolation` por canal mpsc. 7 tests incluyendo E2E con raw sockets.
- CONNECT tunneling → 501 hasta que llegue HTTPS MITM (Fase 2.3).
- Integración en `main.rs`: proxy arranca automáticamente si `dlp.enabled = true`, compartiendo el canal de eventos con el guard.

Verificado E2E: `curl -x http://127.0.0.1:7771 -d 'sk-...' http://dest/` → `HTTP 403`. Rutas DELETE dispararon snapshot reactivo simultáneamente.

### Added — Fase 2.2 (CA root local)
- `agentguard-daemon::ca`: `LocalCa` con ECDSA self-signed root (validez 10 años, CN `"AgentGuard DLP Local Root CA"`) generado con `rcgen`.
- `load_or_generate()` idempotente: genera la primera vez, recarga en siguientes arranques.
- Persistencia en `~/.agentguard/ca/` (modo usuario) o `/var/lib/agentguard/ca/` (modo servicio). Permisos `0o700` dir, `0o644` cert, `0o600` key.
- `Debug` impl redactado (la clave privada no aparece en logs accidentalmente).
- Detección de directorio corrupto (cert sin key o viceversa).
- Daemon genera la CA en primer boot y muestra la ruta del cert para que el usuario la añada al trust store.

### Added — Fase 2.3 (HTTPS MITM)
- `DlpProxy` acepta `LeafIssuer` opcional via `with_tls()` builder. CONNECT con TLS → 200 + MITM; sin TLS → 501.
- `do_connect_mitm()`: downcast del `Upgraded` de hyper a `TokioIo<TcpStream>`, TLS handshake con el cliente (leaf cert via `LeafIssuer`), conexión upstream via `tokio-rustls` con verificación `webpki-roots`.
- `PrependBuf<R>` wrapper que reintroduce bytes del `read_buf` de hyper al stream antes del handshake TLS.
- Forward bidireccional con escaneo DLP del tráfico client→upstream (block/alert/log). 1 test E2E.
- Cableado en `main.rs`: `LeafIssuer` se construye desde la CA y se pasa al proxy.
- Bugfix: `tls.rs` — definición de `struct Inner` faltante + API correcta de `rcgen::CertificateParams::signed_by` (3 args).

### Added — Fase 1.5 (eBPF real)

- `crates/agentguard-ebpf/`: programas eBPF reales — `file_guard.rs` con hooks LSM `file_unlink` / `file_rename` / `file_open`, resolución de path vía `bpf_d_path`, comparación contra array map `PROTECTED_PREFIXES`, eventos a ring buffer. `net_guard.rs` con hook `socket_connect` (esqueleto funcional).
- `scripts/build-ebpf.sh`: compila los programas a bytecode BPF con `cargo +nightly --target bpfel-unknown-none`.
- `crates/agentguard-daemon/build.rs`: con `--features ebpf`, embeber los bytecodes `.bpf.o` en el binario via `include_bytes_aligned!`.
- `crates/agentguard-daemon/Cargo.toml`: `aya` / `aya-log` como dependencias opcionales tras la feature `ebpf`.
- `agentguard-daemon::guard::ebpf`: `EbpfGuard` real — carga programas con `BpfLoader`, attacha hooks LSM, pobla `PROTECTED_PREFIXES`, lee ring buffer con `poll_wait()`, parsea eventos a `SecurityEvent`.
- Fallback userspace (`select_guard`) sin cambios: si la feature `ebpf` no está activa o el kernel no tiene BPF LSM, el daemon usa `notify`.

### Added — Fase 2.6 (IPC server + CLI vía socket)

- `agentguard-common::ipc`: `IpcCommand` / `IpcResponse` / `SnapshotInfo` (serde JSON, feature `std`). Constantes `IPC_SOCKET_PATH`, `IPC_PIPE_NAME`.
- `agentguard-daemon::ipc_server`: `IpcServer` con socket Unix (`std::os::unix::net::UnixListener`), protocolo JSON-line. Comandos: `Status`, `Protect`, `Unprotect`, `SnapshotCreate`, `SnapshotList`, `SnapshotRestore`, `SnapshotCleanup`, `Incidents` (stub), `Pause`/`Resume` (stub), `Ping`. 3 tests.
- `agentguard-daemon::main.rs`: arranque del IPC server en su propio thread con runtime tokio; shutdown al salir.
- `agentguard-cli`: conecta al socket IPC, serializa el comando a JSON, muestra respuesta formateada (tabla, colores, timestamps).

### Fixed
- `LocalCa`: guarda `Arc<Certificate>` + `Arc<KeyPair>` para consistencia entre cert original y leaf certs.
- `LeafIssuer`: usa objetos rcgen directos en vez de reconstruir desde PEM.
- `tls.rs`: `signed_by` con 3 argumentos (corrección de API rcgen 0.13).

### Added — Fase 1.6 (file_open + PROTECTED_WRITE_PATHS)

- `agentguard-ebpf::file_guard.rs`: hook LSM `file_open` implementado — bloquea escritura sobre archivos individuales protegidos (`.env`, credenciales). Nuevos mapas BPF: `PROTECTED_WRITE_PATHS` (array de `PathPrefix`, coincidencia exacta) y `WRITE_PATH_COUNT`. Resolución de ruta desde `struct file *` via `file->f_path`.
- `agentguard-daemon::guard::ebpf`: `populate_write_paths()` pobla el mapa desde `config.protected_files`. `select_guard()` y `EbpfGuard::try_load()` aceptan `protected_files`.
- `agentguard-daemon::main.rs`: pasa `config.protected_files` a `select_guard`.

### Pending
- 2.7: detección de procesos agente (match por exe/argv/env).
- eBPF kernel testing (requiere VM con BPF LSM).

### Added — Fase 3 (CLI cross-platform + Installer)

- `agentguard-core::ipc_server`: Comandos `Incidents` (lectura real de JSONL), `Pause`/`Resume` (flag atómico con auto-resume timer), `Protect`/`Unprotect` (mutan config en runtime vía `RwLock<Config>`). Builder pattern con `.incidents_log()` y `.paused()`. Cero `.unwrap()` en producción.
- `agentguard-cli`: Output muestra estado `paused` (⏸ PAUSED). Fix mapping de `Incidents.last` a `Option<usize>`. Función `yellow()` renombrada (sin underscore).
- `IpcResponse::StatusData`: Nuevo campo `paused: bool` (backward-compatible con `#[serde(default)]`).
- `agentguard-linux/src/main.rs`: IPC server con builder + incidents log + paused flag. Event loop respeta pausa (loguea incidentes pero no reacciona).
- `agentguard-windows/src/main.rs`: Igual que Linux. Corrección de `.expect()` por manejo explícito de error en `Runtime::new()`.
- `agentguard-windows/src/guard.rs`: Compilación cross-platform (stubs en Linux con `#[cfg(windows)]`). Lectura de PEB para command line de otro proceso. Matching por `argv_contains_any`. Job Objects uno por proceso. 7 tests.
- `packaging/install.sh`: Bootstrap Linux/macOS — detecta SO/arch, descarga binarios de GitHub Releases, verifica SHA-256, instala systemd/launchd, genera config, añade CA al trust store.
- `packaging/install.ps1`: Bootstrap Windows — detecta arch, descarga binarios, verifica SHA-256, registra Windows Service, genera config.
- `packaging/uninstall.sh` + `packaging/uninstall.ps1`: Scripts de desinstalación completa (binarios, servicio, CA, datos).
- `packaging/macos/com.agentguard.daemon.plist`: LaunchDaemon plist para macOS.
- `packaging/windows/`: Directorio preparado para Inno Setup installer (Fase 4.6).

### Fixed
- `agentguard-core::config`: Clippy `derivable_impls` — `#[derive(Default)]` reemplaza `impl Default for Config` manual.
- `agentguard-core::vault`: Clippy `unnecessary_sort_by` → `sort_by_key`.
- `agentguard-core::ipc_server`: Clippy `io_other_error` → `std::io::Error::other`.
- `agentguard-core::dlp::proxy`: Clippy `too_many_arguments` → `#[allow]`.
- `agentguard-core::config::from_str`: Clippy `should_implement_trait` → `#[allow]`.
- Prohibido `.unwrap()`/`.expect()` en producción: `ipc_server.rs` usa `read_config()`/`write_config()` con manejo de `PoisonError`. `main.rs` Windows maneja `Runtime::new()` sin expect.

### Verificación
- `cargo build --workspace` → 0 errores, 0 warnings
- `cargo test --workspace` → 84 passed, 0 failed
- `cargo clippy --workspace -- -D warnings` → 0 warnings
- `scripts/check-no-panic.sh` → 0 unwrap/expect/panic en producción
