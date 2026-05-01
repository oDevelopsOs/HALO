# Changelog

Todas las novedades notables de este proyecto se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
versionado [SemVer](https://semver.org/lang/es/).

## [Unreleased]

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

### Pending
- 1.5 real: aya + build.rs que compile `crates/agentguard-ebpf/` + `include_bytes_aligned!` del bytecode + hooks LSM reales. Iterar en VM con BPF LSM.
- Fase 2: DLP proxy (hyper + rustls + rcgen MITM), IPC server (interprocess), CLI cableada.
