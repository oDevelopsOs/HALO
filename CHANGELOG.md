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

### Pending
- 1.5 `agentguard-ebpf/file_guard.rs` real (aya + build.rs + kernel_loader en daemon).
- 1.6 `kernel_loader.rs` con population de mapa BPF y ring buffer reader.
- 1.8 Fallback userspace con `notify`.
- Fase 2+: DLP proxy, IPC, CLI cableada.
