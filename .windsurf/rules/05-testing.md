---
trigger: always_on
description: Testing discipline for AgentGuard
---

# Testing

- **Todo módulo nuevo** en `crates/*/src/` requiere un bloque `#[cfg(test)] mod tests` con al menos un test del happy path y uno de error.
- **Módulos críticos** (`vault.rs`, `dlp_proxy.rs`, `kernel_loader.rs`, `config.rs`, `ipc_server.rs`) requieren tests de integración en `tests/integration/`.
- **No debilitar ni eliminar tests** sin justificación explícita en el commit message (`test: remove X because Y`).
- **Tests eBPF:** usar `vmtest` o ejecutar en la VM de dev (docs/DEV_ENV.md). Los tests que requieren kernel BPF LSM deben ir bajo `#[cfg(feature = "ebpf-integration")]` y skip por defecto en CI de PR.
- **Fixtures:** usar `tempfile::TempDir` para filesystem. Nunca tocar `$HOME` del desarrollador.
- **Async tests:** `#[tokio::test]` con runtime multi-thread solo si es necesario.
- **Proptest / fuzz:** para parsers (config.toml, regex DLP) recomendado añadir `proptest` cuando haya cobertura insuficiente de inputs.
- **Coverage mínima objetivo:** 70% en `agentguard-common`, `vault.rs`, `dlp_proxy.rs` (medida con `cargo llvm-cov` en CI nightly).
- **Tests de rendimiento:** `benches/` con `criterion` para vault (snapshot de 10k files), DLP (throughput de regex match). Gate: regresión >20% bloquea merge.
