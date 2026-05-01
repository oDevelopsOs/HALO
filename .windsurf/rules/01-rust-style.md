---
trigger: always_on
description: Rust coding style and linting rules for AgentGuard
---

# Rust Style

- **Edition:** Rust 2021 en todos los crates del workspace.
- **Formato:** `cargo fmt` obligatorio antes de cada commit. `rustfmt.toml` en la raíz es la fuente de verdad.
- **Lints:** `cargo clippy --workspace --all-targets -- -D warnings` debe pasar en CI.
- **Errores:**
  - Librerías (`agentguard-common`, módulos reutilizables): usar `thiserror` para definir enums de error concretos.
  - Binarios (`agentguard-daemon`, `agentguard-cli`): usar `anyhow::Result` en `main()` y en funciones top-level.
  - Nunca convertir un error a string prematuramente; preservar la cadena con `#[source]` o `?`.
- **Docstrings:** todas las funciones `pub` deben tener `///` con al menos una línea describiendo qué hacen y bajo qué condiciones retornan error.
- **Imports:** agrupados por std → crates externos → crates internos, separados por línea en blanco.
- **Async:** `tokio` con features explícitos (nunca `features = ["full"]` salvo en el binario daemon). Evitar `block_on` fuera de `main`.
- **`unsafe`:** cada bloque `unsafe` requiere comentario `// SAFETY:` justificando los invariantes.
