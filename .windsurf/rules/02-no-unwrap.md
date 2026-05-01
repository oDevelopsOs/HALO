---
trigger: always_on
description: Prohibition of panics, unwrap, and expect in production code
---

# No Unwrap / No Panic en producción

- **Prohibido** `.unwrap()`, `.expect("...")`, `panic!()`, `unreachable!()`, `todo!()` en código productivo (todo lo que está dentro de `crates/*/src/` fuera de bloques `#[cfg(test)]`).
- **Permitido** en:
  - Tests (`#[cfg(test)]`, `tests/`, `benches/`).
  - `build.rs`.
  - `fn main()` de binarios si se usa `anyhow::Result<()>` — pero preferir `?`.
- **Alternativas:**
  - `?` con tipo de error propio (`thiserror`) o `anyhow::Error`.
  - `.ok_or_else(|| MyError::...)` en vez de `.unwrap()` sobre `Option`.
  - `.context("what we were trying to do")` de `anyhow` cuando aporta diagnóstico.
- **CI guard:** el pipeline debe correr
  ```
  ! grep -RnE '\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unreachable!\(' \
      crates/*/src --include='*.rs' | grep -v '#\[cfg(test)\]'
  ```
  y fallar si hay matches.
- **Excepción documentada:** si es imprescindible (ej: invariante del verifier BPF, tipo `Infallible`), añadir comentario `// unwrap-ok: <razón>` en la línea anterior. El grep del CI ignorará esas líneas.
