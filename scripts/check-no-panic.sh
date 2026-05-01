#!/usr/bin/env bash
# Guard de CI: prohíbe .unwrap() / .expect(...) / panic!() / todo!() /
# unreachable!() en código productivo.
#
# Reglas:
#   - Solo revisa archivos .rs en crates/*/src/ (excluye agentguard-ebpf,
#     que puede tener patrones diferentes por el verifier BPF).
#   - Ignora el contenido de bloques `#[cfg(test)] mod <nombre> { ... }`
#     (se rastrea la profundidad de llaves después del atributo).
#   - Ignora líneas con comentario `// unwrap-ok: <razón>` o que ya están
#     comentadas (`//`, `/*`).
#
# Salida:
#   0 si el código cumple la regla.
#   1 si hay violaciones (lista detallada en stderr).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

violations=$(
  find "${ROOT}/crates" -path '*/src/*.rs' \
        -not -path '*/agentguard-ebpf/*' \
        -print0 \
    | xargs -0 awk '
        BEGIN { in_test = 0; depth = 0; pending = 0 }

        # Detectar atributo #[cfg(test)] (en su propia línea o antes de mod)
        /^[[:space:]]*#\[cfg\(test\)\]/ { pending = 1; next }

        {
          line = $0

          # Si venimos de #[cfg(test)] y encontramos un bloque que abre {,
          # entramos en contexto de test
          if (pending && match(line, /\{/)) {
            in_test = 1
            depth = 1
            pending = 0
            # Contar llaves adicionales en la misma línea
            for (i = index(line, "{") + 1; i <= length(line); i++) {
              c = substr(line, i, 1)
              if (c == "{") depth++
              else if (c == "}") depth--
            }
            if (depth == 0) in_test = 0
            next
          }
          # Atributo sin bloque: cancelar pending
          if (pending && line !~ /^[[:space:]]*$/ && line !~ /^[[:space:]]*#\[/) {
            pending = 0
          }

          if (in_test) {
            for (i = 1; i <= length(line); i++) {
              c = substr(line, i, 1)
              if (c == "{") depth++
              else if (c == "}") { depth--; if (depth == 0) { in_test = 0; break } }
            }
            next
          }

          # Ignorar líneas comentadas o con marker unwrap-ok
          if (line ~ /unwrap-ok:/) next
          if (line ~ /^[[:space:]]*\/\//) next

          # Buscar patrones prohibidos
          if (line ~ /\.unwrap\(\)/ \
              || line ~ /\.expect\(/ \
              || line ~ /panic!\(/ \
              || line ~ /todo!\(/ \
              || line ~ /unreachable!\(/) {
            printf "%s:%d: %s\n", FILENAME, FNR, line
          }
        }
      '
)

if [ -n "${violations}" ]; then
    echo "::error::Forbidden panic/unwrap/expect in production code:" >&2
    echo "${violations}" >&2
    echo "" >&2
    echo "Fix: use ? with thiserror/anyhow, or annotate the line with" >&2
    echo "     '// unwrap-ok: <reason>' if strictly necessary." >&2
    exit 1
fi

echo "No forbidden panic patterns found in production code."
