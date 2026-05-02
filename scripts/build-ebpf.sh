#!/usr/bin/env bash
# Build AgentGuard eBPF LSM programs.
#
# Compila file_guard.rs y net_guard.rs a bytecode BPF para el target
# bpfel-unknown-none usando nightly Rust.
#
# Salida: target/ebpf/file_guard  y  target/ebpf/net_guard
#
# Requisitos:
#   - rustup instalado, toolchain nightly presente
#   - target bpfel-unknown-none instalado:
#       rustup +nightly target add bpfel-unknown-none
#   - llvm/clang para la generación de código BPF (bpf-linker)
#
# Uso: ./scripts/build-ebpf.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EBPF_CRATE="$PROJECT_ROOT/crates/agentguard-ebpf"
OUT_DIR="$PROJECT_ROOT/target/ebpf"

echo "=== Building eBPF programs ==="

# Verificar que nightly está disponible
if ! rustup run nightly cargo --version &>/dev/null; then
    echo "ERROR: nightly toolchain not found. Install with:"
    echo "  rustup toolchain install nightly"
    exit 1
fi

# Verificar el target BPF
if ! rustup +nightly target list --installed | grep -q bpfel-unknown-none; then
    echo "ERROR: bpfel-unknown-none target not installed. Install with:"
    echo "  rustup +nightly target add bpfel-unknown-none"
    exit 1
fi

mkdir -p "$OUT_DIR"

(
    cd "$EBPF_CRATE"

    # Compilar file_guard
    echo "  → file_guard..."
    cargo +nightly build --release \
        --target bpfel-unknown-none \
        -Z build-std=core

    # Copiar binarios sin extensión para que el build.rs del daemon los encuentre
    cp -f target/bpfel-unknown-none/release/file_guard "$OUT_DIR/file_guard"
    cp -f target/bpfel-unknown-none/release/net_guard  "$OUT_DIR/net_guard"
)

echo "=== Done: $OUT_DIR/file_guard, $OUT_DIR/net_guard ==="
