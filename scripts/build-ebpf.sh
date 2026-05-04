#!/usr/bin/env bash
# Build AgentGuard eBPF LSM programs.
#
# Compila file_guard.rs, net_guard.rs y process_exec.rs a bytecode BPF
# para el target bpfel-unknown-none usando nightly Rust.
#
# Salida: target/ebpf/file_guard, target/ebpf/net_guard,
#         target/ebpf/process_exec
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

# bpfel-unknown-none no tiene binarios precompilados.
# Se compila desde source con -Z build-std=core (requiere rust-src).
if ! rustup +nightly component list --installed | grep -q rust-src; then
    echo "ERROR: rust-src component not installed. Install with:"
    echo "  rustup +nightly component add rust-src"
    exit 1
fi

mkdir -p "$OUT_DIR"

(
    cd "$EBPF_CRATE"

    # Compilar file_guard y net_guard
    echo "  → file_guard..."
    cargo +nightly build --release \
        --target bpfel-unknown-none \
        -Z build-std=core

    # Los binarios quedan en <workspace>/target/ebpf-target/bpfel-unknown-none/release/
    # (configurado en crates/agentguard-ebpf/.cargo/config.toml)
    BIN_DIR="$PROJECT_ROOT/target/ebpf-target/bpfel-unknown-none/release"
    cp -f "$BIN_DIR/file_guard" "$OUT_DIR/file_guard"
    cp -f "$BIN_DIR/net_guard"  "$OUT_DIR/net_guard"
    cp -f "$BIN_DIR/process_exec" "$OUT_DIR/process_exec"
)

echo "=== Done: $OUT_DIR/file_guard, $OUT_DIR/net_guard, $OUT_DIR/process_exec ==="
