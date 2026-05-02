#!/usr/bin/env bash
# dev-reset.sh — Reinstala el daemon en entorno de desarrollo/testing.
#
# Idempotente: reconstruye, reinstala, recarga systemd y limpia vault de pruebas.
# Uso: ./scripts/dev-reset.sh [--no-ebpf]
#
# Requisitos: compilar en el host, ejecutar en VM de pruebas con el
# workspace montado en /workspace.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EBPF_FLAG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --no-ebpf) EBPF_FLAG="" ;;
        *) ;;
    esac
    shift
done

echo "=== dev-reset: AgentGuard ==="

# 1. Build
echo "[1/5] Compilando agentguard-linux..."
cd "$PROJECT_ROOT"
if [ -n "$EBPF_FLAG" ]; then
    ./scripts/build-ebpf.sh
    cargo build --release -p agentguard-linux --features ebpf
else
    cargo build --release -p agentguard-linux
fi

# 2. Parar daemon existente
echo "[2/5] Parando daemon anterior..."
sudo systemctl stop agentguard 2>/dev/null || true

# 3. Instalar binario
echo "[3/5] Instalando binario..."
sudo cp -f target/release/agentguard-linux /usr/local/bin/agentguard-linux

# 4. Recargar systemd
echo "[4/5] Recargando systemd..."
sudo cp -f packaging/linux/agentguard.service /etc/systemd/system/agentguard.service
sudo systemctl daemon-reload

# 5. Arrancar
echo "[5/5] Arrancando daemon..."
sudo systemctl start agentguard

sleep 1
if systemctl is-active --quiet agentguard; then
    echo ""
    echo "✓ Daemon corriendo. Verifica:"
    echo "  sudo journalctl -u agentguard -n 20"
    echo "  agentguard status"
else
    echo ""
    echo "✗ El daemon no arrancó:"
    sudo journalctl -u agentguard -n 30 --no-pager
    exit 1
fi
