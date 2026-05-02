#!/usr/bin/env bash
# setup-vm.sh — Prepara una VM Ubuntu 24.04 para tests de AgentGuard.
#
# Ejecutar UNA VEZ en la VM:
#   sudo ./test-env/setup-vm.sh
#
# Instala: Rust, dependencias de compilación, crea zona de test protegida.

set -euo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: ejecutar como root (sudo)"
    exit 1
fi

echo "=== AgentGuard VM Setup ==="

# 1. Dependencias del sistema
echo "[1/6] Instalando paquetes del sistema..."
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    curl \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    libssl-dev \
    linux-headers-$(uname -r) \
    ca-certificates

# 2. Rust
echo "[2/6] Instalando Rust..."
if ! command -v cargo &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# 3. Nightly + eBPF target
echo "[3/6] Instalando toolchain nightly + BPF target..."
rustup toolchain install nightly
rustup +nightly target add bpfel-unknown-none
rustup component add clippy rustfmt

# 4. Verificar BPF LSM
echo "[4/6] Verificando BPF LSM..."
if [ -r /sys/kernel/security/lsm ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    echo "  LSM activos: $LSM"
    if echo "$LSM" | tr ',' '\n' | grep -qx bpf; then
        echo "  ✓ BPF LSM activo"
    else
        echo "  ⚠ BPF LSM no activo — añade 'lsm=...,bpf' a GRUB_CMDLINE_LINUX en /etc/default/grub"
        echo "  y ejecuta 'update-grub && reboot'"
    fi
else
    echo "  ⚠ No se puede leer /sys/kernel/security/lsm"
fi

# 5. Crear directorios de test
echo "[5/6] Creando zona de test..."
mkdir -p /protected/test-zone/nested /protected/test-zone/sub/deeper /protected/secrets
echo "# Documento importante" > /protected/test-zone/important.md
echo "# Anidado" > /protected/test-zone/nested/deep.md
echo "API_KEY=sk-TEST1234567890abcdef1234567890abcdef12345678" > /protected/secrets/.env
chmod -R 755 /protected

# 6. Directorios del daemon
echo "[6/6] Creando directorios del daemon..."
mkdir -p /etc/agentguard /var/lib/agentguard/vault /var/lib/agentguard/ca /var/log/agentguard /run/agentguard

echo ""
echo "✓ VM lista para tests de AgentGuard."
echo "  Montar el workspace: mount -t 9p -o trans=virtio /workspace /workspace"
echo "  Ejecutar tests:      sudo /workspace/test-env/vm-test.sh"
