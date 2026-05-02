#!/usr/bin/env bash
# ============================================================
#  AgentGuard — VM Provision (ejecutar UNA VEZ dentro de la VM)
# ============================================================
#
# Prepara una VM recién instalada para probar AgentGuard.
# Compatible con Fedora 41+ y Ubuntu 24.04+.
#
# Instala:
#   - Rust (stable + nightly con eBPF target)
#   - Dependencias de compilación (clang, llvm, libelf, etc.)
#   - Herramientas de test (curl, python3, etc.)
#   - Directorios protegidos de prueba
#   - Montaje del workspace
#
# Uso (DENTRO de la VM, como root):
#   sudo bash /workspace/test-env/provision-vm.sh
# ============================================================

set -euo pipefail

GREEN='\033[32m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${GREEN}→${NC} ${BOLD}$*${NC}"; }

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: ejecutar como root (sudo)"
    exit 1
fi

echo "╔════════════════════════════════════════════╗"
echo "║   🛡  AgentGuard VM Provision              ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ── Detectar distro ────────────────────────────────────────
if [ -f /etc/fedora-release ]; then
    DISTRO="fedora"
    PKG_MGR="dnf install -y"
    info "Distro detectada: Fedora"
elif [ -f /etc/lsb-release ] && grep -q Ubuntu /etc/lsb-release; then
    DISTRO="ubuntu"
    PKG_MGR="apt-get install -y -qq"
    info "Distro detectada: Ubuntu"
else
    echo "ERROR: solo Fedora y Ubuntu son soportados"
    exit 1
fi

# ── 1. Paquetes del sistema ────────────────────────────────
info "1/7 Instalando paquetes del sistema..."

if [ "$DISTRO" = "fedora" ]; then
    dnf update -y --refresh 2>/dev/null || true
    dnf install -y \
        curl wget git \
        gcc gcc-c++ make cmake \
        clang llvm lld \
        elfutils-libelf-devel \
        openssl-devel \
        pkg-config \
        python3 \
        bpftool libbpf libbpf-devel \
        2>&1 | tail -5
elif [ "$DISTRO" = "ubuntu" ]; then
    apt-get update -qq
    apt-get install -y -qq \
        curl wget git \
        build-essential cmake \
        clang llvm lld \
        libelf-dev \
        libssl-dev \
        pkg-config \
        python3 \
        linux-headers-$(uname -r) \
        2>&1 | tail -5
fi

info "Paquetes instalados"

# ── 2. Rust ─────────────────────────────────────────────────
info "2/7 Instalando Rust..."

if ! command -v rustup &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi

rustup default stable
info "Rust stable: $(rustc --version)"

# ── 3. Nightly + BPF target ─────────────────────────────────
info "3/7 Instalando toolchain nightly + BPF target..."

rustup toolchain install nightly 2>/dev/null || true
rustup +nightly target add bpfel-unknown-none 2>/dev/null || true
rustup component add rust-src --toolchain nightly 2>/dev/null || true

if rustup run nightly rustc --version &>/dev/null; then
    info "Nightly instalado: $(rustup run nightly rustc --version)"
else
    echo "  ⚠ Nightly no disponible — eBPF no se compilará"
fi

# ── 4. Verificar BPF LSM ────────────────────────────────────
info "4/7 Verificando BPF LSM en el kernel..."

KERNEL=$(uname -r)
echo "  Kernel: $KERNEL"

if [ -r /sys/kernel/security/lsm ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    echo "  LSM activos: $LSM"
    if echo "$LSM" | tr ',' '\n' | grep -qx bpf; then
        info "✓ BPF LSM ACTIVO — protección kernel-level disponible"
    else
        echo "  ⚠ BPF LSM NO activo"
        echo "  → El daemon usará fallback userspace (notify)"
        echo ""
        if [ "$DISTRO" = "fedora" ]; then
            echo "  Para activar (Fedora):"
            echo "    sudo grubby --update-kernel=ALL --args='lsm=lockdown,capability,yama,selinux,bpf'"
        elif [ "$DISTRO" = "ubuntu" ]; then
            echo "  Para activar (Ubuntu):"
            echo "    sudo sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 lsm=...,bpf\"/' /etc/default/grub"
            echo "    sudo update-grub"
        fi
        echo "    sudo reboot"
    fi
else
    echo "  ⚠ No se puede leer /sys/kernel/security/lsm"
fi

# ── 5. Directorios protegidos ───────────────────────────────
info "5/7 Creando zona de prueba protegida..."

mkdir -p /protected/ag-test-zone/nested/sub \
         /protected/ag-secrets \
         /etc/agentguard \
         /var/lib/agentguard/{vault,ca} \
         /var/log/agentguard \
         /run/agentguard

echo "# Documento IMPORTANTE" > /protected/ag-test-zone/important.md
echo "# Datos sensibles" > /protected/ag-test-zone/data.txt
echo "# Anidado profundo" > /protected/ag-test-zone/nested/deep.md
echo "# Triple anidado" > /protected/ag-test-zone/nested/sub/leaf.md
cat > /protected/ag-secrets/.env <<'SECRETS'
API_KEY=sk-1234567890abcdef1234567890abcdef1234567890abcdef
DATABASE_URL=postgres://user:hunter2@localhost/prod
GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SECRETS
chmod 600 /protected/ag-secrets/.env

info "Zona de prueba creada en /protected/"

# ── 6. Verificar workspace ──────────────────────────────────
info "6/7 Verificando montaje del workspace..."

if [ -d /workspace/Cargo.toml ] && [ -d /workspace/crates ]; then
    info "✓ Workspace montado en /workspace"
else
    echo "  ⚠ Workspace NO encontrado en /workspace"
    echo "  Monta el repo con:"
    echo "    virt-manager → Add Hardware → Filesystem"
    echo "    Source: $(pwd)/HALO"
    echo "    Target: /workspace"
    echo ""
    echo "  O con Vagrant:"
    echo "    config.vm.synced_folder '.', '/workspace', type: 'virtiofs'"
fi

# ── 7. Compilar una vez para cachear ────────────────────────
info "7/7 Pre-compilando AgentGuard (esto toma unos minutos)..."

if [ -d /workspace/Cargo.toml ]; then
    cd /workspace
    cargo build --release -p agentguard-core 2>&1 | tail -3
    cargo build --release -p agentguard-linux 2>&1 | tail -3
    cargo build --release -p agentguard-cli 2>&1 | tail -3
    info "✓ Pre-compilación completada"
else
    echo "  Saltado: workspace no disponible"
fi

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║   ✓ VM PROVISIONADA — lista para tests     ║"
echo "╠════════════════════════════════════════════╣"
echo "║                                            ║"
echo "║  Ejecutar tests:                           ║"
echo "║    sudo /workspace/test-env/full-test.sh    ║"
echo "║                                            ║"
echo "║  Toma snapshot ANTES de tests:             ║"
echo "║    virsh snapshot-create-as agentguard-vm   ║"
echo "║      --name clean --description \"Limpio\"  ║"
echo "║                                            ║"
echo "║  Restaurar si se rompe:                    ║"
echo "║    virsh snapshot-revert agentguard-vm clean║"
echo "║                                            ║"
echo "╚════════════════════════════════════════════╝"
