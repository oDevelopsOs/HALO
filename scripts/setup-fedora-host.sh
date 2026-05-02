#!/usr/bin/env bash
# ============================================================
#  AgentGuard — Host Setup para Fedora (KVM + libvirt)
# ============================================================
#
# Ejecutar UNA VEZ en el HOST Fedora.
# Crea una VM aislada con KVM, monta el workspace HALO,
# provisiona Rust + eBPF toolchain, y deja todo listo
# para correr `full-test.sh`.
#
# La VM tiene su propio kernel, memoria y filesystem.
# Si la VM explota, el host ni se entera.
# ============================================================

set -euo pipefail

GREEN='\033[32m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'; CYAN='\033[36m'
info()  { echo -e "${GREEN}→${NC} ${BOLD}$*${NC}"; }
cmd()   { echo -e "  ${CYAN}\$${NC} ${DIM}$*${NC}"; }
err()   { echo -e "${RED}ERROR:${NC} $*"; }

VM_NAME="agentguard-test"
VM_MEMORY=6144
VM_CPUS=4
VM_DISK=30
VM_IMAGE="/var/lib/libvirt/images/${VM_NAME}.qcow2"
ISO_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/41/Server/x86_64/iso/Fedora-Server-netinst-x86_64-41-1.4.iso"

# ── 1. Instalar KVM + libvirt ──────────────────────────────
step1_install_kvm() {
    info "1/5 Instalando KVM + libvirt..."

    sudo dnf groupinstall "Virtualization" -y 2>&1 | tail -3
    sudo dnf install virt-manager virt-install virt-viewer -y 2>&1 | tail -3

    sudo systemctl enable --now libvirtd

    # Añadir usuario al grupo libvirt
    sudo usermod -aG libvirt "$USER"

    info "KVM instalado. Cierra sesión y vuelve a entrar para aplicar el grupo,"
    info "o ejecuta: newgrp libvirt"
}

# ── 2. Crear VM ─────────────────────────────────────────────
step2_create_vm() {
    info "2/5 Creando VM '$VM_NAME'..."

    # Descargar Fedora Server netinst si no existe
    local iso; iso=$(basename "$ISO_URL")
    if [ ! -f "/tmp/${iso}" ]; then
        info "Descargando Fedora Server 41 netinst..."
        curl -L "$ISO_URL" -o "/tmp/${iso}" 2>&1 | tail -2
    fi

    # Crear disco
    if [ ! -f "$VM_IMAGE" ]; then
        qemu-img create -f qcow2 "$VM_IMAGE" "${VM_DISK}G"
    fi

    # Crear VM con virt-install
    sudo virt-install \
        --name "$VM_NAME" \
        --ram "$VM_MEMORY" \
        --vcpus "$VM_CPUS" \
        --disk path="$VM_IMAGE",size="$VM_DISK",format=qcow2 \
        --os-variant fedora-unknown \
        --network network=default \
        --graphics spice \
        --console pty,target_type=serial \
        --location "/tmp/${iso}" \
        --extra-args "inst.ks=file:/kickstart.cfg console=ttyS0,115200n8" \
        --initrd-inject /dev/stdin <<'KICKSTART'
# Kickstart mínimo para Fedora Server
text
network --bootproto=dhcp --device=link --activate
rootpw --plaintext agentguard
user --name=dev --password=agentguard --groups=wheel
keyboard us
lang en_US.UTF-8
timezone UTC
bootloader --location=mbr
zerombr
clearpart --all --initlabel
autopart
firstboot --disable
selinux --permissive
firewall --disabled
%packages
@core
@standard
curl
wget
git
gcc
gcc-c++
make
cmake
clang
llvm
lld
elfutils-libelf-devel
openssl-devel
pkg-config
python3
python3-pip
bpftool
libbpf
libbpf-devel
%end
%post --log=/root/kickstart-post.log
# Activar BPF LSM
grubby --update-kernel=ALL --args='lsm=lockdown,capability,yama,selinux,bpf'
# Habilitar acceso root SSH
mkdir -p /root/.ssh
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
systemctl enable sshd
%end
reboot
KICKSTART

    info "VM '$VM_NAME' creada. La instalación comenzará en una ventana."
    info "Si quieres instalación desatendida (sin GUI), usa la opción --graphics none"
    info "y completa la instalación por consola serie."
}

# ── 3. Post-instalación (montar workspace) ─────────────────
step3_mount_workspace() {
    info "3/5 Configurando montaje del workspace..."

    WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

    echo ""
    info "Después de que la VM esté instalada y funcionando:"
    echo ""
    cmd "virsh start $VM_NAME"
    echo ""
    info "Para montar el workspace dentro de la VM, usa virtiofs:"
    echo ""
    cmd "sudo mkdir -p /tmp/ag-workspace-share"
    cmd "sudo virsh edit $VM_NAME"
    echo ""
    echo "  Añade ESTO dentro de <devices>:"
    echo ""
    echo "  <filesystem type='mount' accessmode='passthrough'>"
    echo "    <source dir='${WORKSPACE_DIR}'/>"
    echo "    <target dir='workspace'/>"
    echo "  </filesystem>"
    echo ""
    echo "  Y asegúrate de que el kernel de la VM tiene soporte 9p:"
    echo "    (Fedora lo tiene por defecto)"
    echo ""
    info "Dentro de la VM, monta con:"
    cmd "sudo mkdir -p /workspace"
    cmd "sudo mount -t 9p -o trans=virtio workspace /workspace -oversion=9p2000.L"
}

# ── 4. Provisionar VM ───────────────────────────────────────
step4_provision() {
    info "4/5 Provisionando VM (Rust + eBPF + AgentGuard)..."

    echo ""
    info "Conecta a la VM:"
    cmd "virsh console $VM_NAME    # consola serie"
    cmd "virt-viewer $VM_NAME      # o interfaz gráfica"
    echo ""
    info "Dentro de la VM, como root, ejecuta:"
    cmd "sudo bash /workspace/test-env/provision-vm.sh"
    echo ""
    info "Esto instalará Rust, nightly, eBPF toolchain, creará"
    info "la zona de prueba y pre-compilará AgentGuard (~5-10 min)."
}

# ── 5. Ejecutar tests ──────────────────────────────────────
step5_run_tests() {
    info "5/5 Ejecutando suite completa de tests..."

    echo ""
    info "Dentro de la VM, como root:"
    cmd "sudo bash /workspace/test-env/full-test.sh"
    echo ""
    info "La suite ejecuta 15 pasos:"
    echo "  1. Verifica BPF LSM"
    echo "  2. Compila eBPF bytecodes"
    echo "  3. Compila agentguard-linux con eBPF"
    echo "  4. Compila agentguard CLI"
    echo "  5. Crea zona de prueba protegida"
    echo "  6. Genera config.toml"
    echo "  7. Arranca el daemon"
    echo "  8. Verifica IPC ping"
    echo "  9. Crea snapshot pre-ataque"
    echo "  10. Lanza agente rogue (8 ataques)"
    echo "  11. Verifica integridad de archivos"
    echo "  12. Restaura snapshot"
    echo "  13. Test DLP (API key blocking)"
    echo "  14. Verifica incidentes en disco"
    echo "  15. Apaga el daemon"
    echo ""
    info "Resultado esperado: 15 pass / 0 fail / X skip"
    echo ""
    info "Para repetir tests desde cero:"
    cmd "sudo virsh snapshot-revert $VM_NAME clean"
    cmd "sudo bash /workspace/test-env/full-test.sh"
}

# ── Main ────────────────────────────────────────────────────
echo "╔════════════════════════════════════════════╗"
echo "║   🛡  AGENTGUARD — HOST SETUP FEDORA       ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "Este script configura un entorno de pruebas"
echo "ULTRA-SEGURO con KVM para AgentGuard."
echo ""
echo "  ¿Qué hace?"
echo "  1. Instala KVM + libvirt"
echo "  2. Crea VM aislada de Fedora 41"
echo "  3. Configura montaje del workspace"
echo "  4. Provisiona VM (Rust, eBPF)"
echo "  5. Ejecuta suite de 15 tests"
echo ""
echo "  ¿Es seguro?"
echo "  SÍ. KVM aísla kernel, memoria y filesystem."
echo "  Si la VM explota, el host ni se entera."
echo ""
echo "════════════════════════════════════════════"
echo ""

if [ "${1:-}" = "--auto" ]; then
    info "Modo automático — ejecutando todos los pasos"
    step1_install_kvm
    step2_create_vm
    step3_mount_workspace
    step4_provision
    step5_run_tests
else
    echo "Selecciona qué hacer:"
    echo "  1) Instalar KVM + libvirt"
    echo "  2) Crear VM (Fedora Server 41)"
    echo "  3) Configurar montaje del workspace"
    echo "  4) Provisionar VM (Rust + eBPF)"
    echo "  5) Ejecutar suite de tests"
    echo "  0) Salir"
    echo ""
    read -r -p "Opción [0-5]: " choice

    case "$choice" in
        1) step1_install_kvm ;;
        2) step2_create_vm ;;
        3) step3_mount_workspace ;;
        4) step4_provision ;;
        5) step5_run_tests ;;
        *) echo "Ok. Para automatizar todo: bash $0 --auto" ;;
    esac
fi
