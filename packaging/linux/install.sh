#!/usr/bin/env bash
# agentguard-install.sh — Linux bootstrap installer.
#
# Detecta el SO y arquitectura, descarga el binario correcto desde
# GitHub Releases, verifica SHA256, instala y configura systemd.
#
# Uso: curl -fsSL https://get.agentguard.io | bash
#      o local: ./packaging/linux/install.sh

set -euo pipefail

REPO="${AGENTGUARD_REPO:-tuorg/agentguard}"
VERSION="${AGENTGUARD_VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/agentguard}"
DATA_DIR="${DATA_DIR:-/var/lib/agentguard}"

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}==>${RESET} ${BOLD}${*}${RESET}"; }
warn()  { echo -e "${YELLOW}⚠${RESET}  ${*}"; }
error() { echo -e "${RED}✗${RESET}  ${*}" >&2; exit 1; }

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *) error "Arquitectura no soportada: $arch" ;;
    esac
}

detect_ebpf() {
    local lsm
    if [ -r /sys/kernel/security/lsm ]; then
        lsm=$(cat /sys/kernel/security/lsm)
        if echo "$lsm" | tr ',' '\n' | grep -qx bpf; then
            echo "kernel-ebpf"
            return
        fi
    fi
    echo "userspace"
}

main() {
    info "AgentGuard Linux Installer"
    echo "  repo    = $REPO"
    echo "  version = $VERSION"
    echo ""

    TARGET=$(detect_arch)
    PROTECTION=$(detect_ebpf)
    info "Arquitectura: $TARGET"
    info "Protección:   $PROTECTION"
    echo ""

    # 1. Descargar binarios
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    if [ "$VERSION" = "latest" ]; then
        DL_URL="https://github.com/${REPO}/releases/latest/download"
    else
        DL_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    info "Descargando agentguard-cli..."
    curl -fsSL "${DL_URL}/agentguard-cli-${TARGET}" -o "$TMPDIR/agentguard" || {
        warn "CLI no disponible en release — compilando localmente"
        warn "(ejecuta 'cargo build -p agentguard-cli --release' en el repo)"
    }

    info "Descargando agentguard-linux..."
    curl -fsSL "${DL_URL}/agentguard-linux-${TARGET}" -o "$TMPDIR/agentguard-linux" || {
        error "No se pudo descargar agentguard-linux-${TARGET}"
    }

    # 2. Verificar checksums
    curl -fsSL "${DL_URL}/checksums.txt" -o "$TMPDIR/checksums.txt" 2>/dev/null || true
    if [ -f "$TMPDIR/checksums.txt" ]; then
        info "Verificando SHA256..."
        (cd "$TMPDIR" && sha256sum --check --ignore-missing checksums.txt 2>/dev/null) || \
            warn "Verificación de checksum falló — continuando bajo tu responsabilidad"
    fi

    # 3. Instalar binarios
    info "Instalando en $BIN_DIR..."
    sudo install -m 755 "$TMPDIR/agentguard-linux" "$BIN_DIR/agentguard-linux"
    if [ -f "$TMPDIR/agentguard" ]; then
        sudo install -m 755 "$TMPDIR/agentguard" "$BIN_DIR/agentguard"
    fi

    # 4. Crear directorios
    sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR/vault" "$DATA_DIR/ca"

    # 5. Generar config por defecto si no existe
    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        info "Generando config.toml por defecto..."
        sudo tee "$CONFIG_DIR/config.toml" > /dev/null <<'EOF'
[agentguard]
version = "1"

protected_dirs = ["~/Documents", "~/Projects", "~/.ssh"]
protected_files = ["~/.env", "~/.netrc", "~/.aws/credentials"]

[on_violation]
kill_process = false
snapshot_on_violation = true

[alerts]
desktop_notifications = true
sound = false

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 6
keep_days = 30

[dlp]
enabled = true
proxy_port = 7771
action = "block"

[updates]
auto_check = true
auto_install = false
channel = "stable"
EOF
    fi

    # 6. Instalar y arrancar systemd service
    info "Instalando systemd service..."
    sudo cp packaging/linux/agentguard.service /etc/systemd/system/agentguard.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now agentguard

    # 7. Verificar que arrancó
    sleep 1
    if systemctl is-active --quiet agentguard; then
        info "AgentGuard está corriendo"
    else
        warn "AgentGuard no arrancó. Revisa: journalctl -u agentguard -n 50"
    fi

    echo ""
    info "Instalación completada."
    echo "  Comandos:"
    echo "    agentguard status               # estado general"
    echo "    agentguard protect ~/Documents  # proteger carpeta"
    echo "    agentguard snapshot create      # snapshot manual"
    echo "    agentguard incidents            # últimos incidentes"
    echo "  Logs:"
    echo "    journalctl -u agentguard -f     # seguir logs"
    echo "    cat /var/log/agentguard/incidents.jsonl"
}

main "$@"
