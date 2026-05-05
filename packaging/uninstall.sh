#!/usr/bin/env bash
# =============================================================================
# AgentGuard — Uninstaller (Linux)
# =============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
NC='\033[0m'

info() { printf "${BOLD}  →${NC} %s\n" "$*"; }
success() { printf "${GREEN}${BOLD}  ✓${NC} %s\n" "$*"; }

echo "AgentGuard Uninstaller"
echo ""

read -rp "Uninstall AgentGuard? [y/N] " REPLY
if [[ ! "$REPLY" =~ ^[Yy] ]]; then
    echo "Cancelled."
    exit 0
fi
echo ""

OS="$(uname -s)"

if [[ "$OS" == "Linux" ]]; then
    info "Stopping and disabling systemd service..."
    sudo systemctl stop agentguard 2>/dev/null || true
    sudo systemctl disable agentguard 2>/dev/null || true
    sudo rm -f /etc/systemd/system/agentguard.service
    sudo systemctl daemon-reload
    success "systemd unit removed"

    info "Removing binaries..."
    sudo rm -f /usr/local/bin/agentguard /usr/local/bin/agentguard-linux
    success "binaries removed"

    info "Removing CA from system trust store..."
    sudo rm -f /etc/pki/ca-trust/source/anchors/agentguard.crt \
               /usr/local/share/ca-certificates/agentguard.crt 2>/dev/null || true
    command -v update-ca-trust &>/dev/null && sudo update-ca-trust extract || true
    command -v update-ca-certificates &>/dev/null && sudo update-ca-certificates || true
    success "CA removed"

    info "Removing data..."
    read -rp "  Remove /var/lib/agentguard/ and /etc/agentguard/? [y/N] " DELDATA
    if [[ "$DELDATA" =~ ^[Yy] ]]; then
        sudo rm -rf /var/lib/agentguard /etc/agentguard /var/log/agentguard
        success "data removed"
    else
        info "data preserved"
    fi
fi

echo ""
success "AgentGuard uninstalled"
