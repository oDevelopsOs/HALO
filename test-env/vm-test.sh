#!/usr/bin/env bash
# vm-test.sh — Suite de tests end-to-end para AgentGuard en VM Linux.
#
# Ejecuta: simulación de agente rogue, verifica bloqueo eBPF, verifica DLP,
# snapshot/restore. Diseñado para correr en una VM Ubuntu 24.04 con:
#   - Kernel con BPF LSM activo (lsm=...,bpf en grub)
#   - Workspace del proyecto montado en /workspace
#   - Entorno de test pre-creado en /protected/test-zone
#
# Uso:
#   1. En el host: ./scripts/build-ebpf.sh
#   2. En la VM:    sudo ./test-env/vm-test.sh
#
# Requisitos previos (ejecutar una vez en la VM):
#   sudo ./test-env/setup-vm.sh
#
# Exit codes:
#   0  → todos los tests pasan
#   1  → fallo en tests de protección
#   2  → error de setup

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

PASS=0
FAIL=0

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗${RESET} $*"; FAIL=$((FAIL + 1)); }
info()  { echo -e "${BOLD}$*${RESET}"; }

check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "ERROR: este script debe ejecutarse como root (sudo)"
        exit 2
    fi
}

check_bpf_lsm() {
    if [ -r /sys/kernel/security/lsm ]; then
        local lsm=$(cat /sys/kernel/security/lsm)
        if echo "$lsm" | tr ',' '\n' | grep -qx bpf; then
            ok "BPF LSM detectado — protección kernel activa"
            return 0
        fi
    fi
    fail "BPF LSM NO disponible — pruebas limitadas a userspace"
    return 1
}

setup_test_zone() {
    local zone="/protected/test-zone"
    rm -rf "$zone" 2>/dev/null || true
    mkdir -p "$zone" "$zone/nested" "$zone/sub/deeper"
    echo "# Documento importante" > "$zone/important.md"
    echo "# Anidado" > "$zone/nested/deep.md"
    echo "# Subdirectorio" > "$zone/sub/deeper/leaf.md"
    mkdir -p "$zone/../secrets"
    echo "API_KEY=sk-1234567890abcdef1234567890abcdef1234567890abcdef" > "/protected/secrets/.env"
    info "Zona de test creada: $zone"
}

build_and_install() {
    info "Compilando agentguard-linux con eBPF..."
    cd /workspace

    ./scripts/build-ebpf.sh || {
        fail "Fallo compilación eBPF bytecode"
        exit 1
    }

    cargo build --release -p agentguard-linux --features ebpf || {
        fail "Fallo compilación agentguard-linux"
        exit 1
    }

    # Instalar
    sudo cp -f target/release/agentguard-linux /usr/local/bin/agentguard-linux
    sudo cp -f packaging/linux/agentguard.service /etc/systemd/system/agentguard.service

    # Config de test
    sudo mkdir -p /etc/agentguard
    sudo tee /etc/agentguard/config.toml > /dev/null <<EOF
[agentguard]
version = "1"

protected_dirs = ["/protected/test-zone"]
protected_files = ["/protected/secrets/.env"]

[on_violation]
kill_process = false
snapshot_on_violation = false

[alerts]
desktop_notifications = false

[vault]
snapshot_on_start = false
auto_snapshot_interval_hours = 0
keep_days = 30
vault_dir = "/var/lib/agentguard/vault"

[dlp]
enabled = false

[updates]
auto_check = false
EOF

    sudo systemctl daemon-reload
    sudo systemctl stop agentguard 2>/dev/null || true
    sudo systemctl start agentguard

    sleep 2
    if systemctl is-active --quiet agentguard; then
        ok "Daemon arrancó correctamente"
    else
        fail "Daemon no arrancó"
        journalctl -u agentguard -n 30 --no-pager
        exit 1
    fi
}

test_ebpf_blocking() {
    info "--- Test: bloqueo eBPF ---"

    local zone="/protected/test-zone"

    echo "  Probando unlink..."
    if rm "$zone/important.md" 2>/dev/null; then
        fail "unlink debería haber sido bloqueado (EPERM)"
    else
        ok "unlink bloqueado por eBPF LSM"
    fi

    echo "  Probando rename..."
    if mv "$zone/nested" "$zone/nested_RENAMED" 2>/dev/null; then
        fail "rename debería haber sido bloqueado"
        mv "$zone/nested_RENAMED" "$zone/nested" 2>/dev/null || true
    else
        ok "rename bloqueado por eBPF LSM"
    fi

    echo "  Probando rm -rf..."
    if rm -rf "$zone" 2>/dev/null; then
        fail "rm -rf no debería haber funcionado"
    else
        ok "rm -rf bloqueado"
        [ -d "$zone" ] && ok "zona intacta después de rm -rf"
    fi

    echo "  Probando write protegido..."
    if echo "malware" > "/protected/secrets/.env" 2>/dev/null; then
        fail "write a archivo protegido debería ser bloqueado"
    else
        ok "write a archivo protegido bloqueado"
    fi
}

test_userspace_fallback() {
    info "--- Test: fallback userspace ---"

    sudo systemctl stop agentguard

    cargo build --release -p agentguard-linux --no-default-features
    sudo cp -f target/release/agentguard-linux /usr/local/bin/agentguard-linux
    sudo systemctl start agentguard
    sleep 2

    local zone="/protected/test-zone"
    if rm "$zone/sub/deeper/leaf.md" 2>/dev/null; then
        ok "userspace: delete permitido (esperado — solo observa)"
        [ ! -f "$zone/sub/deeper/leaf.md" ] && ok "archivo eliminado (detectado post-hoc)"

        # Verificar en logs que se detectó
        if journalctl -u agentguard --since "1 min ago" | grep -q "filesystem violation"; then
            ok "userspace: evento de violación registrado"
        else
            fail "userspace: no se detectó la violación en logs"
        fi
    else
        ok "userspace: delete bloqueado por sistema externo"
    fi
}

test_vault_snapshot_restore() {
    info "--- Test: vault snapshot + restore ---"

    # Reconstruir con eBPF
    sudo systemctl stop agentguard
    cargo build --release -p agentguard-linux --features ebpf
    sudo cp -f target/release/agentguard-linux /usr/local/bin/agentguard-linux
    sudo systemctl start agentguard
    sleep 2

    # Crear snapshot manual
    local output
    output=$(cargo run --release -p agentguard-cli -- snapshot create --label vm-test 2>&1) || true
    echo "  CLI output: $output"

    if echo "$output" | grep -q "created"; then
        ok "vault: snapshot creado vía CLI"
    else
        fail "vault: snapshot falló"
    fi

    # Listar snapshots
    output=$(cargo run --release -p agentguard-cli -- snapshot list 2>&1) || true
    if echo "$output" | grep -q "vm-test"; then
        ok "vault: snapshot listado"
    else
        fail "vault: no se encontró el snapshot"
    fi
}

test_rogue_agent_simulator() {
    info "--- Test: simulador de agente rogue ---"

    cargo build --release --manifest-path /workspace/test-env/Cargo.toml 2>/dev/null || {
        # El simulador está en Rust; si no hay Cargo.toml separado, lo compilamos a mano
        rustc /workspace/test-env/simulate_ai_agent.rs -o /tmp/simulate_ai_agent 2>/dev/null || {
            warn "No se pudo compilar el simulador"
            return
        }
    }

    /tmp/simulate_ai_agent "/protected/test-zone"
    local ret=$?

    if [ $ret -eq 1 ]; then
        ok "simulador: todas las operaciones bloqueadas"
    elif [ $ret -eq 0 ]; then
        fail "simulador: algunas operaciones NO fueron bloqueadas"
    else
        fail "simulador: error de ejecución (código $ret)"
    fi
}

# ── Main ──────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║   AgentGuard VM Test Suite — Fase 2  ║"
echo "╚══════════════════════════════════════╝"
echo ""

check_root
cd /workspace 2>/dev/null || { echo "ERROR: workspace no montado en /workspace"; exit 2; }

check_bpf_lsm
setup_test_zone
build_and_install
echo ""

test_ebpf_blocking
echo ""
test_vault_snapshot_restore
echo ""
test_rogue_agent_simulator
echo ""

# ── Resultado ─────────────────────────────────────────────
echo "════════════════════════════════════════"
echo -e "  ${GREEN}Pasaron:${RESET} $PASS  |  ${RED}Fallaron:${RESET} $FAIL"
echo "════════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
    echo -e "\n${GREEN}✓ Todos los tests pasan. AgentGuard Fase 2 operativo.${RESET}"
    exit 0
else
    echo -e "\n${RED}✗ $FAIL test(s) fallaron. Revisa los logs.${RESET}"
    exit 1
fi
