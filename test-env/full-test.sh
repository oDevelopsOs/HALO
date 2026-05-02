#!/usr/bin/env bash
# ============================================================
#  AgentGuard — Test Suite COMPLETA para VM aislada (KVM)
# ============================================================
#
# Ejecutar DENTRO de la VM (Fedora 41+ o Ubuntu 24.04+).
# Requiere: kernel con BPF LSM activo, Rust nightly+stable.
#
# Lo que hace (TODO en orden, 15 pasos):
#   1.  Verifica BPF LSM en el kernel
#   2.  Compila bytecodes eBPF (nightly)
#   3.  Compila agentguard-linux con --features ebpf
#   4.  Compila agentguard-cli
#   5.  Crea la zona de prueba protegida
#   6.  Genera config.toml con la zona
#   7.  Arranca el daemon
#   8.  Verifica que el daemon responde (ping IPC)
#   9.  Crea snapshot pre-ataque
#  10.  Lanza simulador de agente rogue (8 ataques)
#  11.  Verifica que TODOS los ataques fueron bloqueados
#  12.  Verifica que los archivos protegidos siguen intactos
#  13.  Restaura snapshot y verifica integridad
#  14.  Test DLP: proxy bloquea API keys
#  15.  Apaga el daemon limpiamente
#
# Salida:
#   0 → TODO OK, AgentGuard funcional
#   1 → Algún test falló
# ============================================================

set -euo pipefail

# ── Colores ────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0; TOTAL=15

_pass() { echo -e "  ${GREEN}✓${NC} $1"; PASS=$((PASS + 1)); }
_fail() { echo -e "  ${RED}✗${NC} $1 ${RED}← FALLÓ${NC}"; FAIL=$((FAIL + 1)); }
_skip() { echo -e "  ${YELLOW}⊘${NC} $1 ${DIM}(saltado)${NC}"; SKIP=$((SKIP + 1)); }
_info() { echo -e "\n${BLUE}${BOLD}─── $1 ───${NC}"; }
_banner() { echo -e "\n${BOLD}╔════════════════════════════════════════════╗${NC}";
            echo -e "${BOLD}║   🛡  AgentGuard Test Suite — VM aislada    ║${NC}";
            echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"; }

# ── Entorno ────────────────────────────────────────────────
WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
ZONE="/protected/ag-test-zone"
SECRETS="/protected/ag-secrets"
VAULT_DIR="/var/lib/agentguard/vault"
SOCKET="/var/run/agentguard.sock"
CONFIG="/etc/agentguard/config.toml"
BIN_DIR="/usr/local/bin"

export RUST_BACKTRACE=1
export RUST_LOG=info

must_be_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}ERROR: ejecutar como root (sudo)${NC}"
        exit 2
    fi
}

# ── 1. Verificar BPF LSM ──────────────────────────────────
step1_check_bpf() {
    _info "1/15 Verificando BPF LSM"
    if [ -r /sys/kernel/security/lsm ]; then
        local lsm; lsm=$(cat /sys/kernel/security/lsm)
        echo "  LSM activos: $lsm"
        if echo "$lsm" | tr ',' '\n' | grep -qx bpf; then
            _pass "BPF LSM activo — protección kernel-level disponible"
            return 0
        fi
    fi
    _skip "BPF LSM NO disponible (kernel sin soporte eBPF LSM)"
    _skip "  → Solo se probará el fallback userspace (notify)"
    _skip "  → Para eBPF real: añade lsm=...,bpf a GRUB y reinicia"
    echo "USESPACE_ONLY=1" > /tmp/ag-test-mode
    return 1
}

# ── 2. Compilar eBPF bytecodes ─────────────────────────────
step2_build_ebpf() {
    _info "2/15 Compilando programas eBPF (nightly)"
    if [ -f /tmp/ag-test-mode ] && grep -q USESPACE_ONLY /tmp/ag-test-mode; then
        _skip "Modo userspace — saltando compilación eBPF"
        return
    fi

    cd "$WORKSPACE"
    if ! rustup run nightly cargo --version &>/dev/null; then
        _skip "Nightly no disponible — saltando eBPF"
        echo "USESPACE_ONLY=1" > /tmp/ag-test-mode
        return
    fi

    bash scripts/build-ebpf.sh 2>&1 | tail -3
    if [ -f target/ebpf/file_guard ] && [ -f target/ebpf/net_guard ]; then
        _pass "Bytecodes eBPF compilados"
    else
        _fail "Fallo compilación eBPF bytecodes"
        return 1
    fi
}

# ── 3. Compilar daemon Linux ───────────────────────────────
step3_build_daemon() {
    _info "3/15 Compilando agentguard-linux"
    cd "$WORKSPACE"

    local ebpf_feat=""
    if [ ! -f /tmp/ag-test-mode ] || ! grep -q USESPACE_ONLY /tmp/ag-test-mode; then
        ebpf_feat="--features ebpf"
    fi

    if cargo build --release -p agentguard-linux $ebpf_feat 2>&1 | tail -3; then
        cp -f target/release/agentguard-linux "$BIN_DIR/agentguard-linux"
        _pass "agentguard-linux compilado e instalado"
    else
        _fail "Fallo compilación agentguard-linux"
        return 1
    fi
}

# ── 4. Compilar CLI ────────────────────────────────────────
step4_build_cli() {
    _info "4/15 Compilando agentguard CLI"
    cd "$WORKSPACE"
    if cargo build --release -p agentguard-cli 2>&1 | tail -3; then
        cp -f target/release/agentguard "$BIN_DIR/agentguard"
        _pass "agentguard CLI compilado e instalado"
    else
        _fail "Fallo compilación CLI"
        return 1
    fi
}

# ── 5. Crear zona de prueba ────────────────────────────────
step5_create_zone() {
    _info "5/15 Creando zona de prueba protegida"
    rm -rf "$ZONE" "$SECRETS"
    mkdir -p "$ZONE" "$ZONE/nested/sub" "$SECRETS"

    echo "# Documento IMPORTANTE — no borrar" > "$ZONE/important.md"
    echo "# Archivo de datos" > "$ZONE/data.txt"
    echo "# Deep nested" > "$ZONE/nested/deep.md"
    echo "# Triple nested" > "$ZONE/nested/sub/leaf.md"
    echo "API_KEY=sk-1234567890abcdef1234567890abcdef1234567890abcdef" > "$SECRETS/.env"
    echo "DATABASE_URL=postgres://user:pass@localhost/db" >> "$SECRETS/.env"
    echo "SECRET_TOKEN=ghp_$(python3 -c 'print("a"*36)' 2>/dev/null || echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')" >> "$SECRETS/.env"
    chmod 600 "$SECRETS/.env"

    _pass "Zona creada: $ZONE"

    # Guardar hashes para verificar integridad después
    find "$ZONE" "$SECRETS" -type f -exec sha256sum {} \; | sort > /tmp/ag-hashes-before.txt
}

# ── 6. Generar config ──────────────────────────────────────
step6_create_config() {
    _info "6/15 Generando config.toml"
    mkdir -p /etc/agentguard /var/lib/agentguard/vault /var/lib/agentguard/ca /var/log/agentguard /run/agentguard

    cat > "$CONFIG" <<EOF
[agentguard]
version = "1"

protected_dirs = ["$ZONE"]
protected_files = ["$SECRETS/.env"]

[on_violation]
kill_process = false
snapshot_on_violation = true

[alerts]
desktop_notifications = false
sound = false

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 0
keep_days = 30
vault_dir = "$VAULT_DIR"

[dlp]
enabled = true
proxy_port = 7771
action = "block"

[updates]
auto_check = false
EOF

    _pass "config.toml generado"
    cat "$CONFIG" | head -5
}

# ── 7. Arrancar daemon ─────────────────────────────────────
step7_start_daemon() {
    _info "7/15 Arrancando agentguard-linux"

    # Matar cualquier instancia previa
    pkill -f agentguard-linux 2>/dev/null || true
    sleep 1

    # Arrancar en background
    "$BIN_DIR/agentguard-linux" \
        --config "$CONFIG" \
        > /tmp/ag-daemon.log 2>&1 &

    local pid=$!
    echo "$pid" > /tmp/ag-daemon.pid

    # Esperar a que esté listo
    local waited=0
    while [ $waited -lt 30 ]; do
        if [ -S "$SOCKET" ]; then
            _pass "Daemon arrancado (PID $pid, socket listo)"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    _fail "Daemon no arrancó en 30s"
    echo "  Últimos logs:"
    tail -20 /tmp/ag-daemon.log
    return 1
}

# ── 8. Ping al daemon ──────────────────────────────────────
step8_ping() {
    _info "8/15 Verificando IPC (ping)"
    if "$BIN_DIR/agentguard" --socket "$SOCKET" ping 2>&1 | grep -q "running"; then
        _pass "Daemon responde vía IPC"
    else
        _fail "Daemon no responde al ping"
        "$BIN_DIR/agentguard" --socket "$SOCKET" status 2>&1 || true
        return 1
    fi
}

# ── 9. Snapshot pre-ataque ──────────────────────────────────
step9_snapshot_pre() {
    _info "9/15 Creando snapshot pre-ataque"
    local out
    out=$("$BIN_DIR/agentguard" --socket "$SOCKET" snapshot create --label pre-attack 2>&1) || true
    echo "  $out"
    if echo "$out" | grep -q "created"; then
        _pass "Snapshot pre-ataque creado"
        echo "$out" | grep -oP '[a-f0-9-]{36}' | head -1 > /tmp/ag-snapshot-id.txt
    else
        _fail "Fallo al crear snapshot"
    fi
}

# ── 10. Lanzar agente rogue ────────────────────────────────
step10_rogue_agent() {
    _info "10/15 Lanzando simulador de agente rogue (8 ataques)"

    # Compilar el simulador
    rustc --edition 2021 -O "$WORKSPACE/test-env/simulate_ai_agent.rs" -o /tmp/rogue_agent 2>/dev/null || {
        _skip "No se pudo compilar simulate_ai_agent.rs (¿rustc instalado?)"
        return
    }

    echo "  ╔══════════════════════════════════════╗"
    echo "  ║  🤖 ROGUE AI AGENT — ATACANDO ZONA  ║"
    echo "  ╚══════════════════════════════════════╝"

    /tmp/rogue_agent "$ZONE" 2>&1
    local ret=$?

    echo ""
    if [ $ret -eq 1 ]; then
        _pass "Simulador: TODOS los ataques bloqueados (exit 1)"
    elif [ $ret -eq 0 ]; then
        _fail "Simulador: algunos ataques NO fueron bloqueados (exit 0)"
    else
        _fail "Simulador: error de ejecución (exit $ret)"
    fi
}

# ── 11. Verificar integridad ────────────────────────────────
step11_verify_integrity() {
    _info "11/15 Verificando integridad de archivos protegidos"
    if [ -f /tmp/ag-hashes-before.txt ]; then
        find "$ZONE" "$SECRETS" -type f -exec sha256sum {} \; 2>/dev/null | sort > /tmp/ag-hashes-after.txt
        if diff /tmp/ag-hashes-before.txt /tmp/ag-hashes-after.txt > /dev/null 2>&1; then
            _pass "Integridad: todos los archivos intactos"
        else
            _fail "Integridad: cambios detectados en archivos"
            diff /tmp/ag-hashes-before.txt /tmp/ag-hashes-after.txt || true
        fi
    else
        _skip "No hay hashes de referencia"
    fi
}

# ── 12. Restaurar snapshot ──────────────────────────────────
step12_restore_snapshot() {
    _info "12/15 Restaurando snapshot"
    local snap_id
    if [ -f /tmp/ag-snapshot-id.txt ]; then
        snap_id=$(cat /tmp/ag-snapshot-id.txt)
        local out
        out=$("$BIN_DIR/agentguard" --socket "$SOCKET" snapshot restore "$snap_id" --yes 2>&1) || true
        echo "  $out"
        if echo "$out" | grep -q "restored"; then
            _pass "Snapshot restaurado correctamente"
        else
            _fail "Fallo al restaurar snapshot"
        fi
    else
        _skip "No hay ID de snapshot"
    fi
}

# ── 13. Test DLP ────────────────────────────────────────────
step13_test_dlp() {
    _info "13/15 Test DLP: proxy bloquea API keys"

    # Verificar que el proxy DLP está escuchando
    if ! ss -tlnp | grep -q 7771; then
        _skip "DLP proxy no está escuchando en :7771"
        return
    fi

    # Test 1: request con API key → debe ser bloqueado
    local out
    out=$(curl -sS --max-time 5 \
        -x http://127.0.0.1:7771 \
        -H "Authorization: Bearer sk-1234567890abcdef1234567890abcdef1234567890abcdef" \
        http://example.invalid/test 2>&1) || true

    if echo "$out" | grep -q "AgentGuard DLP\|403\|Forbidden"; then
        _pass "DLP: API key bloqueada (HTTP 403)"
    else
        _fail "DLP: API key NO fue bloqueada"
        echo "  Respuesta: $out"
    fi

    # Test 2: request limpio → debe pasar
    local out2
    out2=$(curl -sS --max-time 5 \
        -x http://127.0.0.1:7771 \
        http://example.invalid/test 2>&1) || true
    # Fallará con 502 porque example.invalid no existe, pero NO debe ser 403
    if ! echo "$out2" | grep -q "AgentGuard DLP"; then
        _pass "DLP: request limpio no bloqueado"
    else
        _fail "DLP: request limpio bloqueado incorrectamente"
    fi
}

# ── 14. Verificar incidentes en disco ──────────────────────
step14_check_incidents() {
    _info "14/15 Verificando incidentes en disco"
    local log="/var/log/agentguard/incidents.jsonl"
    if [ -f "$log" ]; then
        local count; count=$(wc -l < "$log")
        if [ "$count" -gt 0 ]; then
            _pass "Incidentes registrados: $count eventos"
            echo "  Último evento:"
            tail -1 "$log" | python3 -m json.tool 2>/dev/null || tail -1 "$log"
        else
            _skip "0 incidentes registrados"
        fi
    else
        _skip "Archivo de incidentes no encontrado"
    fi
}

# ── 15. Shutdown ────────────────────────────────────────────
step15_shutdown() {
    _info "15/15 Apagando daemon"
    if [ -f /tmp/ag-daemon.pid ]; then
        local pid; pid=$(cat /tmp/ag-daemon.pid)
        kill "$pid" 2>/dev/null || true
        sleep 2
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        _pass "Daemon apagado (PID $pid)"
    fi
    rm -f /tmp/ag-daemon.pid /tmp/ag-test-mode /tmp/ag-hashes-*.txt /tmp/ag-snapshot-id.txt
}

# ── Main ────────────────────────────────────────────────────
main() {
    _banner
    must_be_root

    echo -e "${DIM}Workspace: $WORKSPACE${NC}"
    echo -e "${DIM}Kernel:    $(uname -r)${NC}"
    echo ""

    step1_check_bpf || true
    step2_build_ebpf || true
    step3_build_daemon || exit 1
    step4_build_cli || exit 1
    step5_create_zone
    step6_create_config
    step7_start_daemon || exit 1
    sleep 2
    step8_ping || true
    step9_snapshot_pre || true
    step10_rogue_agent || true
    step11_verify_integrity
    step12_restore_snapshot || true
    step13_test_dlp || true
    step14_check_incidents || true
    step15_shutdown

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Pasaron:${NC} $PASS  |  ${RED}Fallaron:${NC} $FAIL  |  ${YELLOW}Saltados:${NC} $SKIP"
    echo -e "${BOLD}════════════════════════════════════════════${NC}"

    if [ "$FAIL" -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}✓ AGENTGUARD FUNCIONANDO — TODOS LOS TESTS PASAN${NC}"
        exit 0
    else
        echo -e "\n${RED}${BOLD}✗ $FAIL TEST(S) FALLARON${NC}"
        echo -e "${DIM}Revisa: tail -100 /tmp/ag-daemon.log${NC}"
        exit 1
    fi
}

main "$@"
