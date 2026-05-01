#!/usr/bin/env bash
# Suite automatizada de pruebas para AgentGuard.
# Ejecutar dentro del contenedor test-env.
set -uo pipefail

PROTECTED_ZONE="${PROTECTED_ZONE:-/protected/test-zone}"
SECRETS_DIR="${SECRETS_DIR:-/protected/secrets}"
WORKSPACE="${WORKSPACE:-/workspace}"
DAEMON_BIN="${DAEMON_BIN:-${WORKSPACE}/target/release/agentguard-daemon}"
CLI_BIN="${CLI_BIN:-${WORKSPACE}/target/release/agentguard}"
SIMULATOR_BIN="/tmp/simulate_ai_agent"
PROXY_PORT="${PROXY_PORT:-7771}"

PASS=0
FAIL=0
SKIP=0

c_red()    { printf '\033[31m%s\033[0m' "$*"; }
c_green()  { printf '\033[32m%s\033[0m' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m' "$*"; }
c_blue()   { printf '\033[34m%s\033[0m' "$*"; }

step() { echo ""; c_blue "▶ $*"; echo ""; }
ok()   { c_green "  ✓ PASS"; echo " — $*"; PASS=$((PASS+1)); }
ko()   { c_red   "  ✗ FAIL"; echo " — $*"; FAIL=$((FAIL+1)); }
sk()   { c_yellow "  ⊘ SKIP"; echo " — $*"; SKIP=$((SKIP+1)); }

# ─────────────────────────────────────────────────────────────
step "1/12  Check del entorno"
# ─────────────────────────────────────────────────────────────
uname -a
if [ -r /sys/kernel/security/lsm ]; then
    lsm=$(cat /sys/kernel/security/lsm)
    echo "  LSM: $lsm"
    if echo "$lsm" | tr ',' '\n' | grep -qx bpf; then
        ok "BPF LSM disponible"
    else
        sk "BPF LSM no disponible — el daemon caerá a userspace"
    fi
else
    sk "No hay /sys/kernel/security/lsm montado"
fi

# ─────────────────────────────────────────────────────────────
step "2/12  Build del workspace Cargo"
# ─────────────────────────────────────────────────────────────
if [ ! -f "${WORKSPACE}/Cargo.toml" ]; then
    ko "No hay Cargo.toml en ${WORKSPACE} — ¿olvidaste montar el repo?"
    exit 1
fi
if cargo build --release --manifest-path "${WORKSPACE}/Cargo.toml" 2>&1 | tail -20; then
    ok "workspace compila"
else
    ko "build falla"
fi

# ─────────────────────────────────────────────────────────────
step "3/12  Build del crate eBPF (nightly)"
# ─────────────────────────────────────────────────────────────
if [ -d "${WORKSPACE}/crates/agentguard-ebpf" ]; then
    if ( cd "${WORKSPACE}/crates/agentguard-ebpf" \
         && cargo +nightly build --release --target bpfel-unknown-none \
              -Z build-std=core 2>&1 | tail -20 ); then
        ok "agentguard-ebpf compila a bpfel-unknown-none"
    else
        ko "agentguard-ebpf no compila"
    fi
else
    sk "crate agentguard-ebpf aún no existe (fase 1.5 pendiente)"
fi

# ─────────────────────────────────────────────────────────────
step "4/12  Compilar simulador del agente malicioso"
# ─────────────────────────────────────────────────────────────
if rustc --edition 2021 /opt/test-env/simulate_ai_agent.rs -O -o "${SIMULATOR_BIN}"; then
    ok "simulate_ai_agent compilado"
else
    ko "no se pudo compilar el simulador"
    exit 1
fi

# ─────────────────────────────────────────────────────────────
step "5/12  Arrancar daemon en background"
# ─────────────────────────────────────────────────────────────
if [ ! -x "${DAEMON_BIN}" ]; then
    sk "daemon no compilado aún (${DAEMON_BIN} no existe) — resto de tests skipped"
    echo ""
    echo "Resumen: ${PASS} pass / ${FAIL} fail / ${SKIP} skip"
    exit 0
fi

mkdir -p /tmp/agentguard-run
"${DAEMON_BIN}" --protect "${PROTECTED_ZONE}" --protect "${SECRETS_DIR}" \
    > /tmp/agentguard-run/daemon.log 2>&1 &
DAEMON_PID=$!
trap 'kill -TERM ${DAEMON_PID} 2>/dev/null || true' EXIT
sleep 2

if kill -0 "${DAEMON_PID}" 2>/dev/null; then
    ok "daemon corriendo (PID ${DAEMON_PID})"
else
    ko "daemon murió al arrancar — ver /tmp/agentguard-run/daemon.log"
    tail -20 /tmp/agentguard-run/daemon.log || true
    exit 1
fi

# ─────────────────────────────────────────────────────────────
step "6/12  Baseline: verificar estado inicial del protected zone"
# ─────────────────────────────────────────────────────────────
if [ -f "${PROTECTED_ZONE}/important.md" ]; then
    ok "archivo baseline existe"
else
    ko "archivo baseline no existe — entorno corrupto"
fi
INITIAL_HASH=$(sha256sum "${PROTECTED_ZONE}/important.md" | cut -d' ' -f1)
echo "  hash inicial: ${INITIAL_HASH}"

# ─────────────────────────────────────────────────────────────
step "7/12  Intento de unlink — DEBE fallar"
# ─────────────────────────────────────────────────────────────
if rm -f "${PROTECTED_ZONE}/important.md" 2>/dev/null && \
   [ ! -f "${PROTECTED_ZONE}/important.md" ]; then
    ko "BREACH: el archivo fue eliminado"
else
    ok "unlink bloqueado por el kernel (o archivo intacto)"
fi

# ─────────────────────────────────────────────────────────────
step "8/12  Intento de rename — DEBE fallar"
# ─────────────────────────────────────────────────────────────
if mv "${PROTECTED_ZONE}/important.md" "${PROTECTED_ZONE}/pwned.md" 2>/dev/null; then
    ko "BREACH: rename exitoso"
    mv "${PROTECTED_ZONE}/pwned.md" "${PROTECTED_ZONE}/important.md" 2>/dev/null || true
else
    ok "rename bloqueado"
fi

# ─────────────────────────────────────────────────────────────
step "9/12  Ejecutar simulador completo"
# ─────────────────────────────────────────────────────────────
"${SIMULATOR_BIN}" "${PROTECTED_ZONE}"
SIM_RC=$?
if [ "${SIM_RC}" -eq 1 ]; then
    ok "simulador reportó que TODO fue bloqueado"
elif [ "${SIM_RC}" -eq 0 ]; then
    ko "simulador logró romper la protección (ver output arriba)"
else
    ko "simulador errored out con código ${SIM_RC}"
fi

# ─────────────────────────────────────────────────────────────
step "10/12  Verificar integridad del baseline"
# ─────────────────────────────────────────────────────────────
if [ -f "${PROTECTED_ZONE}/important.md" ]; then
    FINAL_HASH=$(sha256sum "${PROTECTED_ZONE}/important.md" | cut -d' ' -f1)
    if [ "${INITIAL_HASH}" = "${FINAL_HASH}" ]; then
        ok "archivo idéntico al baseline (hash coincide)"
    else
        ko "archivo MODIFICADO (hash cambió): ${INITIAL_HASH} → ${FINAL_HASH}"
    fi
else
    ko "archivo baseline DESAPARECIÓ"
fi

# ─────────────────────────────────────────────────────────────
step "11/12  Vault: snapshot + destrucción simulada + restore"
# ─────────────────────────────────────────────────────────────
if [ -x "${CLI_BIN}" ]; then
    if "${CLI_BIN}" snapshot create --label "test-run" 2>/dev/null; then
        ok "snapshot creado"
        # Forzar pausa del daemon para permitir restore sin bloqueo
        "${CLI_BIN}" pause --minutes 1 2>/dev/null || true
        # Simular destrucción (daemon pausado, debería dejar pasar)
        echo "CHANGED" > "${PROTECTED_ZONE}/important.md" 2>/dev/null || true
        LATEST=$("${CLI_BIN}" snapshot list 2>/dev/null | head -1 | awk '{print $1}')
        if [ -n "${LATEST}" ] && "${CLI_BIN}" snapshot restore "${LATEST}" --yes 2>/dev/null; then
            RESTORED_HASH=$(sha256sum "${PROTECTED_ZONE}/important.md" | cut -d' ' -f1)
            if [ "${RESTORED_HASH}" = "${INITIAL_HASH}" ]; then
                ok "restore dejó el archivo idéntico al original"
            else
                ko "restore no restauró correctamente el contenido"
            fi
        else
            ko "no se pudo restaurar snapshot"
        fi
        "${CLI_BIN}" resume 2>/dev/null || true
    else
        sk "CLI no soporta snapshot aún"
    fi
else
    sk "agentguard CLI no compilado aún"
fi

# ─────────────────────────────────────────────────────────────
step "12/12  DLP: API key en request saliente"
# ─────────────────────────────────────────────────────────────
if ss -tln 2>/dev/null | grep -q ":${PROXY_PORT}"; then
    RESP=$(curl -sS -o /dev/null -w "%{http_code}" \
        -x "http://127.0.0.1:${PROXY_PORT}" \
        --max-time 5 \
        -X POST \
        --data 'OPENAI_API_KEY=sk-abc1234567890abcdef1234567890abcdef1234567890ab' \
        http://httpbin.org/post || echo "000")
    if [ "${RESP}" = "403" ]; then
        ok "DLP bloqueó request con API key (HTTP 403)"
    else
        ko "DLP no bloqueó (HTTP ${RESP}) — esperaba 403"
    fi
else
    sk "DLP proxy no está escuchando en :${PROXY_PORT}"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo " Resumen:  $(c_green "${PASS} pass")  /  $(c_red "${FAIL} fail")  /  $(c_yellow "${SKIP} skip")"
echo "══════════════════════════════════════════════════════"
echo ""
echo "Logs del daemon: /tmp/agentguard-run/daemon.log"
[ "${FAIL}" -eq 0 ]
