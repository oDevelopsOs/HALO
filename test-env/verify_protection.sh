#!/usr/bin/env bash
# Verificación manual rápida — útil para debug interactivo.
# No asume que el daemon esté corriendo: solo muestra el estado.
set -uo pipefail

PROTECTED_ZONE="${PROTECTED_ZONE:-/protected/test-zone}"

echo "═══ AgentGuard — verificación rápida ═══"
echo ""
echo "Kernel:         $(uname -r)"
echo "LSM activos:    $(cat /sys/kernel/security/lsm 2>/dev/null || echo '(no disponible)')"
echo "Protected zone: ${PROTECTED_ZONE}"
echo ""

echo "── Contenido actual ──"
if command -v tree >/dev/null 2>&1; then
    tree -a "${PROTECTED_ZONE}"
else
    ls -la "${PROTECTED_ZONE}"
fi

echo ""
echo "── Hashes actuales ──"
find "${PROTECTED_ZONE}" -type f -exec sha256sum {} \;

echo ""
echo "── Daemon de AgentGuard ──"
if pgrep -x agentguard-daemon >/dev/null; then
    echo "  ✓ agentguard-daemon está corriendo (PID $(pgrep -x agentguard-daemon))"
else
    echo "  ⚠ agentguard-daemon NO está corriendo"
fi

echo ""
echo "── Socket IPC ──"
for sock in /run/agentguard/daemon.sock "$HOME/.agentguard/daemon.sock"; do
    if [ -S "$sock" ]; then
        echo "  ✓ $sock"
    fi
done

echo ""
echo "── Prueba rápida: rm del archivo protegido ──"
TARGET="${PROTECTED_ZONE}/important.md"
if [ -f "${TARGET}" ]; then
    if rm "${TARGET}" 2>&1; then
        if [ -f "${TARGET}" ]; then
            echo "  (rm no reportó error pero el archivo sigue ahí — raro)"
        else
            echo "  ✗ BREACH: el archivo fue eliminado"
        fi
    else
        echo "  ✓ rm rechazado"
    fi
else
    echo "  ⚠ el archivo baseline no existe"
fi
