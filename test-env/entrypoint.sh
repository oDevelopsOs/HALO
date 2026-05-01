#!/usr/bin/env bash
set -euo pipefail

cat <<'BANNER'
╔══════════════════════════════════════════════════════════╗
║       AgentGuard Test Environment — Ubuntu 24.04         ║
╠══════════════════════════════════════════════════════════╣
║  Protected zone:   /protected/test-zone                  ║
║  Secrets fixture:  /protected/secrets/.env               ║
║  Workspace mount:  /workspace (tu repo HALO)             ║
║                                                          ║
║  Comandos disponibles:                                   ║
║    run-tests.sh            → suite automatizada          ║
║    verify_protection.sh    → check manual rápido         ║
║    simulate_ai_agent       → agente "loco" (ver README)  ║
╚══════════════════════════════════════════════════════════╝
BANNER

echo ""
echo "[entorno] kernel: $(uname -r)"

if [ -r /sys/kernel/security/lsm ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    echo "[entorno] LSM activos: ${LSM}"
    if echo "${LSM}" | tr ',' '\n' | grep -qx bpf; then
        echo "[entorno] ✓ BPF LSM disponible — protección kernel-level activable"
    else
        echo "[entorno] ⚠ BPF LSM NO disponible en este kernel."
        echo "           El daemon caerá al modo userspace (notify). Para probar"
        echo "           eBPF real, arrancar el host con lsm=...,bpf en grub."
    fi
else
    echo "[entorno] ⚠ No se puede leer /sys/kernel/security/lsm (montaje de /sys)"
fi

echo ""
exec "$@"
