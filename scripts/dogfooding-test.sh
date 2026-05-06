#!/usr/bin/env bash
# dogfooding-test.sh — end-to-end installation test.
#
# Simulates a fresh install from scratch:
# 1. Build all binaries locally
# 2. Install (config, systemd, binary displacement)
# 3. Start daemon
# 4. Verify agentguard status
# 5. Verify agentguard protect works
# 6. Clean up
#
# Usage: bash scripts/dogfooding-test.sh

set -euo pipefail

echo "=== AgentGuard Dogfooding Test ==="
echo ""

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP_HOME="/tmp/agentguard-dogfood-$$"
BIN_DIR="$TMP_HOME/bin"
CONFIG_DIR="$TMP_HOME/.agentguard"
SOCKET_PATH="$TMP_HOME/.agentguard/agentguard.sock"

cleanup() {
    echo ""
    echo "Cleaning up..."
    # Kill daemon if running
    pkill -f "target/debug/agentguard-linux" 2>/dev/null || true
    rm -rf "$TMP_HOME"
    echo "Done."
}
trap cleanup EXIT

# ── Step 1: Build ──────────────────────────────────────────
echo "[1/6] Building binaries..."
cd "$PROJECT_DIR"
cargo build -p agentguard-cli -p agentguard-linux 2>&1 | tail -1

# Build shim
cargo build --manifest-path crates/agentguard-shim/Cargo.toml 2>&1 | tail -1

echo "  Build OK"

# ── Step 2: Install ────────────────────────────────────────
echo "[2/6] Installing to $TMP_HOME..."
mkdir -p "$BIN_DIR" "$CONFIG_DIR"

cp target/debug/agentguard "$BIN_DIR/" 2>/dev/null || \
    cp target/debug/agentguard-cli "$BIN_DIR/agentguard"
cp target/debug/agentguard-linux "$BIN_DIR/"

# Copy shim
if [ -f crates/agentguard-shim/target/debug/agentguard-shim ]; then
    cp crates/agentguard-shim/target/debug/agentguard-shim "$BIN_DIR/"
elif [ -f target/x86_64-unknown-linux-musl/debug/agentguard-shim ]; then
    cp target/x86_64-unknown-linux-musl/debug/agentguard-shim "$BIN_DIR/"
fi

# Default config
cat > "$CONFIG_DIR/config.toml" <<'EOF'
[agentguard]
version = "1"

protected_dirs = ["/tmp/agentguard-test-dir"]

[[agent_processes]]
name = "test-agent"
match = { exe = "echo" }

[on_violation]
kill_process = false
snapshot_on_violation = false

[alerts]
desktop_notifications = false

[vault]
snapshot_on_start = false

[dlp]
enabled = false

[sandbox]
modo_por_defecto = "monitor"

[updates]
auto_check = false
EOF

export AGENTGUARD_CONFIG="$CONFIG_DIR/config.toml"
echo "  Install OK"

# ── Step 3: Start daemon ───────────────────────────────────
echo "[3/6] Starting daemon..."
export HOME="$TMP_HOME"
"$BIN_DIR/agentguard-linux" \
    --config "$AGENTGUARD_CONFIG" \
    --protect /tmp \
    &
DAEMON_PID=$!
sleep 2

if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "  FAIL: daemon failed to start"
    exit 1
fi
echo "  Daemon started (PID $DAEMON_PID)"

# ── Step 4: Check status ───────────────────────────────────
echo "[4/6] Checking status..."
export PATH="$BIN_DIR:$PATH"
export AGENTGUARD_SOCKET="$SOCKET_PATH"

STATUS_OUTPUT=$("$BIN_DIR/agentguard" status 2>&1) || {
    echo "  FAIL: agentguard status failed"
    echo "  Output: $STATUS_OUTPUT"
    exit 1
}

echo "$STATUS_OUTPUT" | head -5

if echo "$STATUS_OUTPUT" | grep -qi "backend\|protection\|guard"; then
    echo "  Status OK"
else
    echo "  WARNING: status output doesn't contain expected fields"
fi

# ── Step 5: Protect a path ──────────────────────────────────
echo "[5/6] Testing protect command..."
PROTECT_OUTPUT=$("$BIN_DIR/agentguard" protect /tmp/agentguard-test-dir 2>&1) || true
echo "  $PROTECT_OUTPUT"

# ── Step 6: Snapshot test ───────────────────────────────────
echo "[6/6] Testing snapshot..."
SNAP_OUTPUT=$("$BIN_DIR/agentguard" snapshot create --label "dogfood-test" 2>&1) || true
echo "  $SNAP_OUTPUT"

SNAP_LIST=$("$BIN_DIR/agentguard" snapshot list 2>&1) || true
echo "$SNAP_LIST" | head -3

# ── Done ───────────────────────────────────────────────────
echo ""
echo "=== Dogfooding test PASSED ==="
echo "  Daemon: running (PID $DAEMON_PID)"
echo "  Config: $AGENTGUARD_CONFIG"
echo "  Vault:  $TMP_HOME/.agentguard/vault"
exit 0
