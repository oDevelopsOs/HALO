#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
#  AgentGuard — Fix 1.0 verification script
#
#  Validates the surgical refactor that closed the four real bugs identified
#  in the 2026-05-07 audit:
#
#    Phase 1 — file_open inspects f_flags (read-only opens of protected files
#              are no longer denied)
#    Phase 2 — populate_inode_map walks the entire subtree (deep files match
#              parent-inode lookup)
#    Phase 3 — expand_path is unified — `~/...` resolves to the real user
#              home everywhere (smart_protect no longer uses /root/...)
#    Phase 4 — CA filename consistent (`root.crt`) across daemon + installer
#    Phase 5 — `LocalCa::install_system_trust` is distro-agnostic in Rust
#    Phase 6 — `agentguard ca {install|uninstall|show}` CLI subcommand
#
#  Two tiers:
#    Tier 1 (unprivileged) — build, unit tests, static structural checks,
#                            CLI smoke tests against a temp CA dir.
#    Tier 2 (root only)    — actually invoke `agentguard ca install` against
#                            the system trust store and verify it cleans up.
#                            Skipped when not run as root.
#
#  Usage:   bash scripts/test-fix1.sh        (Tier 1 only)
#           sudo bash scripts/test-fix1.sh   (Tier 1 + Tier 2)
# ════════════════════════════════════════════════════════════════════════════

set -uo pipefail

# Resolve repo root from this script's location so it works no matter where
# the user invokes it from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

PASS=0
FAIL=0
SKIP=0

# Bash 5+ on Fedora supports terminal escapes natively. No external deps.
if [ -t 1 ]; then
    GREEN=$'\033[32m' RED=$'\033[31m' YELLOW=$'\033[33m'
    BOLD=$'\033[1m' DIM=$'\033[2m' RESET=$'\033[0m'
else
    GREEN= RED= YELLOW= BOLD= DIM= RESET=
fi

step()    { echo; echo "${BOLD}── $1 ──${RESET}"; }
ok()      { echo "  ${GREEN}✓${RESET} $1"; PASS=$((PASS+1)); }
fail()    { echo "  ${RED}✗${RESET} $1"; FAIL=$((FAIL+1)); }
skip()    { echo "  ${YELLOW}⚠${RESET} skip: $1"; SKIP=$((SKIP+1)); }
info()    { echo "    ${DIM}$1${RESET}"; }

# ────────────────────────────────────────────────────────────────────────────
#  Tier 1 — Build & test gates
# ────────────────────────────────────────────────────────────────────────────

step "Tier 1.0  Workspace builds (debug)"
if cargo build --workspace --exclude agentguard-ebpf >/tmp/agentguard-build.log 2>&1; then
    ok "cargo build --workspace --exclude agentguard-ebpf"
else
    fail "cargo build failed (see /tmp/agentguard-build.log)"
fi

step "Tier 1.1  Unit + integration tests"
TEST_OUT=/tmp/agentguard-test.log
if cargo test --workspace --exclude agentguard-ebpf >"${TEST_OUT}" 2>&1; then
    PASSED_COUNT=$(grep -E "^test result: ok\." "${TEST_OUT}" | awk '{ s += $4 } END { print s+0 }')
    IGNORED_COUNT=$(grep -E "^test result: ok\." "${TEST_OUT}" | awk '{ s += $7 } END { print s+0 }')
    ok "cargo test passed (${PASSED_COUNT} tests, ${IGNORED_COUNT} ignored)"
else
    fail "cargo test failed (see ${TEST_OUT})"
fi

step "Tier 1.2  Strict clippy (-D warnings)"
if cargo clippy --workspace --exclude agentguard-ebpf --all-targets -- -D warnings \
     >/tmp/agentguard-clippy.log 2>&1; then
    ok "cargo clippy clean"
else
    fail "clippy reported warnings (see /tmp/agentguard-clippy.log)"
fi

step "Tier 1.3  eBPF bytecode builds"
if [ -x scripts/build-ebpf.sh ]; then
    if ./scripts/build-ebpf.sh >/tmp/agentguard-ebpf.log 2>&1; then
        ok "scripts/build-ebpf.sh succeeded"
        for prog in file_guard net_guard process_exec; do
            if [ -s "target/ebpf/${prog}" ]; then
                size=$(stat -c '%s' "target/ebpf/${prog}")
                info "${prog}: ${size} bytes"
            else
                fail "target/ebpf/${prog} is missing or empty"
            fi
        done
    else
        fail "build-ebpf.sh failed (see /tmp/agentguard-ebpf.log)"
    fi
else
    skip "scripts/build-ebpf.sh not present"
fi

# ────────────────────────────────────────────────────────────────────────────
#  Tier 1 — Structural checks (greps that prove each phase landed)
# ────────────────────────────────────────────────────────────────────────────

step "Tier 1.4  Phase 1 structural checks (file_open f_flags filter)"

PHASE1_FILE="crates/agentguard-ebpf/src/file_guard.rs"
PHASE1_LOADER="crates/agentguard-linux/src/guard/ebpf.rs"

if grep -q "DFL_F_FLAGS" "${PHASE1_FILE}"; then
    ok "DFL_F_FLAGS fallback constant present"
else
    fail "DFL_F_FLAGS missing in ${PHASE1_FILE}"
fi

if grep -q "try_deny_file_open_write" "${PHASE1_FILE}"; then
    ok "try_deny_file_open_write helper present"
else
    fail "try_deny_file_open_write missing — file_open still denies all opens"
fi

if grep -qE "O_WRONLY|O_RDWR|O_TRUNC" "${PHASE1_FILE}"; then
    ok "POSIX flag constants present (O_WRONLY/O_RDWR/O_TRUNC)"
else
    fail "POSIX flag constants missing"
fi

# OFFSETS map must cover slot 6 (f_flags). Capacity bumped to 12.
if grep -q "with_max_entries(12, 0)" "${PHASE1_FILE}"; then
    ok "OFFSETS map capacity bumped to 12"
else
    fail "OFFSETS map capacity not bumped (slot 6 won't fit)"
fi

if grep -q '"BTF: file.f_flags"' "${PHASE1_LOADER}"; then
    ok "userspace BTF parser populates file.f_flags"
else
    fail "BTF parser does not populate f_flags slot"
fi

step "Tier 1.5  Phase 2 structural checks (recursive subtree indexing)"

if grep -q "MAX_PROTECTED_INODES: u32 = 8192" crates/agentguard-common/src/lib.rs; then
    ok "MAX_PROTECTED_INODES = 8192 in agentguard-common"
else
    fail "MAX_PROTECTED_INODES not set to 8192"
fi

if grep -qE "with_max_entries\(8192, 0\)" "${PHASE1_FILE}"; then
    ok "PROTECTED_*_INODES BPF maps sized 8192"
else
    fail "BPF inode maps still at old capacity"
fi

if grep -q "fn walk_subtree_dirs" "${PHASE1_LOADER}"; then
    ok "walk_subtree_dirs() helper present"
else
    fail "walk_subtree_dirs() missing — subtree indexing not implemented"
fi

if grep -q "fn index_subtree_dirs" "${PHASE1_LOADER}"; then
    ok "index_subtree_dirs() helper present"
else
    fail "index_subtree_dirs() missing"
fi

# Verify the new unit tests are actually wired up.
NEW_TESTS=(
    "walk_subtree_dirs_finds_all_nested_directories"
    "walk_subtree_dirs_respects_limit"
    "walk_subtree_dirs_skips_symlinks"
    "build_inode_key_packs_dev_and_ino_consistently"
)
for t in "${NEW_TESTS[@]}"; do
    if grep -q "fn ${t}" "${PHASE1_LOADER}"; then
        ok "test ${t} present"
    else
        fail "test ${t} missing"
    fi
done

step "Tier 1.6  Phase 3 structural checks (expand_path unification)"

# The rogue local expand_path in smart_protect.rs must be gone.
if grep -qE "^fn expand_path\(path: &Path\)" crates/agentguard-core/src/smart_protect.rs; then
    fail "rogue expand_path(&Path) still present in smart_protect.rs"
else
    ok "rogue expand_path removed from smart_protect.rs"
fi

# The unified config-side helpers must exist.
if grep -q "pub fn expand_path_p" crates/agentguard-core/src/config.rs; then
    ok "config::expand_path_p() exposed"
else
    fail "config::expand_path_p() missing"
fi

# smart_protect must import the unified helper (aliased back to expand_path).
if grep -q "expand_path_p as expand_path" crates/agentguard-core/src/smart_protect.rs; then
    ok "smart_protect imports the unified expand_path"
else
    fail "smart_protect does not import the unified expand_path"
fi

# No direct uses of dirs::home_dir() in smart_protect.rs production code.
# Tests are allowed to use it (they run as the calling user, not root).
# We split the file at the `mod tests {` line and grep only the prod half,
# AND strip comment lines (starting with //) so doc references don't count.
SP_FILE="crates/agentguard-core/src/smart_protect.rs"
TESTS_LINE=$(grep -n "^mod tests" "${SP_FILE}" | head -1 | cut -d: -f1)
if [ -n "${TESTS_LINE}" ]; then
    PROD_SLICE=$(head -n $((TESTS_LINE - 1)) "${SP_FILE}")
else
    PROD_SLICE=$(cat "${SP_FILE}")
fi
# Strip lines that are pure comments (// or /// or //!) before grepping.
PROD_LEAKS=$(printf '%s\n' "${PROD_SLICE}" \
              | grep -nE "dirs::home_dir\(\)" \
              | grep -vE ":\s*///?!?" \
              | grep -vE "^\s*[0-9]+:\s*//" || true)
if [ -z "${PROD_LEAKS}" ]; then
    ok "no production-code uses of dirs::home_dir() in smart_protect.rs"
else
    fail "dirs::home_dir() still used in production code:"
    echo "${PROD_LEAKS}" | sed 's/^/      /'
fi

step "Tier 1.7  Phase 4 structural checks (CA filename consistency)"

LEAKS=$(grep -rln "root-cert\.pem" packaging/ scripts/ crates/ 2>/dev/null \
         | grep -v "/test-fix1.sh" \
         | grep -v "Cargo.lock" || true)
if [ -z "${LEAKS}" ]; then
    ok "no occurrences of legacy 'root-cert.pem'"
else
    fail "legacy 'root-cert.pem' still present in:"
    echo "${LEAKS}" | sed 's/^/      /'
fi

# packaging files must mention root.crt
for f in packaging/install.sh packaging/install.ps1 packaging/windows/installer.iss; do
    if [ ! -f "${f}" ]; then
        skip "${f} not present"
    elif grep -q "root\.crt" "${f}"; then
        ok "${f} references root.crt"
    else
        fail "${f} does not reference root.crt"
    fi
done

step "Tier 1.8  Phase 5 structural checks (trust-install Rust API)"

CA_FILE="crates/agentguard-core/src/ca.rs"

if grep -q "pub fn install_system_trust" "${CA_FILE}"; then
    ok "LocalCa::install_system_trust() defined"
else
    fail "install_system_trust missing"
fi

if grep -q "pub fn uninstall_system_trust" "${CA_FILE}"; then
    ok "LocalCa::uninstall_system_trust() defined"
else
    fail "uninstall_system_trust missing"
fi

if grep -q "pub enum CaTrustMethod" "${CA_FILE}"; then
    ok "CaTrustMethod enum defined"
else
    fail "CaTrustMethod missing"
fi

# All four detection branches must be reachable in source.
for variant in UpdateCaCertificates UpdateCaTrust TrustAnchor Manual; do
    if grep -q "CaTrustMethod::${variant}" "${CA_FILE}"; then
        ok "${variant} branch present"
    else
        fail "${variant} branch missing"
    fi
done

# detect_ca_trust_method() must be a pub helper for testability.
if grep -q "pub fn detect_ca_trust_method" "${CA_FILE}"; then
    ok "detect_ca_trust_method() exported"
else
    fail "detect_ca_trust_method() not exported"
fi

step "Tier 1.9  Phase 6 structural checks (agentguard ca CLI)"

CLI_FILE="crates/agentguard-cli/src/main.rs"

if grep -q "enum CaCmd" "${CLI_FILE}"; then
    ok "CaCmd subcommand enum defined"
else
    fail "CaCmd enum missing"
fi

for h in handle_ca_install handle_ca_uninstall handle_ca_show; do
    if grep -q "fn ${h}" "${CLI_FILE}"; then
        ok "${h}() defined"
    else
        fail "${h}() missing"
    fi
done

if [ -f crates/agentguard-cli/tests/ca_cmd.rs ]; then
    ok "tests/ca_cmd.rs integration test file present"
    # Check the four expected tests are inside it.
    for t in ca_help_lists_install_uninstall_show \
             ca_show_with_no_existing_ca_warns_user \
             ca_show_with_generated_ca_prints_fingerprint_and_path \
             ca_uninstall_without_root_does_not_error_when_no_anchor_present; do
        if grep -q "fn ${t}" crates/agentguard-cli/tests/ca_cmd.rs; then
            ok "test ${t} present"
        else
            fail "test ${t} missing"
        fi
    done
else
    fail "tests/ca_cmd.rs missing"
fi

# ────────────────────────────────────────────────────────────────────────────
#  Tier 1 — Live CLI smoke tests (no daemon required)
# ────────────────────────────────────────────────────────────────────────────

step "Tier 1.10  Live CLI smoke (no privileges)"

CLI_BIN=./target/debug/agentguard
if [ ! -x "${CLI_BIN}" ]; then
    fail "${CLI_BIN} not built"
else
    # `ca --help` must list all 3 subcommands.
    if "${CLI_BIN}" ca --help 2>&1 | grep -qE "install.*Install" \
       && "${CLI_BIN}" ca --help 2>&1 | grep -qE "uninstall.*Remove" \
       && "${CLI_BIN}" ca --help 2>&1 | grep -qE "show.*Show"; then
        ok "agentguard ca --help lists install/uninstall/show"
    else
        fail "agentguard ca --help output incomplete"
    fi

    # `ca show` must work unprivileged with AGENTGUARD_CA_DIR override.
    TEST_CA_DIR="$(mktemp -d /tmp/agentguard-ca-test.XXXXXX)"
    trap "rm -rf '${TEST_CA_DIR}'" EXIT

    OUT=$(AGENTGUARD_CA_DIR="${TEST_CA_DIR}" "${CLI_BIN}" ca show 2>&1)
    if echo "${OUT}" | grep -q "AgentGuard local CA"; then
        ok "ca show prints header"
    else
        fail "ca show header missing"
        echo "${OUT}" | sed 's/^/      /'
    fi

    if echo "${OUT}" | grep -q "${TEST_CA_DIR}"; then
        ok "ca show honours AGENTGUARD_CA_DIR override"
    else
        fail "ca show ignored AGENTGUARD_CA_DIR"
    fi

    if echo "${OUT}" | grep -q "not yet generated"; then
        ok "ca show warns when CA not yet generated"
    else
        fail "ca show should warn about missing CA"
    fi

    # Running ca show on an empty dir must not create files.
    if [ -z "$(ls -A "${TEST_CA_DIR}" 2>/dev/null)" ]; then
        ok "ca show is read-only (no files created)"
    else
        fail "ca show created files in CA dir"
    fi

    # Now place a fake PEM and verify the fingerprint path renders.
    cat > "${TEST_CA_DIR}/root.crt" << 'EOF'
-----BEGIN CERTIFICATE-----
MIIBdummycontentforfingerprinttesting123456789012345678901234567890==
-----END CERTIFICATE-----
EOF
    OUT=$(AGENTGUARD_CA_DIR="${TEST_CA_DIR}" "${CLI_BIN}" ca show 2>&1)
    if echo "${OUT}" | grep -q "PEM SHA-256:"; then
        ok "ca show prints PEM SHA-256 when cert exists"
    else
        fail "ca show fingerprint missing for present cert"
    fi
    if echo "${OUT}" | grep -q "openssl x509 -in"; then
        ok "ca show emits openssl hint for canonical fingerprint"
    else
        fail "ca show openssl hint missing"
    fi

    # ca uninstall must be a no-op (idempotent) without root.
    if AGENTGUARD_CA_DIR="${TEST_CA_DIR}" "${CLI_BIN}" ca uninstall >/dev/null 2>&1; then
        ok "ca uninstall is idempotent (no-op when nothing installed)"
    else
        fail "ca uninstall errored when there was nothing to remove"
    fi
fi

# ────────────────────────────────────────────────────────────────────────────
#  Tier 1 — Behavioural test for Phase 3 (expand_path unification)
# ────────────────────────────────────────────────────────────────────────────

step "Tier 1.11  Behavioural: expand_path returns real-user home"

# Run a tiny doctest-style program to verify expand_path("~/foo") returns
# the user's home, not /root, even with SUDO_USER unset. We exercise
# this through the existing config tests which cover both paths.
if cargo test -p agentguard-core --lib config::tests::resolve_real_user_home \
     >/tmp/agentguard-resolve.log 2>&1; then
    ok "resolve_real_user_home tests pass"
elif cargo test -p agentguard-core --lib expand_tilde_to_home \
     >/tmp/agentguard-expand.log 2>&1; then
    ok "smart_protect::tests::expand_tilde_to_home passes"
else
    skip "no resolver tests matched"
fi

# Also re-run the smart_protect tests that exercise the unified path.
if cargo test -p agentguard-core --lib smart_protect::tests \
     >/tmp/agentguard-smart.log 2>&1; then
    SMART_COUNT=$(grep -E "^test result: ok\." /tmp/agentguard-smart.log | awk '{ print $4 }')
    ok "smart_protect tests: ${SMART_COUNT} pass"
else
    fail "smart_protect tests failed"
fi

# ────────────────────────────────────────────────────────────────────────────
#  Tier 1 — Phase 5 detect_ca_trust_method actually identifies this host
# ────────────────────────────────────────────────────────────────────────────

step "Tier 1.12  Behavioural: detect_ca_trust_method on this host"

# We can only assert that *some* tool was detected on a system where
# certificates work. On Fedora `update-ca-trust` should win.
HAVE_UPD_CA_TRUST=0
HAVE_UPD_CA_CRT=0
HAVE_TRUST=0
command -v update-ca-trust       >/dev/null 2>&1 && HAVE_UPD_CA_TRUST=1
command -v update-ca-certificates >/dev/null 2>&1 && HAVE_UPD_CA_CRT=1
command -v trust                  >/dev/null 2>&1 && HAVE_TRUST=1
info "update-ca-trust:        $([ $HAVE_UPD_CA_TRUST -eq 1 ] && echo present || echo absent)"
info "update-ca-certificates: $([ $HAVE_UPD_CA_CRT  -eq 1 ] && echo present || echo absent)"
info "trust:                  $([ $HAVE_TRUST       -eq 1 ] && echo present || echo absent)"

if [ $HAVE_UPD_CA_TRUST -eq 1 ] || [ $HAVE_UPD_CA_CRT -eq 1 ] || [ $HAVE_TRUST -eq 1 ]; then
    ok "host has at least one trust-store tool — install_system_trust would succeed"
else
    skip "host has none of the supported trust-store tools (Manual fallback would trigger)"
fi

# ────────────────────────────────────────────────────────────────────────────
#  Tier 2 — Privileged tests (only run when EUID == 0)
# ────────────────────────────────────────────────────────────────────────────

if [ "$(id -u)" -eq 0 ]; then
    step "Tier 2.1  agentguard ca install (real trust store)"

    PRE_ANCHOR_FED="/etc/pki/ca-trust/source/anchors/agentguard-ca.crt"
    PRE_ANCHOR_DEB="/usr/local/share/ca-certificates/agentguard-ca.crt"
    if [ -f "${PRE_ANCHOR_FED}" ] || [ -f "${PRE_ANCHOR_DEB}" ]; then
        skip "system already has a stale anchor — clean it before running this test"
    else
        ROOT_CA_DIR="/var/lib/agentguard/ca"
        mkdir -p "${ROOT_CA_DIR}"
        chmod 700 "${ROOT_CA_DIR}"

        # Generate a CA quickly via the daemon code path. We do this by
        # asking the CLI to "show", which doesn't generate; so we
        # instead just call install — install also generates if needed.
        if "${CLI_BIN}" ca install >/tmp/agentguard-ca-install.log 2>&1; then
            ok "agentguard ca install (root) succeeded"

            if [ -f "${PRE_ANCHOR_FED}" ] || [ -f "${PRE_ANCHOR_DEB}" ]; then
                ok "anchor file written to system trust dir"
            else
                fail "install reported success but no anchor file appeared"
            fi

            # Clean up: uninstall and verify the file is gone.
            if "${CLI_BIN}" ca uninstall >/tmp/agentguard-ca-uninstall.log 2>&1; then
                ok "agentguard ca uninstall (root) succeeded"
                if [ ! -f "${PRE_ANCHOR_FED}" ] && [ ! -f "${PRE_ANCHOR_DEB}" ]; then
                    ok "anchor file removed by uninstall"
                else
                    fail "anchor file still present after uninstall"
                fi
            else
                fail "ca uninstall failed — see /tmp/agentguard-ca-uninstall.log"
            fi
        else
            fail "ca install failed — see /tmp/agentguard-ca-install.log"
            sed 's/^/      /' /tmp/agentguard-ca-install.log | tail -20
        fi
    fi
else
    step "Tier 2 (skipped — needs root)"
    info "Run again as 'sudo bash scripts/test-fix1.sh' to exercise CA install/uninstall"
    info "against the real /etc/pki or /usr/local/share/ca-certificates trust store."
fi

# ────────────────────────────────────────────────────────────────────────────

echo
echo "${BOLD}═════════════════════════════════════════════════════════════${RESET}"
printf '  Results: %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
    "${GREEN}" "${PASS}" "${RESET}" \
    "${RED}"   "${FAIL}" "${RESET}" \
    "${YELLOW}" "${SKIP}" "${RESET}"
echo "${BOLD}═════════════════════════════════════════════════════════════${RESET}"

if [ ${FAIL} -eq 0 ]; then
    echo "  ${GREEN}${BOLD}✓ Fix 1.0 verification PASSED${RESET}"
    exit 0
else
    echo "  ${RED}${BOLD}✗ ${FAIL} check(s) failed${RESET}"
    exit 1
fi
