//! Integration tests for the `agentguard ca {install|uninstall|show}` CLI
//! subcommand introduced in Phase 6.
//!
//! These tests invoke the compiled `agentguard` binary directly via
//! `cargo run` to exercise the user-facing surface end-to-end. They run
//! unprivileged: any flow that requires root (`install`, `uninstall`)
//! is verified only via the `--help` output and dry-run paths that don't
//! actually write to `/etc/...`.
//!
//! `show` is exercised against a temporary `AGENTGUARD_CA_DIR` so the
//! test never touches the real `~/.agentguard/ca`.

use std::process::Command;

/// Path to the compiled `agentguard` binary. Cargo guarantees this env
/// var is set when running integration tests.
fn agentguard_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is provided by Cargo for any [[bin]] declared
    // in the same package. The bin name is `agentguard` per Cargo.toml.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_agentguard"))
}

/// Run `agentguard <args>` with a clean env (no AGENTGUARD_USER_HOME
/// inherited from outer test runs) plus any explicit `extra_env` pairs.
/// Returns (stdout, stderr, status code).
fn run(args: &[&str], extra_env: &[(&str, &str)]) -> (String, String, i32) {
    let mut cmd = Command::new(agentguard_bin());
    cmd.args(args);
    cmd.env_remove("AGENTGUARD_USER_HOME");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn agentguard");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn ca_help_lists_install_uninstall_show() {
    let (stdout, _stderr, code) = run(&["ca", "--help"], &[]);
    assert_eq!(code, 0, "ca --help should succeed");
    assert!(stdout.contains("install"), "missing 'install' in help");
    assert!(stdout.contains("uninstall"), "missing 'uninstall' in help");
    assert!(stdout.contains("show"), "missing 'show' in help");
}

#[test]
fn ca_show_with_no_existing_ca_warns_user() {
    // Use a tempdir we know is empty.
    let tmp = tempfile::tempdir().expect("tempdir");
    let ca_dir = tmp.path().join("agentguard-ca-test");
    let ca_dir_str = ca_dir.to_string_lossy().to_string();

    let (stdout, _stderr, code) = run(&["ca", "show"], &[("AGENTGUARD_CA_DIR", &ca_dir_str)]);

    // `show` must not error if the CA file does not yet exist; it should
    // print a helpful warning instead.
    assert_eq!(code, 0, "ca show on empty dir should succeed; got {}", code);
    assert!(
        stdout.contains("not yet generated") || stdout.contains("CA not yet"),
        "expected 'not yet generated' warning, got:\n{}",
        stdout
    );
    // It must NOT have created the directory or any file as a side
    // effect of `show` — the CLI never writes anything in show mode.
    assert!(
        !ca_dir.join("root.crt").exists(),
        "ca show must not create root.crt"
    );
}

#[test]
fn ca_show_with_generated_ca_prints_fingerprint_and_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();

    // Write a deterministic dummy PEM file; `show` only hashes its bytes.
    // (We intentionally don't go through `LocalCa::generate_and_persist`
    // here because that would require linking the core crate into the
    // test, when all we want is to verify the formatting path.)
    let dummy_pem = "-----BEGIN CERTIFICATE-----\n\
                     MIIBdummyforfingerprinttestxx==\n\
                     -----END CERTIFICATE-----\n";
    std::fs::write(ca_dir.join("root.crt"), dummy_pem).unwrap();

    let ca_dir_str = ca_dir.to_string_lossy().to_string();
    let (stdout, _stderr, code) = run(&["ca", "show"], &[("AGENTGUARD_CA_DIR", &ca_dir_str)]);

    assert_eq!(code, 0, "ca show with valid PEM should succeed");
    assert!(stdout.contains(&ca_dir_str), "stdout should mention CA dir");
    assert!(
        stdout.contains("root.crt"),
        "stdout should mention cert filename"
    );
    assert!(
        stdout.contains("PEM SHA-256:"),
        "stdout should print fingerprint label"
    );
    // Each byte rendered as "XX:" → 32 bytes × 3 = 96 chars (no trailing colon)
    assert!(
        stdout.contains(":") && stdout.matches(':').count() >= 31,
        "fingerprint should be colon-separated, got:\n{}",
        stdout
    );
}

#[test]
fn ca_uninstall_without_root_does_not_error_when_no_anchor_present() {
    // Without root we cannot actually delete files in /etc/, but the
    // function is documented as idempotent. Running it on a system
    // where no anchor was previously installed must succeed silently.
    let (stdout, _stderr, code) = run(&["ca", "uninstall"], &[]);
    assert_eq!(
        code, 0,
        "ca uninstall must be idempotent; got {} stdout={}",
        code, stdout
    );
}
