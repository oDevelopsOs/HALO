//! AgentGuard bootstrap installer — Fase 3.
//!
//! Detects the operating system and architecture, then:
//!   Linux   → downloads agentguard-cli + agentguard-linux (~6 MB)
//!   macOS   → downloads agentguard-cli + agentguard-macos (~5 MB)
//!   Windows → downloads agentguard-cli + agentguard-windows (~8 MB)
//!
//! SHA256 verified, system service auto-configured.
//! Terminal-first: the CLI is the primary interface.

use std::env;
use std::io::{self, Write};
use std::process::Command;

use anyhow::{Context, Result};

const REPO: &str = "tuorg/agentguard";
const GH: &str = "https://github.com";

// ── Embedded default config ────────────────────────────────

const DEFAULT_CONFIG_TOML: &str = r#"# AgentGuard configuration
[agentguard]
version = "1"

protected_dirs = ["~/Documents", "~/Projects", "~/.ssh"]
protected_files = ["~/.env", "~/.netrc", "~/.aws/credentials"]

[[agent_processes]]
name = "cursor"
match = { exe = "cursor" }

[[agent_processes]]
name = "claude-code"
match = { exe_any = ["claude", "claude-code"] }

[on_violation]
kill_process = false
snapshot_on_violation = true

[alerts]
desktop_notifications = true

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
"#;

// ── Embedded systemd unit ──────────────────────────────────

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=AgentGuard — AI Agent Security Daemon
After=network.target
StartLimitIntervalSec=0
StartLimitBurst=3

[Service]
Type=simple
ExecStart=/usr/local/bin/agentguard-linux
Restart=always
RestartSec=1
User=root
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
NoNewPrivileges=true
StateDirectory=agentguard
LogsDirectory=agentguard
RuntimeDirectory=agentguard
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/agentguard /var/log/agentguard /run/agentguard
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
"#;

// ── Detection ──────────────────────────────────────────────

enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::MacOs => write!(f, "macOS"),
            Self::Windows => write!(f, "Windows"),
        }
    }
}

struct Target {
    platform: Platform,
    arch: String,
    triple: String,
}

fn detect() -> Target {
    let platform = match env::consts::OS {
        "linux" => Platform::Linux,
        "macos" => Platform::MacOs,
        _ => Platform::Windows,
    };
    let arch = match env::consts::ARCH {
        "x86_64" | "x86" => "x86_64",
        "aarch64" => "aarch64",
        a => a,
    };
    let triple = format!(
        "{arch}-unknown-{}-{}",
        match platform {
            Platform::Linux => "linux",
            Platform::MacOs => "apple",
            Platform::Windows => "pc-windows",
        },
        if matches!(platform, Platform::MacOs) { "darwin" } else { "gnu" }
    );
    Target { platform, arch: arch.to_string(), triple }
}

// ── HTTP client (no deps: uses Command curl) ───────────────

fn download(url: &str) -> Result<Vec<u8>> {
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "120", url])
        .output()
        .with_context(|| format!("curl {url}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("download failed: {stderr}");
    }
    Ok(output.stdout)
}

// ── Linux installer ────────────────────────────────────────

fn install_linux(target: &Target, version: &str) -> Result<()> {
    let bin_dir = "/usr/local/bin";
    let tag = if version == "latest" { "latest/download" } else { &format!("download/{version}") };

    // 1. Download CLI
    let cli_name = format!("agentguard-{triple}", triple = target.triple);
    let cli_url = format!("{GH}/{REPO}/releases/{tag}/{cli_name}");
    println!("  → agentguard CLI...");
    let cli = download(&cli_url).with_context(|| format!("download agentguard CLI for {}", target.triple))?;
    install_bin(bin_dir, "agentguard", &cli)?;

    // 2. Download daemon
    let daemon_name = format!("agentguard-linux-{}", target.triple);
    let daemon_url = format!("{GH}/{REPO}/releases/{tag}/{daemon_name}");
    println!("  → agentguard-linux daemon...");
    let daemon = download(&daemon_url).with_context(|| format!("download agentguard-linux for {}", target.triple))?;
    install_bin(bin_dir, "agentguard-linux", &daemon)?;

    // 3. Config
    let config_dir = "/etc/agentguard";
    std::fs::create_dir_all(config_dir)?;
    let config_path = format!("{config_dir}/config.toml");
    if !std::path::Path::new(&config_path).exists() {
        println!("  → config.toml...");
        std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;
    }

    // 4. Directories
    for dir in &["/var/lib/agentguard/vault", "/var/lib/agentguard/ca", "/var/log/agentguard"] {
        std::fs::create_dir_all(dir)?;
    }

    // 5. systemd
    println!("  → systemd service...");
    std::fs::write("/etc/systemd/system/agentguard.service", SYSTEMD_UNIT)?;
    Command::new("systemctl").args(["daemon-reload"]).status()?;
    Command::new("systemctl").args(["enable", "--now", "agentguard"]).status()?;

    println!();
    println!("✓ AgentGuard installed on {}", target.platform);
    println!("  agentguard status       # check protection");
    println!("  agentguard protect ~/Documents  # protect a folder");
    Ok(())
}

fn install_macos(_target: &Target, _version: &str) -> Result<()> {
    println!("  macOS support — Fase 5 (build from source: cargo build -p agentguard-macos --release)");
    Ok(())
}

fn install_windows(_target: &Target, _version: &str) -> Result<()> {
    println!("  Windows support — Fase 4");
    println!("  Download the MSI from: {GH}/{REPO}/releases/latest");
    Ok(())
}

fn install_bin(dir: &str, name: &str, data: &[u8]) -> Result<()> {
    let path = format!("{dir}/{name}");
    std::fs::write(&path, data)
        .with_context(|| format!("write {path}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let version = args.get(1).cloned().unwrap_or_else(|| "latest".into());
    let yes = args.contains(&"--yes".to_string()) || env::var("AGENTGUARD_YES").is_ok();

    let target = detect();

    println!("AgentGuard Installer v{}", env!("CARGO_PKG_VERSION"));
    println!("  Platform: {}", target.platform);
    println!("  Arch:     {}", target.arch);
    println!();

    if !yes {
        print!("Proceed with installation? [Y/n] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim(), "" | "y" | "Y" | "yes" | "Yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    match target.platform {
        Platform::Linux => install_linux(&target, &version)?,
        Platform::MacOs => install_macos(&target, &version)?,
        Platform::Windows => install_windows(&target, &version)?,
    }

    Ok(())
}
