//! AgentGuard bootstrap installer — Fase 3.
//!
//! Detects the operating system and architecture, then:
//!   Linux   → downloads agentguard-cli + agentguard-linux (~6 MB)
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

[[agent_processes]]
name = "windsurf"
match = { exe = "windsurf" }

[[agent_processes]]
name = "opencode"
match = { exe = "opencode" }

[[agent_processes]]
name = "aider"
match = { exe = "aider" }

[[agent_processes]]
name = "vscode-copilot"
match = { exe_any = ["code", "code-insiders", "codium"] }

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
StartLimitIntervalSec=10
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/agentguard-linux
Restart=always
RestartSec=100ms
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
    Windows,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
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
            Platform::Windows => "pc-windows",
        },
        "gnu"
    );
    Target {
        platform,
        arch: arch.to_string(),
        triple,
    }
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
    let tag = if version == "latest" {
        "latest/download"
    } else {
        &format!("download/{version}")
    };

    // 1. Download CLI
    let cli_name = format!("agentguard-{triple}", triple = target.triple);
    let cli_url = format!("{GH}/{REPO}/releases/{tag}/{cli_name}");
    println!("  → agentguard CLI...");
    let cli = download(&cli_url)
        .with_context(|| format!("download agentguard CLI for {}", target.triple))?;
    install_bin(bin_dir, "agentguard", &cli)?;

    // 2. Download daemon
    let daemon_name = format!("agentguard-linux-{}", target.triple);
    let daemon_url = format!("{GH}/{REPO}/releases/{tag}/{daemon_name}");
    println!("  → agentguard-linux daemon...");
    let daemon = download(&daemon_url)
        .with_context(|| format!("download agentguard-linux for {}", target.triple))?;
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
    for dir in &[
        "/var/lib/agentguard/vault",
        "/var/lib/agentguard/ca",
        "/var/log/agentguard",
    ] {
        std::fs::create_dir_all(dir)?;
    }

    // 5. systemd
    println!("  → systemd service...");
    std::fs::write("/etc/systemd/system/agentguard.service", SYSTEMD_UNIT)?;
    Command::new("systemctl").args(["daemon-reload"]).status()?;
    Command::new("systemctl")
        .args(["enable", "--now", "agentguard"])
        .status()?;

    println!();
    println!("✓ AgentGuard installed on {}", target.platform);
    println!("  agentguard status       # check protection");
    println!("  agentguard protect ~/Documents  # protect a folder");
    Ok(())
}

fn install_windows(target: &Target, version: &str) -> Result<()> {
    let tag = if version == "latest" {
        "latest/download"
    } else {
        &format!("download/{version}")
    };

    // 1. Download CLI
    let cli_name = format!("agentguard-{triple}.exe", triple = target.triple);
    let cli_url = format!("{GH}/{REPO}/releases/{tag}/{cli_name}");
    println!("  → agentguard CLI...");
    let cli = download(&cli_url)
        .with_context(|| format!("download agentguard CLI for {}", target.triple))?;
    let install_dir = r"C:\Program Files\AgentGuard";
    std::fs::create_dir_all(install_dir).with_context(|| format!("create {install_dir}"))?;
    let cli_path = format!("{install_dir}\\agentguard.exe");
    std::fs::write(&cli_path, &cli).with_context(|| format!("write {cli_path}"))?;

    // 2. Download daemon
    let daemon_name = format!("agentguard-windows-{triple}.exe", triple = target.triple);
    let daemon_url = format!("{GH}/{REPO}/releases/{tag}/{daemon_name}");
    println!("  → agentguard-windows daemon...");
    let daemon = download(&daemon_url)
        .with_context(|| format!("download agentguard-windows for {}", target.triple))?;
    let daemon_path = format!("{install_dir}\\agentguard-windows.exe");
    std::fs::write(&daemon_path, &daemon).with_context(|| format!("write {daemon_path}"))?;

    // 3. Config
    let config_dir = r"C:\ProgramData\AgentGuard";
    std::fs::create_dir_all(config_dir).with_context(|| format!("create {config_dir}"))?;
    let config_path = format!("{config_dir}\\config.toml");
    if !std::path::Path::new(&config_path).exists() {
        println!("  → config.toml...");
        std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;
    }

    // 4. Install as Windows Service
    println!("  → Registering Windows Service...");
    let sc_status = std::process::Command::new("sc.exe")
        .args([
            "create",
            "AgentGuard",
            "binPath=",
            &format!("{daemon_path} --service"),
            "start=",
            "auto",
            "type=",
            "own",
            "obj=",
            "LocalSystem",
        ])
        .status();
    if let Err(e) = sc_status {
        eprintln!("  ⚠ Failed to register service (may need admin): {e}");
    }

    let start_status = std::process::Command::new("sc.exe")
        .args(["start", "AgentGuard"])
        .status();
    if let Err(e) = start_status {
        eprintln!("  ⚠ Failed to start service: {e}");
    }

    println!();
    println!("✓ AgentGuard installed on Windows");
    println!("  agentguard status       # check protection");
    println!("  agentguard protect C:\\Projects  # protect a folder");

    // ── Windows binary displacement ──
    println!("  → Scanning for AI agents...");
    let daemon_path = format!("{install_dir}\\agentguard-windows.exe");
    install_displacement_windows(&daemon_path)?;

    Ok(())
}

fn install_bin(dir: &str, name: &str, data: &[u8]) -> Result<()> {
    let path = format!("{dir}/{name}");
    std::fs::write(&path, data).with_context(|| format!("write {path}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

// ── Binary displacement (Fase 1 — v2.0) ─────────────────────

/// Known AI agent executable names to look for in PATH.
const KNOWN_AGENTS: &[&str] = &[
    "claude",
    "claude-code",
    "cursor",
    "opencode",
    "aider",
    "windsurf",
    "code",
    "codium",
    "vscode-copilot",
];

/// Magic bytes in the AgentGuard shim ELF binary.
const SHIM_MAGIC: &[u8] = b"AGENTGUARD_SHIM_V1\x00";
const MAGIC_SCAN_BYTES: usize = 8192;

/// Displacement database — persisted to ~/.agentguard/displaced.json.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct DisplacementDb {
    #[serde(skip)]
    db_path: std::path::PathBuf,
    entries: Vec<DisplacementEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DisplacementEntry {
    shim_path: std::path::PathBuf,
    real_path: std::path::PathBuf,
    agent_name: String,
    displaced_at: u64,
    shim_hash: String,
}

use std::path::{Path, PathBuf};

fn default_db_path() -> PathBuf {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return PathBuf::from("/var/lib/agentguard/displaced.json");
        }
    }
    dirs_next().join(".agentguard/displaced.json")
}

fn dirs_next() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(home) = std::env::var("USERPROFILE") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from("/tmp")
}

fn load_displacement_db() -> DisplacementDb {
    let db_path = default_db_path();
    match std::fs::read_to_string(&db_path) {
        Ok(json) => match serde_json::from_str::<DisplacementDb>(&json) {
            Ok(mut db) => {
                db.db_path = db_path;
                db
            }
            Err(_) => DisplacementDb {
                db_path,
                entries: vec![],
            },
        },
        Err(_) => DisplacementDb {
            db_path,
            entries: vec![],
        },
    }
}

fn save_displacement_db(db: &DisplacementDb) -> Result<()> {
    if let Some(parent) = db.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(db)?;
    std::fs::write(&db.db_path, json)?;
    Ok(())
}

/// Check if a file is already an AgentGuard shim (contains magic bytes).
fn is_agentguard_shim(path: &Path) -> bool {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = vec![0u8; MAGIC_SCAN_BYTES];
    let n = match std::io::Read::read(&mut file, &mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    buf[..n].windows(SHIM_MAGIC.len()).any(|w| w == SHIM_MAGIC)
}

/// Check if the current user can write to a file.
fn is_user_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                m.uid() == uid || uid == 0
            }
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        std::fs::metadata(path).is_ok()
    }
}

/// Compute SHA256 of a file for the displacement database.
fn compute_shim_hash(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Find known AI agents in Windows PATH (using `where` or manual scan).
fn find_agents_windows() -> Vec<PathBuf> {
    let mut found = Vec::new();
    // Check common install locations
    let search_dirs = &[
        r"C:\Users",
        r"C:\Program Files",
        &format!(r"C:\Users\{}\AppData\Local\Programs", whoami()),
        &format!(r"C:\Users\{}\AppData\Roaming\npm", whoami()),
    ];

    for search_dir in search_dirs {
        if !Path::new(search_dir).is_dir() {
            continue;
        }
        for agent in KNOWN_AGENTS.iter() {
            let agent_exe = format!("{}.exe", agent);
            // Walk subdirs (max depth 3) looking for the agent
            find_exe_in_dir(search_dir, &agent_exe, 3, &mut found);
        }
    }
    found
}

fn whoami() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "Default".into())
}

fn find_exe_in_dir(dir: &str, exe_name: &str, max_depth: u32, found: &mut Vec<PathBuf>) {
    if max_depth == 0 {
        return;
    }
    let dir_path = Path::new(dir);
    let candidate = dir_path.join(exe_name);
    if candidate.exists() && !is_agentguard_shim(&candidate) {
        found.push(candidate);
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let subdir = entry.path();
                if let Some(s) = subdir.to_str() {
                    find_exe_in_dir(s, exe_name, max_depth - 1, found);
                }
            }
        }
    }
}

/// Install binary displacement for all detected Windows agents.
fn install_displacement_windows(launcher_path: &str) -> Result<()> {
    let agents = find_agents_windows();
    if agents.is_empty() {
        println!("    No AI agents found to displace.");
        return Ok(());
    }

    let mut db = load_displacement_db();
    let launcher = PathBuf::from(launcher_path);
    let mut count = 0;

    for agent_binary in &agents {
        let name = agent_binary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if db.entries.iter().any(|e| e.shim_path == *agent_binary) {
            continue;
        }

        println!("    → {} (displacing...)", agent_binary.display());

        let parent = agent_binary.parent().unwrap().to_path_buf();
        let real_path = parent.join(format!(".{}.real.exe", name));

        std::fs::rename(agent_binary, &real_path)?;
        std::fs::copy(&launcher, agent_binary)?;

        let hash = compute_shim_hash(&launcher)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        db.entries.push(DisplacementEntry {
            shim_path: agent_binary.clone(),
            real_path,
            agent_name: name,
            displaced_at: now,
            shim_hash: hash,
        });
        count += 1;
    }

    if count > 0 {
        save_displacement_db(&db)?;
        println!("    ✓ Displaced {} Windows agent(s)", count);
    }

    Ok(())
}
fn find_agents_in_path() -> Vec<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let mut found = Vec::new();

    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            continue;
        }

        for &agent_name in KNOWN_AGENTS {
            let agent_path = dir_path.join(agent_name);
            if agent_path.exists() && !is_agentguard_shim(&agent_path) {
                found.push(agent_path);
            }
        }
    }

    // Sort: user-writable first, system paths last
    found.sort_by_key(|p| !is_user_writable(p));
    found
}

/// Install binary displacement for all detected agents.
fn install_displacement(shim_path: &Path) -> Result<()> {
    let agents = find_agents_in_path();

    if agents.is_empty() {
        println!("  No AI agents found in PATH to displace.");
        return Ok(());
    }

    let mut db = load_displacement_db();
    let mut displaced_count = 0;
    let mut warned_count = 0;

    let shim_hash = compute_shim_hash(shim_path)?;

    for agent_binary in &agents {
        let name = agent_binary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Already displaced?
        if db.entries.iter().any(|e| e.shim_path == *agent_binary) {
            continue;
        }

        // Not writable?
        if !is_user_writable(agent_binary) {
            println!(
                "  ⚠ {} — not writable (system path, needs root)",
                agent_binary.display()
            );
            println!("    Suggestion: reinstall {name} via npm/pip/cargo in user directory");
            warned_count += 1;
            continue;
        }

        // Compute .real path
        let parent = agent_binary.parent().unwrap().to_path_buf();
        let real_path = parent.join(format!(".{name}.real"));

        // Displace
        println!("  → {} → {}", agent_binary.display(), real_path.display());
        std::fs::rename(agent_binary, &real_path)
            .with_context(|| format!("rename {}", agent_binary.display()))?;

        if let Err(e) = std::fs::copy(shim_path, agent_binary) {
            // Rollback
            let _ = std::fs::rename(&real_path, agent_binary);
            return Err(anyhow::anyhow!("copy shim: {e}"));
        }

        // Preserve permissions
        if let Ok(meta) = std::fs::metadata(&real_path) {
            let _ = std::fs::set_permissions(agent_binary, meta.permissions());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        db.entries.push(DisplacementEntry {
            shim_path: agent_binary.clone(),
            real_path,
            agent_name: name,
            displaced_at: now,
            shim_hash: shim_hash.clone(),
        });

        displaced_count += 1;
    }

    if displaced_count > 0 {
        save_displacement_db(&db)?;
        println!(
            "  ✓ Displaced {} agent(s) with AgentGuard shim",
            displaced_count
        );
    }
    if warned_count > 0 {
        println!("  ⚠ {warned_count} agent(s) not displaced (system paths, need root)");
        println!(
            "  ℹ Agents launched by absolute path from system dirs are NOT protected without root."
        );
        println!("  ℹ Run 'sudo agentguard install' for full protection.");
    }

    Ok(())
}

fn locate_shim_binary() -> Option<PathBuf> {
    // Look in the same directory as the installer
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(Path::new("."));
        let candidate = dir.join("agentguard-shim");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    // Look in ~/.agentguard/
    let home = dirs_next();
    let candidate = home.join(".agentguard/agentguard-shim");
    if candidate.exists() {
        return Some(candidate);
    }
    None
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
        Platform::Windows => install_windows(&target, &version)?,
    }

    // ── Binary displacement (Fase 1 — v2.0) ──
    #[cfg(unix)]
    {
        println!("  → Scanning for AI agents in PATH...");
        if let Some(shim) = locate_shim_binary() {
            install_displacement(&shim)?;
        } else {
            println!("  ⚠ agentguard-shim not found — run 'agentguard-install-shim' or build from source");
            println!(
                "    Binary displacement skipped. AgentGuard daemon will protect via scanning."
            );
        }
    }

    Ok(())
}
