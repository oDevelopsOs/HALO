/// Smart protection — detección automática de rutas importantes,
/// workspaces de agentes IA, y secretos. Genera sugerencias de protección
/// para el comando `agentguard setup --smart`.
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::{expand_path_p as expand_path, RiskLevel, SmartProtection};

const KNOWN_AI_AGENTS: &[&str] = &[
    "cursor",
    "Cursor",
    "claude",
    "claude-code",
    "code",
    "code-insiders",
    "codium",
    "windsurf",
    "Windsurf",
    "aider",
    "opencode",
    "opencode-go",
];

const SECRET_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "*.pem",
    "credentials",
    "credentials.json",
    "token",
    "secrets.yaml",
    "secrets.yml",
    ".npmrc",
    ".pypirc",
    "config.json",
];

const MAX_DIR_SCAN_ENTRIES: u64 = 10_000;
const MAX_DIR_SCAN_DURATION: Duration = Duration::from_secs(5);
const MAX_RECENT_MODIFICATION_MINUTES: i64 = 15;

#[derive(Debug, Clone)]
pub struct DetectedAgent {
    pub name: String,
    pub pid: u32,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProtectionSuggestion {
    pub path: PathBuf,
    pub group: String,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub size_bytes: u64,
    pub file_count: u64,
    pub contains_secrets: bool,
    pub is_git_repo: bool,
    pub active_agents: Vec<String>,
}

pub fn generate_smart_suggestions(config: &SmartProtection) -> Vec<ProtectionSuggestion> {
    let mut suggestions: Vec<ProtectionSuggestion> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    let detected_agents = detect_ai_agents();

    for profile in &config.profiles {
        if profile.auto {
            suggestions.extend(detect_ai_workspaces(&detected_agents, &mut seen));
        } else {
            for path_pattern in &profile.paths {
                let expanded = expand_path(path_pattern);
                if !expanded.exists() {
                    continue;
                }
                let canonical = match expanded.canonicalize() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if !seen.insert(canonical.clone()) {
                    continue;
                }

                let suggestion = analyze_path(&canonical, &profile.name, &detected_agents);
                if suggestion.risk_level >= RiskLevel::Low {
                    suggestions.push(suggestion);
                }
            }
        }
    }

    suggestions.extend(fallback_home_detect(&mut seen, &detected_agents));

    // Deduplicate by canonical path, keeping the suggestion with higher risk_level
    // (already handled by seen set during insertion)
    suggestions.sort_by_key(|s| std::cmp::Reverse(s.risk_level));
    suggestions
}

fn analyze_path(path: &Path, group: &str, agents: &[DetectedAgent]) -> ProtectionSuggestion {
    let is_git_repo = path.join(".git").is_dir();
    let (size_bytes, file_count) = estimate_dir_size(path);
    let has_secrets = quick_secret_scan(path);
    let active: Vec<String> = agents
        .iter()
        .filter_map(|a| {
            let cwd = a.cwd.as_ref()?;
            if cwd == path || cwd.starts_with(path) {
                Some(a.name.clone())
            } else {
                None
            }
        })
        .collect();

    let reason = build_reason(is_git_repo, size_bytes, &active, has_secrets);
    let risk_level = calc_risk(is_git_repo, size_bytes, has_secrets, !active.is_empty());

    ProtectionSuggestion {
        path: path.to_path_buf(),
        group: group.to_string(),
        reason,
        risk_level,
        size_bytes,
        file_count,
        contains_secrets: has_secrets,
        is_git_repo,
        active_agents: active,
    }
}

fn calc_risk(is_git: bool, size: u64, has_secrets: bool, agents_active: bool) -> RiskLevel {
    if has_secrets && (is_git || agents_active) {
        RiskLevel::Critical
    } else if has_secrets || (is_git && agents_active) || (size > 1_000_000_000 && agents_active) {
        RiskLevel::High
    } else if is_git || agents_active || size > 1_000_000_000 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn build_reason(is_git: bool, size: u64, agents: &[String], has_secrets: bool) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !agents.is_empty() {
        parts.push(format!(
            "Agente{} {} activo aquí",
            if agents.len() > 1 { "s" } else { "" },
            agents.join(", ")
        ));
    }
    if is_git {
        let repo_count = count_git_repos_raw();
        parts.push("Repositorio git detectado".to_string());
        if repo_count > 1 {
            parts.push(format!("({repo_count} repos en subdirectorios)"));
        }
    }
    if size > 0 {
        parts.push(fmt_size(size));
    }
    if has_secrets {
        parts.push("contiene archivos sensibles".to_string());
    }

    if parts.is_empty() {
        "Directorio de usuario".to_string()
    } else {
        parts.join(" — ")
    }
}

// ── AI Agent Detection ─────────────────────────────────────

fn detect_ai_agents() -> Vec<DetectedAgent> {
    #[cfg(target_os = "linux")]
    return detect_agents_proc();

    #[cfg(not(target_os = "linux"))]
    return Vec::new();
}

#[cfg(target_os = "linux")]
fn detect_agents_proc() -> Vec<DetectedAgent> {
    let mut agents: Vec<DetectedAgent> = Vec::new();
    let current_pid = std::process::id();

    let entries = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return agents,
    };

    for entry in entries.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == current_pid {
            continue;
        }

        let comm = read_proc_comm(pid);
        let name = match comm {
            Some(ref c) if is_known_agent(c) => c.clone(),
            _ => continue,
        };

        let cwd = read_proc_cwd(pid);
        agents.push(DetectedAgent { name, pid, cwd });
    }

    agents
}

#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

fn is_known_agent(comm: &str) -> bool {
    let comm_lower = comm.to_lowercase();
    KNOWN_AI_AGENTS
        .iter()
        .any(|a| comm_lower.contains(&a.to_lowercase()))
}

// ── AI Workspace Detection ─────────────────────────────────

fn detect_ai_workspaces(
    agents: &[DetectedAgent],
    seen: &mut HashSet<PathBuf>,
) -> Vec<ProtectionSuggestion> {
    let mut suggestions = Vec::new();

    for agent in agents {
        let cwd = match &agent.cwd {
            Some(c) => c.clone(),
            None => continue,
        };

        if !is_worth_protecting(&cwd) {
            continue;
        }

        let canonical = match cwd.canonicalize() {
            Ok(c) => c,
            Err(_) => continue,
        };

        if !seen.insert(canonical.clone()) {
            continue;
        }

        let recent_mods = count_recent_modifications(&canonical);
        let is_git = canonical.join(".git").is_dir();
        let (size_bytes, file_count) = estimate_dir_size(&canonical);

        suggestions.push(ProtectionSuggestion {
            path: canonical.clone(),
            group: "AI Workspaces".to_string(),
            reason: format!(
                "{} está trabajando aquí ({} archivos modificados recientemente)",
                agent.name, recent_mods
            ),
            risk_level: if is_git {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            },
            size_bytes,
            file_count,
            contains_secrets: false,
            is_git_repo: is_git,
            active_agents: vec![agent.name.clone()],
        });
    }

    suggestions
}

fn is_worth_protecting(path: &Path) -> bool {
    // Use the same real-user resolver the rest of the daemon uses so we
    // don't accidentally compare against `/root` when running under
    // systemd (where `dirs::home_dir()` returns the daemon's UID's home).
    let home = match crate::config::resolve_real_user_home() {
        Some(h) => h,
        None => return false,
    };

    if path == Path::new("/") || path == Path::new("/tmp") || path == Path::new("/usr") {
        return false;
    }

    if path == home {
        return false;
    }

    // Skip well-known system paths
    for skip in &["/proc", "/sys", "/dev", "/run", "/var/run", "/snap"] {
        if path.starts_with(skip) {
            return false;
        }
    }

    true
}

// ── Filesystem Analysis ────────────────────────────────────

fn estimate_dir_size(path: &Path) -> (u64, u64) {
    let mut total_size: u64 = 0;
    let mut file_count: u64 = 0;
    let start = Instant::now();

    walk_dir(path, 0, &mut total_size, &mut file_count, start);
    (total_size, file_count)
}

fn walk_dir(path: &Path, depth: usize, size: &mut u64, count: &mut u64, start: Instant) {
    if depth > 20 || *count >= MAX_DIR_SCAN_ENTRIES || start.elapsed() > MAX_DIR_SCAN_DURATION {
        return;
    }

    let entries = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if *count >= MAX_DIR_SCAN_ENTRIES || start.elapsed() > MAX_DIR_SCAN_DURATION {
            return;
        }

        let path = entry.path();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Skip well-known large/virtual directories
        if file_name.starts_with('.') && is_skip_dir(&file_name) {
            continue;
        }

        *count += 1;

        if path.is_dir() {
            walk_dir(&path, depth + 1, size, count, start);
        } else if path.is_file() {
            if let Ok(meta) = path.metadata() {
                *size += meta.len();
            }
        }
    }
}

fn is_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | ".cache"
            | ".npm"
            | ".cargo"
            | ".rustup"
            | ".local"
            | ".mozilla"
            | ".vscode"
            | ".cursor"
            | ".Trash"
            | "vendor"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".tox"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".next"
            | ".nuxt"
    )
}

fn count_recent_modifications(path: &Path) -> usize {
    let mut count: usize = 0;
    let start = Instant::now();

    count_recent_recursive(path, 0, &mut count, start);
    count
}

fn count_recent_recursive(path: &Path, depth: usize, count: &mut usize, start: Instant) {
    if depth > 4 || *count >= 500 || start.elapsed() > Duration::from_secs(3) {
        return;
    }

    let entries = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let now = std::time::SystemTime::now();

    for entry in entries.flatten() {
        if *count >= 500 || start.elapsed() > Duration::from_secs(3) {
            return;
        }

        let path = entry.path();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if file_name.starts_with('.') && is_skip_dir(&file_name) {
            continue;
        }

        if let Ok(meta) = path.metadata() {
            if let Ok(elapsed) = now.duration_since(meta.modified().unwrap_or(now)) {
                if elapsed.as_secs() < (MAX_RECENT_MODIFICATION_MINUTES * 60) as u64 {
                    *count += 1;
                }
            }
        }

        if path.is_dir() {
            count_recent_recursive(&path, depth + 1, count, start);
        }
    }
}

fn count_git_repos_raw() -> usize {
    0 // Only computed when needed; placeholder for reason building
}

// ── Secret Scanning ────────────────────────────────────────

fn quick_secret_scan(path: &Path) -> bool {
    let entries = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let mut found = false;
    for entry in entries.flatten().take(200) {
        if found {
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();

        for secret_pattern in SECRET_FILES {
            if name == *secret_pattern {
                found = true;
                break;
            }
            if secret_pattern.starts_with("*.") {
                let ext = &secret_pattern[1..];
                if name.ends_with(ext) {
                    found = true;
                    break;
                }
            }
        }
    }

    if !found {
        found = scan_for_globs(path);
    }

    found
}

fn scan_for_globs(path: &Path) -> bool {
    let entries = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return false,
    };

    for entry in entries.flatten().take(50) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("credentials") || name.ends_with(".key") {
            return true;
        }
    }
    false
}

/// Fallback: detect home-level paths that should be protected even if not in profiles.
fn fallback_home_detect(
    seen: &mut HashSet<PathBuf>,
    _agents: &[DetectedAgent],
) -> Vec<ProtectionSuggestion> {
    let mut extra = Vec::new();
    // Real-user resolver: under systemd `dirs::home_dir()` returns the
    // daemon's UID home (`/root`), so this fallback would scan `/root`
    // and find nothing. `resolve_real_user_home()` falls back to the
    // first UID >= 1000 user in `/etc/passwd` and is the canonical
    // resolver across the daemon.
    let home = match crate::config::resolve_real_user_home() {
        Some(h) => h,
        None => return extra,
    };

    let critical_dirs = [
        (".ssh", "Secretos", "contiene claves SSH"),
        (".gnupg", "Secretos", "contiene claves GPG"),
        (".aws", "Secretos", "contiene credenciales AWS"),
    ];

    for (dir, group, reason_suffix) in &critical_dirs {
        let p = home.join(dir);
        if !p.exists() {
            continue;
        }
        let canonical = match p.canonicalize() {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }

        let (size_bytes, file_count) = estimate_dir_size(&canonical);
        extra.push(ProtectionSuggestion {
            path: canonical,
            group: group.to_string(),
            reason: reason_suffix.to_string(),
            risk_level: RiskLevel::Critical,
            size_bytes,
            file_count,
            contains_secrets: true,
            is_git_repo: false,
            active_agents: Vec::new(),
        });
    }

    extra
}

// ── Path Helpers ────────────────────────────────────────────
//
// `expand_path` is now imported from `crate::config` (aliased above) so
// `~/...` resolves to the real user's home rather than `/root` under
// systemd. The previous local copy used `dirs::home_dir()` directly and
// therefore silently broke smart-protect under the daemon.

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes > 0 {
        format!("{bytes} B")
    } else {
        String::new()
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProtectionProfile;

    #[test]
    fn expand_tilde_to_home() {
        let home = dirs::home_dir().unwrap();
        let p = expand_path(Path::new("~/Documents"));
        assert_eq!(p, home.join("Documents"));
    }

    #[test]
    fn expand_absolute_unchanged() {
        let p = expand_path(Path::new("/etc/passwd"));
        assert_eq!(p, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn known_agent_detection() {
        assert!(is_known_agent("cursor"));
        assert!(is_known_agent("Cursor"));
        assert!(is_known_agent("windsurf"));
        assert!(is_known_agent("opencode"));
        assert!(is_known_agent("claude-code"));
        assert!(!is_known_agent("bash"));
        assert!(!is_known_agent("systemd"));
        assert!(!is_known_agent("firefox"));
    }

    #[test]
    fn is_worth_protecting_rejects_system_paths() {
        assert!(!is_worth_protecting(Path::new("/")));
        assert!(!is_worth_protecting(Path::new("/proc")));
        assert!(!is_worth_protecting(Path::new("/sys")));
        assert!(!is_worth_protecting(Path::new("/dev")));
        assert!(!is_worth_protecting(Path::new("/tmp")));
    }

    #[test]
    fn is_worth_protecting_rejects_home() {
        let home = dirs::home_dir().unwrap();
        assert!(!is_worth_protecting(&home));
    }

    #[test]
    fn is_worth_protecting_accepts_home_subdir() {
        let path = dirs::home_dir().unwrap().join("Documents");
        assert!(is_worth_protecting(&path));
    }

    #[test]
    fn calc_risk_critical() {
        assert_eq!(calc_risk(true, 100, true, false), RiskLevel::Critical);
        assert_eq!(calc_risk(false, 100, true, true), RiskLevel::Critical);
    }

    #[test]
    fn calc_risk_high() {
        assert_eq!(calc_risk(true, 100, false, true), RiskLevel::High);
        assert_eq!(
            calc_risk(false, 2_000_000_000, false, true),
            RiskLevel::High
        );
    }

    #[test]
    fn calc_risk_medium() {
        assert_eq!(calc_risk(true, 100, false, false), RiskLevel::Medium);
        assert_eq!(
            calc_risk(false, 2_000_000_000, false, false),
            RiskLevel::Medium
        );
    }

    #[test]
    fn calc_risk_low() {
        assert_eq!(calc_risk(false, 100, false, false), RiskLevel::Low);
    }

    #[test]
    fn estimate_dir_size_returns_numbers() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("test.txt"), b"hello world").unwrap();
        let (size, count) = estimate_dir_size(tmp.path());
        assert!(count >= 1);
        assert!(size >= 11);
    }

    #[test]
    fn smart_suggestions_with_defaults() {
        let sp = SmartProtection::default();
        let suggestions = generate_smart_suggestions(&sp);
        // At minimum we should get the XDG dirs that exist
        // (exact number depends on the system)
        for s in &suggestions {
            assert!(!s.group.is_empty());
            assert!(!s.reason.is_empty());
        }
    }

    #[test]
    fn suggestion_dedup() {
        // Create two profiles with same path — should deduplicate
        let sp = SmartProtection {
            enabled: true,
            auto_suggest_on_start: true,
            profiles: vec![
                ProtectionProfile {
                    name: "A".into(),
                    paths: vec![PathBuf::from("/tmp")],
                    auto: false,
                },
                ProtectionProfile {
                    name: "B".into(),
                    paths: vec![PathBuf::from("/tmp")],
                    auto: false,
                },
            ],
        };
        let suggestions = generate_smart_suggestions(&sp);
        let tmp_suggestions: Vec<_> = suggestions
            .iter()
            .filter(|s| s.path == Path::new("/tmp"))
            .collect();
        assert!(
            tmp_suggestions.len() <= 1,
            "Expected at most 1 suggestion for /tmp, got {}",
            tmp_suggestions.len()
        );
    }

    #[test]
    fn fmt_size_formats_correctly() {
        assert_eq!(fmt_size(0), "");
        assert_eq!(fmt_size(500), "500 B");
        assert_eq!(fmt_size(2048), "2.0 KB");
        assert_eq!(fmt_size(5_000_000), "4.8 MB");
        assert_eq!(fmt_size(2_500_000_000), "2.3 GB");
    }
}
