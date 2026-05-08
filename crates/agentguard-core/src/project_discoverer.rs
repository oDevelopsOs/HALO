//! ProjectDiscoverer — detección de workspaces de agentes IA (v2.2).
//!
//! Recorre los CWDs de agentes detectados y el filesystem en busca de raíces
//! de proyectos (Git, lenguajes de programación, etc.). Calcula un score de
//! sensibilidad (0-100) para decidir si merece protección automática.
//!
//! Política: INFO-ONLY. No modifica la configuración ni añade rutas protegidas.
//! Los resultados se exponen vía IPC para que el usuario/CLI decida.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const KNOWN_PROJECT_FILES: &[(&str, &str)] = &[
    ("Cargo.toml", "Rust"),
    ("package.json", "Node"),
    ("tsconfig.json", "TypeScript"),
    ("pyproject.toml", "Python"),
    ("setup.py", "Python"),
    ("requirements.txt", "Python"),
    ("go.mod", "Go"),
    ("pom.xml", "Java"),
    ("build.gradle", "Java"),
    ("Gemfile", "Ruby"),
    ("CMakeLists.txt", "C/C++"),
    ("Makefile", "C/C++"),
    ("composer.json", "PHP"),
    ("mix.exs", "Elixir"),
];

const HIGH_SENSITIVITY_INDICATORS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
    "id_rsa",
    "id_ed25519",
    "*.pem",
    ".npmrc",
    ".pypirc",
];

#[derive(Debug, Clone)]
pub struct ProjectContext {
    pub path: PathBuf,
    pub project_type: ProjectType,
    pub git_remote: Option<String>,
    pub sensitivity_score: u8,
    pub last_activity: Option<SystemTime>,
}

impl ProjectContext {
    pub fn display_type(&self) -> &str {
        self.project_type.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectType {
    Rust,
    Python,
    Node,
    Go,
    Java,
    Ruby,
    CCpp,
    Php,
    Elixir,
    Unknown,
}

impl ProjectType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rust => "Rust",
            Self::Python => "Python",
            Self::Node => "Node",
            Self::Go => "Go",
            Self::Java => "Java",
            Self::Ruby => "Ruby",
            Self::CCpp => "C/C++",
            Self::Php => "PHP",
            Self::Elixir => "Elixir",
            Self::Unknown => "Unknown",
        }
    }
}

pub struct ProjectDiscoverer;

impl ProjectDiscoverer {
    /// Descubre proyectos a partir de los CWDs de agentes detectados.
    /// Deduplica por raíz Git.
    pub fn discover(cwd_hints: &[PathBuf]) -> Vec<ProjectContext> {
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut projects = Vec::new();

        for cwd in cwd_hints {
            if let Some(root) = find_git_root(cwd) {
                let canonical = std::fs::canonicalize(&root).unwrap_or(root);
                if seen.insert(canonical.clone()) {
                    projects.push(analyze_project(&canonical));
                }
            } else if looks_like_project(cwd) && seen.insert(cwd.clone()) {
                projects.push(analyze_project(cwd));
            }
        }

        projects.sort_by_key(|p| -(p.sensitivity_score as i32));
        projects
    }

    /// Calcula el score de sensibilidad de un directorio (0-100).
    pub fn sensitivity_score(path: &Path) -> u8 {
        let mut score: u8 = 0;

        if !path.is_dir() {
            return 0;
        }

        let entries = match std::fs::read_dir(path) {
            Ok(r) => r.filter_map(|e| e.ok()).collect::<Vec<_>>(),
            Err(_) => return 0,
        };

        for entry in &entries {
            let fname = entry.file_name();
            let name = fname.to_string_lossy();

            if name == ".git" && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                score = score.saturating_add(25);
            }

            for (file, _) in KNOWN_PROJECT_FILES {
                if name == *file {
                    score = score.saturating_add(10);
                    break;
                }
            }

            for indicator in HIGH_SENSITIVITY_INDICATORS {
                let matches = if indicator.starts_with("*.") {
                    let ext = &indicator[1..];
                    name.ends_with(ext)
                } else {
                    name == *indicator
                };
                if matches {
                    score = score.saturating_add(15);
                    break;
                }
            }
        }

        score.min(100)
    }
}

fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };

    loop {
        if current.join(".git").is_dir() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

fn looks_like_project(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }

    let entries = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return false,
    };

    let mut project_file_count = 0u32;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if KNOWN_PROJECT_FILES.iter().any(|(f, _)| *f == name) {
            project_file_count += 1;
        }
    }

    project_file_count >= 1
}

fn analyze_project(path: &Path) -> ProjectContext {
    let project_type = detect_project_type(path);
    let git_remote = read_git_remote(path);
    let sensitivity = ProjectDiscoverer::sensitivity_score(path);
    let last_activity = last_modified_in_dir(path);

    ProjectContext {
        path: path.to_path_buf(),
        project_type,
        git_remote,
        sensitivity_score: sensitivity,
        last_activity,
    }
}

fn detect_project_type(path: &Path) -> ProjectType {
    let entries = match std::fs::read_dir(path) {
        Ok(r) => r.filter_map(|e| e.ok()).collect::<Vec<_>>(),
        Err(_) => return ProjectType::Unknown,
    };

    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        for (file, ptype) in KNOWN_PROJECT_FILES {
            if name == *file {
                return match *ptype {
                    "Rust" => ProjectType::Rust,
                    "Python" => ProjectType::Python,
                    "Node" | "TypeScript" => ProjectType::Node,
                    "Go" => ProjectType::Go,
                    "Java" => ProjectType::Java,
                    "Ruby" => ProjectType::Ruby,
                    "C/C++" => ProjectType::CCpp,
                    "PHP" => ProjectType::Php,
                    "Elixir" => ProjectType::Elixir,
                    _ => ProjectType::Unknown,
                };
            }
        }
    }

    ProjectType::Unknown
}

fn read_git_remote(path: &Path) -> Option<String> {
    let git_config = path.join(".git").join("config");
    let content = std::fs::read_to_string(git_config).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(url) = trimmed.strip_prefix("url = ") {
            return Some(url.to_string());
        }
    }
    None
}

fn last_modified_in_dir(path: &Path) -> Option<SystemTime> {
    let mut latest: Option<SystemTime> = None;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.filter_map(|e| e.ok()) {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    latest = Some(match latest {
                        Some(l) if mtime > l => mtime,
                        Some(l) => l,
                        None => mtime,
                    });
                }
            }
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitivity_zero_for_non_existent() {
        let s = ProjectDiscoverer::sensitivity_score(Path::new("/tmp/nonexistent_xyz_123"));
        assert_eq!(s, 0);
    }

    #[test]
    fn sensitivity_nonzero_for_temp_dir_with_env() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join(".env"), "SECRET=123").expect("write");
        let s = ProjectDiscoverer::sensitivity_score(tmp.path());
        assert!(s >= 15, "expected at least 15, got {s}");
    }

    #[test]
    fn sensitivity_max_100() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        for i in 0..10 {
            std::fs::write(tmp.path().join(format!(".env.{i}")), "x").ok();
        }
        let s = ProjectDiscoverer::sensitivity_score(tmp.path());
        assert!(s <= 100, "score {s} exceeds 100");
    }

    #[test]
    fn detect_rust_project() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]").expect("write");
        let t = detect_project_type(tmp.path());
        assert_eq!(t, ProjectType::Rust);
    }

    #[test]
    fn detect_node_project() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), "{}").expect("write");
        let t = detect_project_type(tmp.path());
        assert_eq!(t, ProjectType::Node);
    }

    #[test]
    fn discover_from_hints_finds_git_roots() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let git_dir = tmp.path().join("my_project");
        std::fs::create_dir_all(git_dir.join(".git")).expect("mkdir");
        std::fs::write(git_dir.join("Cargo.toml"), "[package]").expect("write");

        let projects = ProjectDiscoverer::discover(&[git_dir.join("src").join("main.rs")]);
        assert!(!projects.is_empty());
        assert_eq!(projects[0].project_type, ProjectType::Rust);
    }

    #[test]
    fn discover_deduplicates_git_roots() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let git_dir = tmp.path().join("repo");
        std::fs::create_dir_all(git_dir.join(".git")).expect("mkdir");
        std::fs::create_dir_all(git_dir.join("src")).expect("mkdir");
        std::fs::create_dir_all(git_dir.join("tests")).expect("mkdir");

        let projects = ProjectDiscoverer::discover(&[
            git_dir.join("src"),
            git_dir.join("tests"),
            git_dir.join("src").join("lib.rs"),
        ]);
        assert_eq!(projects.len(), 1);
    }

    #[test]
    fn find_git_root_bubbles_up() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("repo").join("src")).expect("create");
        std::fs::create_dir(tmp.path().join("repo").join(".git")).expect("create");

        let root = find_git_root(&tmp.path().join("repo").join("src").join("main.rs"));
        assert!(root.is_some());
        assert_eq!(root.unwrap(), tmp.path().join("repo"));
    }

    #[test]
    fn looks_like_project_detects_known_files() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "").expect("write");
        assert!(looks_like_project(tmp.path()));
    }

    #[test]
    fn looks_like_project_rejects_empty_dir() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        assert!(!looks_like_project(tmp.path()));
    }

    #[test]
    fn project_type_display() {
        assert_eq!(ProjectType::Rust.as_str(), "Rust");
        assert_eq!(ProjectType::Unknown.as_str(), "Unknown");
    }
}
