//! Configuration passed to the agentguard-shim binary via environment variables.
//!
//! The shim is a minimal static binary that reads Landlock and seccomp config
//! from environment variables. This module generates those variables from the
//! daemon's Config struct.

use std::path::{Path, PathBuf};

/// Configuration for the AgentGuard shim, serialized as env vars.
#[derive(Debug, Clone)]
pub struct ShimConfig {
    /// Whether Landlock should be applied by the shim.
    pub landlock_enabled: bool,
    /// Directories with read/write access (colon-separated for env var).
    pub write_dirs: Vec<PathBuf>,
    /// Directories with read-only access (colon-separated for env var).
    pub read_dirs: Vec<PathBuf>,
    /// Whether seccomp allowlist should be applied.
    pub seccomp_enabled: bool,
}

impl ShimConfig {
    /// Create config for an agent running in a specific project directory.
    ///
    /// Sets up:
    /// - Write access to the project directory (cross-mounted as workspace)
    /// - Read access to system directories needed for agent execution
    pub fn for_agent(project_dir: &Path, enable_landlock: bool, enable_seccomp: bool) -> Self {
        let mut write_dirs = Vec::new();
        let mut read_dirs = Vec::new();

        if enable_landlock {
            // Write-accessible: only the project directory
            write_dirs.push(project_dir.to_path_buf());

            // Read-only: system directories needed by agents
            let ro_dirs = &[
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/etc/ssl",
                "/etc/pki",
                "/etc/ca-certificates",
                "/opt",
            ];

            for dir in ro_dirs {
                let p = PathBuf::from(dir);
                if p.exists() {
                    read_dirs.push(p);
                }
            }

            // Add runtime cache directories (read-only for safety)
            if let Some(home) = dirs::home_dir() {
                let cache_dirs = &[".npm", ".cache", ".cargo/registry", ".rustup"];
                for cd in cache_dirs {
                    let p = home.join(cd);
                    if p.exists() {
                        read_dirs.push(p);
                    }
                }
            }
        }

        Self {
            landlock_enabled: enable_landlock,
            write_dirs,
            read_dirs,
            seccomp_enabled: enable_seccomp,
        }
    }

    /// Generate environment variables to pass to the shim.
    ///
    /// Returns a list of (key, value) pairs to set as environment variables
    /// before executing the shim.
    pub fn to_env_vars(&self) -> Vec<(String, String)> {
        let mut vars = Vec::new();

        if self.landlock_enabled {
            vars.push(("AGENTGUARD_LANDLOCK".to_string(), "1".to_string()));

            if !self.write_dirs.is_empty() {
                let rw = self
                    .write_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":");
                vars.push(("AGENTGUARD_LANDLOCK_RW".to_string(), rw));
            }

            if !self.read_dirs.is_empty() {
                let ro = self
                    .read_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":");
                vars.push(("AGENTGUARD_LANDLOCK_RO".to_string(), ro));
            }
        }

        if self.seccomp_enabled {
            vars.push(("AGENTGUARD_SECCOMP".to_string(), "1".to_string()));
        }

        vars
    }

    /// Apply the config as environment variables in the current process.
    /// Used when the daemon wants to apply Landlock to itself or a child.
    pub fn apply_env(&self) {
        if self.landlock_enabled {
            std::env::set_var("AGENTGUARD_LANDLOCK", "1");
            if !self.write_dirs.is_empty() {
                let rw = self
                    .write_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":");
                std::env::set_var("AGENTGUARD_LANDLOCK_RW", rw);
            }
            if !self.read_dirs.is_empty() {
                let ro = self
                    .read_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":");
                std::env::set_var("AGENTGUARD_LANDLOCK_RO", ro);
            }
        }
        if self.seccomp_enabled {
            std::env::set_var("AGENTGUARD_SECCOMP", "1");
        }
    }

    /// Remove the environment variables from the current process.
    pub fn clear_env(&self) {
        std::env::remove_var("AGENTGUARD_LANDLOCK");
        std::env::remove_var("AGENTGUARD_LANDLOCK_RW");
        std::env::remove_var("AGENTGUARD_LANDLOCK_RO");
        std::env::remove_var("AGENTGUARD_SECCOMP");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_config_empty() {
        let config = ShimConfig {
            landlock_enabled: false,
            write_dirs: vec![],
            read_dirs: vec![],
            seccomp_enabled: false,
        };

        let vars = config.to_env_vars();
        assert!(vars.is_empty());
    }

    #[test]
    fn test_shim_config_landlock_only() {
        let config = ShimConfig {
            landlock_enabled: true,
            write_dirs: vec![PathBuf::from("/tmp/workspace")],
            read_dirs: vec![PathBuf::from("/usr")],
            seccomp_enabled: false,
        };

        let vars = config.to_env_vars();
        assert!(vars
            .iter()
            .any(|(k, v)| k == "AGENTGUARD_LANDLOCK" && v == "1"));
        assert!(vars
            .iter()
            .any(|(k, v)| k == "AGENTGUARD_LANDLOCK_RW" && v == "/tmp/workspace"));
        assert!(vars
            .iter()
            .any(|(k, v)| k == "AGENTGUARD_LANDLOCK_RO" && v == "/usr"));
        assert!(!vars.iter().any(|(k, _)| k == "AGENTGUARD_SECCOMP"));
    }

    #[test]
    fn test_shim_config_seccomp() {
        let config = ShimConfig {
            landlock_enabled: false,
            write_dirs: vec![],
            read_dirs: vec![],
            seccomp_enabled: true,
        };

        let vars = config.to_env_vars();
        assert_eq!(vars.len(), 1);
        assert!(vars
            .iter()
            .any(|(k, v)| k == "AGENTGUARD_SECCOMP" && v == "1"));
    }

    #[test]
    fn test_shim_config_for_agent() {
        let config = ShimConfig::for_agent(Path::new("/tmp/project"), true, true);
        assert!(config.landlock_enabled);
        assert!(config.seccomp_enabled);
        assert!(config
            .write_dirs
            .iter()
            .any(|p| p == Path::new("/tmp/project")));
    }

    #[test]
    fn test_shim_config_apply_and_clear_env() {
        let config = ShimConfig {
            landlock_enabled: true,
            write_dirs: vec![PathBuf::from("/tmp/w")],
            read_dirs: vec![],
            seccomp_enabled: false,
        };

        config.apply_env();
        assert_eq!(std::env::var("AGENTGUARD_LANDLOCK").unwrap(), "1");
        assert_eq!(std::env::var("AGENTGUARD_LANDLOCK_RW").unwrap(), "/tmp/w");

        config.clear_env();
        assert!(std::env::var("AGENTGUARD_LANDLOCK").is_err());
        assert!(std::env::var("AGENTGUARD_LANDLOCK_RW").is_err());
    }
}
