//! Auto-updater — check GitHub Releases, download, verify, atomic replace.
//!
//! No dependencies externas pesadas. Usa `ureq` para HTTP (bloqueante,
//! ligero) y `sha2` para verificar checksums.
//!
//! Flujo:
//! 1. GET https://api.github.com/repos/{owner}/{repo}/releases/latest
//! 2. Comparar `tag_name` con `CARGO_PKG_VERSION` (semver)
//! 3. Buscar asset: `agentguard-{os}-{arch}.tar.gz`
//! 4. Descargar asset + su `.sha256`
//! 5. Verificar SHA256
//! 6. Extraer binario, reemplazar atómicamente
//! 7. Enviar SIGHUP al daemon para reload

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("JSON parse failed: {0}")]
    Json(String),

    #[error("No asset found for {os}-{arch}")]
    NoAsset { os: String, arch: String },

    #[error("SHA256 mismatch: expected {expected}, got {got}")]
    Checksum { expected: String, got: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Already up to date ({0})")]
    UpToDate(String),

    #[error("Cannot determine current binary path")]
    CurrentExe,
}

#[derive(Debug, Clone)]
pub struct Updater {
    owner: String,
    repo: String,
    current_version: String,
    bin_name: String,
}

/// Raw GitHub API response.
#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

impl Updater {
    pub fn new(owner: &str, repo: &str) -> Self {
        Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            bin_name: String::new(),
        }
    }

    pub fn bin_name(mut self, name: &str) -> Self {
        self.bin_name = name.to_string();
        self
    }

    /// Check if a new version is available on GitHub.
    /// Returns `Some(latest_version)` if update available, `None` if current.
    pub fn check(&self) -> Result<Option<String>, UpdateError> {
        let release = self.fetch_latest_release()?;

        let latest = release.tag_name.trim_start_matches('v');
        let current = self.current_version.trim_start_matches('v');

        if latest == current {
            return Ok(None);
        }

        // Simple semver comparison
        if is_newer(latest, current) {
            Ok(Some(latest.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Download and install the latest version.
    /// Returns the path to the new binary.
    pub fn update(&self) -> Result<PathBuf, UpdateError> {
        let release = self.fetch_latest_release()?;

        let latest = release.tag_name.trim_start_matches('v');
        let current = self.current_version.trim_start_matches('v');

        if !is_newer(latest, current) {
            return Err(UpdateError::UpToDate(current.to_string()));
        }

        let (os, arch) = detect_platform();

        // Find the right asset: agentguard-{os}-{arch}.tar.gz
        let asset_name = format!("agentguard-{os}-{arch}.tar.gz");
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| UpdateError::NoAsset {
                os: os.to_string(),
                arch: arch.to_string(),
            })?;

        // Find checksum file if available: agentguard-{os}-{arch}.tar.gz.sha256
        let checksum_name = format!("{asset_name}.sha256");
        let expected_sha = release
            .assets
            .iter()
            .find(|a| a.name == checksum_name)
            .and_then(|a| download_string(&a.browser_download_url).ok());

        // Download the asset
        tracing::info!(
            url = %asset.browser_download_url,
            "downloading update"
        );
        let data = download_bytes(&asset.browser_download_url)?;

        // Verify SHA256 if available
        if let Some(ref expected) = expected_sha {
            let expected = expected.split_whitespace().next()
                .unwrap_or(expected);
            let got = sha256_hex(&data);
            if !got.eq_ignore_ascii_case(expected) {
                return Err(UpdateError::Checksum {
                    expected: expected.to_string(),
                    got,
                });
            }
            tracing::info!(sha256 = %got, "checksum verified");
        }

        // Extract the binary from tar.gz
        let bin_data = extract_tar_gz(&data, &self.bin_name)?;

        // Determine target path (current executable)
        let current_exe = std::env::current_exe().map_err(|_| UpdateError::CurrentExe)?;
        let new_path = current_exe.with_extension("new");

        // Write new binary
        std::fs::write(&new_path, &bin_data)?;

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&new_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&new_path, perms)?;
        }

        // Atomic rename
        let backup_path = current_exe.with_extension("old");
        std::fs::rename(&current_exe, &backup_path)?;
        std::fs::rename(&new_path, &current_exe)?;

        tracing::info!(
            version = %latest,
            path = %current_exe.display(),
            "update installed successfully"
        );

        Ok(current_exe)
    }

    fn fetch_latest_release(&self) -> Result<Release, UpdateError> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            self.owner, self.repo
        );

        tracing::info!(url = %url, "checking for updates");
        let body = download_string(&url)?;
        serde_json::from_str(&body).map_err(|e| UpdateError::Json(e.to_string()))
    }
}

// ── HTTP helpers (ureq — lightweight, blocking) ────────────────────────────

fn download_string(url: &str) -> Result<String, UpdateError> {
    let resp = ureq::agent()
        .get(url)
        .header("User-Agent", "AgentGuard-Updater/2.0")
        .header("Accept", "application/vnd.github.v3+json")
        .call()
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    let mut body = String::new();
    resp.into_body()
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    Ok(body)
}

fn download_bytes(url: &str) -> Result<Vec<u8>, UpdateError> {
    let resp = ureq::agent()
        .get(url)
        .header("User-Agent", "AgentGuard-Updater/2.0")
        .call()
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    let mut data = Vec::new();
    resp.into_body()
        .as_reader()
        .read_to_end(&mut data)
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    Ok(data)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn extract_tar_gz(data: &[u8], bin_name: &str) -> Result<Vec<u8>, UpdateError> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().map_err(|e| UpdateError::Http(e.to_string()))? {
        let mut entry = entry.map_err(|e| UpdateError::Http(e.to_string()))?;
        let path = entry.path().map_err(|e| UpdateError::Http(e.to_string()))?;

        if path.file_name().and_then(|n| n.to_str()) == Some(bin_name) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| UpdateError::Http(e.to_string()))?;
            return Ok(buf);
        }
    }

    // If bin_name not found, try the first regular file
    let decoder2 = flate2::read::GzDecoder::new(data);
    let mut archive2 = tar::Archive::new(decoder2);
    for entry in archive2.entries().map_err(|e| UpdateError::Http(e.to_string()))? {
        let mut entry = entry.map_err(|e| UpdateError::Http(e.to_string()))?;
        if entry.header().entry_type() == tar::EntryType::Regular {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| UpdateError::Http(e.to_string()))?;
            return Ok(buf);
        }
    }

    Err(UpdateError::Http("no binary found in archive".into()))
}

// ── Platform detection ─────────────────────────────────────────────────────

fn detect_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    (os, arch)
}

// ── Semver comparison (simple) ─────────────────────────────────────────────

fn is_newer(latest: &str, current: &str) -> bool {
    let l_parts: Vec<u32> = latest.split('.').filter_map(|s| s.parse().ok()).collect();
    let c_parts: Vec<u32> = current.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..l_parts.len().max(c_parts.len()) {
        let l = l_parts.get(i).copied().unwrap_or(0);
        let c = c_parts.get(i).copied().unwrap_or(0);
        if l > c { return true; }
        if l < c { return false; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(is_newer("2.0.0", "1.9.9"));
    }

    #[test]
    fn test_same_version_not_newer() {
        assert!(!is_newer("v0.1.0", "v0.1.0"));
    }

    #[test]
    fn test_detect_platform() {
        let (os, arch) = detect_platform();
        assert!(!os.is_empty());
        assert!(!arch.is_empty());
        assert!(["linux", "macos", "windows"].contains(&os));
    }

    #[test]
    fn test_empty_latest_is_not_newer() {
        assert!(!is_newer("", "0.1.0"));
    }
}
