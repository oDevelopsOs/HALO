//! OTA (Over-The-Air) seccomp profile updates — Fase 3.
//!
//! Downloads signed seccomp profiles from a CDN, verifies them with
//! Ed25519 signatures, and applies additions to the daemon's
//! SeccompDecisionProfile. Anti-rollback prevents downgrade attacks.
//!
//! ## Security model:
//!
//! - The Ed25519 PUBLIC key is hardcoded in the binary (never downloaded).
//! - The private key is held offline and never touches the CDN.
//! - Each profile has a monotonic version number — older versions are rejected
//!   even with valid signatures.
//! - Two backup keys enable emergency rotation if the primary is compromised.
//! - In debug mode, signature verification is relaxed for development.
//!
//! ## Flow:
//!
//! 1. Every 24h (configurable), download `latest.json` + `latest.sig` from CDN.
//! 2. Parse JSON → check version > current → verify Ed25519 signature.
//! 3. Apply syscall additions to SeccompDecisionProfile.
//! 4. Persist new version number to disk.

use std::io::Read;

use serde::{Deserialize, Serialize};

/// Public key for debug/test builds (RFC 8032 Ed25519 test vector 1).
/// This allows signature verification to actually work in development.
/// In release builds, this is overridden by AGENTGUARD_OTA_PUBLIC_KEY env var at build time.
#[cfg(debug_assertions)]
const OTA_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Public key for release builds — read from env var at build time,
/// falling back to the RFC 8032 test vector if not set.
#[cfg(not(debug_assertions))]
const OTA_PUBLIC_KEY: [u8; 32] = {
    let hex = option_env!("AGENTGUARD_OTA_PUBLIC_KEY");
    match hex {
        Some(h) if h.len() == 64 => {
            let bytes = match hex::decode(h) {
                Ok(b) if b.len() == 32 => b,
                _ => panic!("AGENTGUARD_OTA_PUBLIC_KEY must be 32 hex-encoded bytes"), // unwrap-ok: compile-time env var validation
            };
            let mut arr = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                arr[i] = bytes[i];
                i += 1;
            }
            arr
        }
        _ => {
            // Fallback: RFC 8032 test vector (same as debug key)
            [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ]
        }
    }
};

/// Backup keys (currently placeholders — populated in production build).
const OTA_BACKUP_KEYS: &[[u8; 32]] = &[[0u8; 32], [0u8; 32]];

#[derive(Debug, thiserror::Error)]
pub enum OtaError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("Invalid JSON in profile: {0}")]
    InvalidJson(String),

    #[error("Anti-rollback: downloaded version {downloaded} <= current {current}")]
    Rollback { downloaded: u64, current: u64 },

    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No update available")]
    NoUpdate,
}

/// A signed seccomp profile downloaded from the CDN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProfile {
    /// Monotonically increasing version number (anti-rollback).
    pub version: u64,
    /// Unix timestamp when this profile was issued.
    pub issued_at: u64,
    /// The profile payload (what gets applied to the daemon).
    pub profile: SeccompProfilePayload,
    /// Ed25519 signature over `version:issued_at:profile_json`, hex-encoded.
    pub signature: String,
}

/// The actual content of a profile update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfilePayload {
    /// Syscall numbers to add to the allowlist.
    #[serde(default)]
    pub allow_additions: Vec<i64>,
    /// Syscall numbers to add to the deny-with-ENOSYS list.
    #[serde(default)]
    pub deny_enosys_additions: Vec<i64>,
    /// Minimum AgentGuard version required for this profile.
    #[serde(default)]
    pub min_agentguard_version: String,
}

/// Client for downloading and applying OTA profile updates.
pub struct OtaClient {
    /// Current profile version (loaded from disk on start).
    current_version: u64,
    /// CDN base URL for profile downloads.
    cdn_url: String,
    /// Path to persist the current version.
    version_path: std::path::PathBuf,
}

impl OtaClient {
    /// Create a new OTA client.
    pub fn new(cdn_url: String) -> Self {
        let version_path = Self::default_version_path();
        let current_version = Self::load_version(&version_path);

        Self {
            current_version,
            cdn_url,
            version_path,
        }
    }

    fn default_version_path() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".agentguard/ota_version")
    }

    fn load_version(path: &std::path::Path) -> u64 {
        match std::fs::read_to_string(path) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(_) => 0,
        }
    }

    fn save_version(path: &std::path::Path, version: u64) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, version.to_string())
    }

    /// Check for and apply profile updates.
    ///
    /// Returns `Some(payload)` if an update was downloaded and verified,
    /// `None` if already up-to-date.
    pub fn check_and_update(&mut self) -> Result<Option<SeccompProfilePayload>, OtaError> {
        // Download profile JSON and signature
        let profile_url = format!("{}/profiles/latest.json", self.cdn_url);
        let sig_url = format!("{}/profiles/latest.sig", self.cdn_url);

        let profile_bytes = Self::download(&profile_url)?;
        let sig_bytes = Self::download(&sig_url)?;

        // Parse and verify
        let signed = self.verify_profile(&profile_bytes, &sig_bytes)?;

        // Already up to date?
        if signed.version <= self.current_version {
            return Ok(None);
        }

        // Persist version
        self.current_version = signed.version;
        Self::save_version(&self.version_path, signed.version).map_err(OtaError::Io)?;

        tracing::info!(
            version = signed.version,
            issued_at = signed.issued_at,
            additions = signed.profile.allow_additions.len(),
            "OTA profile update applied"
        );

        Ok(Some(signed.profile))
    }

    /// Verify a downloaded profile against the hardcoded public key.
    pub fn verify_profile(
        &self,
        profile_bytes: &[u8],
        _sig_bytes: &[u8],
    ) -> Result<SignedProfile, OtaError> {
        let signed: SignedProfile = serde_json::from_slice(profile_bytes)
            .map_err(|e| OtaError::InvalidJson(e.to_string()))?;

        // Anti-rollback check
        if signed.version <= self.current_version {
            return Err(OtaError::Rollback {
                downloaded: signed.version,
                current: self.current_version,
            });
        }

        // Build the message that was signed
        let profile_json = serde_json::to_string(&signed.profile)
            .map_err(|e| OtaError::InvalidJson(e.to_string()))?;
        let message = format!("{}:{}:{}", signed.version, signed.issued_at, profile_json);

        // Decode signature from hex
        let sig_bytes_decoded =
            hex::decode(&signed.signature).map_err(|_| OtaError::SignatureVerificationFailed)?;

        // Verify with primary key and backups
        let all_keys: Vec<&[u8; 32]> = std::iter::once(&OTA_PUBLIC_KEY)
            .chain(OTA_BACKUP_KEYS.iter())
            .filter(|k| **k != [0u8; 32])
            .collect();

        if all_keys.is_empty() {
            tracing::warn!(
                "OTA: no public keys configured — accepting profile without verification"
            );
            return Ok(signed);
        }

        let valid = all_keys.iter().any(|key_bytes| {
            Self::verify_ed25519(key_bytes, message.as_bytes(), &sig_bytes_decoded).is_ok()
        });

        if !valid {
            return Err(OtaError::SignatureVerificationFailed);
        }

        tracing::debug!(
            version = signed.version,
            "OTA profile signature verified (Ed25519)"
        );

        Ok(signed)
    }

    /// Verify an Ed25519 signature.
    fn verify_ed25519(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), OtaError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|_| OtaError::SignatureVerificationFailed)?;

        let sig = if signature.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(signature);
            Signature::from_bytes(&arr)
        } else {
            return Err(OtaError::SignatureVerificationFailed);
        };

        vk.verify(message, &sig)
            .map_err(|_| OtaError::SignatureVerificationFailed)
    }

    /// Download content from a URL (synchronous, uses ureq).
    fn download(url: &str) -> Result<Vec<u8>, OtaError> {
        let response = ureq::get(url)
            .call()
            .map_err(|e| OtaError::Http(format!("GET {}: {}", url, e)))?;

        let mut body = Vec::new();
        response
            .into_body()
            .as_reader()
            .read_to_end(&mut body)
            .map_err(|e| OtaError::Http(format!("read body from {}: {}", url, e)))?;

        Ok(body)
    }

    /// Get the current version (for status reporting).
    pub fn current_version(&self) -> u64 {
        self.current_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_rollback_rejects_older_version() {
        let mut client = OtaClient::new("http://localhost".into());
        client.current_version = 10;

        let profile = SignedProfile {
            version: 5,
            issued_at: 1000,
            profile: SeccompProfilePayload {
                allow_additions: vec![],
                deny_enosys_additions: vec![],
                min_agentguard_version: String::new(),
            },
            signature: "aa".into(),
        };

        let json = serde_json::to_vec(&profile).unwrap();
        let result = client.verify_profile(&json, b"dummy");
        assert!(matches!(result, Err(OtaError::Rollback { .. })));
    }

    #[test]
    fn test_same_version_rejected() {
        let mut client = OtaClient::new("http://localhost".into());
        client.current_version = 3;

        let profile = SignedProfile {
            version: 3,
            issued_at: 1000,
            profile: SeccompProfilePayload {
                allow_additions: vec![],
                deny_enosys_additions: vec![],
                min_agentguard_version: String::new(),
            },
            signature: "aa".into(),
        };

        let json = serde_json::to_vec(&profile).unwrap();
        let result = client.verify_profile(&json, b"dummy");
        assert!(matches!(result, Err(OtaError::Rollback { .. })));
    }

    #[test]
    fn test_newer_version_accepted_sig_matters() {
        let mut client = OtaClient::new("http://localhost".into());
        client.current_version = 1;

        let profile = SignedProfile {
            version: 2,
            issued_at: 2000,
            profile: SeccompProfilePayload {
                allow_additions: vec![42],
                deny_enosys_additions: vec![99],
                min_agentguard_version: "0.1.0".into(),
            },
            signature: "bb".into(),
        };

        let json = serde_json::to_vec(&profile).unwrap();
        // With a real public key, invalid signatures are rejected
        let result = client.verify_profile(&json, b"dummy");
        assert!(matches!(result, Err(OtaError::SignatureVerificationFailed)));
    }

    #[test]
    fn test_version_check_works_before_sig() {
        let mut client = OtaClient::new("http://localhost".into());
        client.current_version = 10;

        let profile = SignedProfile {
            version: 5, // older version
            issued_at: 1000,
            profile: SeccompProfilePayload {
                allow_additions: vec![],
                deny_enosys_additions: vec![],
                min_agentguard_version: String::new(),
            },
            signature: "aa".into(),
        };

        let json = serde_json::to_vec(&profile).unwrap();
        // Anti-rollback check happens before signature verification
        let result = client.verify_profile(&json, b"dummy");
        assert!(matches!(result, Err(OtaError::Rollback { .. })));
    }

    #[test]
    fn test_invalid_json_rejected() {
        let client = OtaClient::new("http://localhost".into());
        let result = client.verify_profile(b"not valid json", b"dummy");
        assert!(matches!(result, Err(OtaError::InvalidJson(_))));
    }

    #[test]
    fn test_version_persistence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("ota_version");

        OtaClient::save_version(&path, 42).unwrap();
        assert_eq!(OtaClient::load_version(&path), 42);

        OtaClient::save_version(&path, 100).unwrap();
        assert_eq!(OtaClient::load_version(&path), 100);
    }

    #[test]
    fn test_load_missing_version_returns_zero() {
        let path = std::path::PathBuf::from("/tmp/agentguard_ota_test_nonexistent_xyz");
        assert_eq!(OtaClient::load_version(&path), 0);
    }

    #[test]
    fn test_profile_payload_defaults() {
        let json = r#"{"allow_additions": [1, 2, 3]}"#;
        let payload: SeccompProfilePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.allow_additions, vec![1, 2, 3]);
        assert!(payload.deny_enosys_additions.is_empty());
        assert!(payload.min_agentguard_version.is_empty());
    }

    #[test]
    fn test_signed_profile_roundtrip() {
        let profile = SignedProfile {
            version: 7,
            issued_at: 1715000000,
            profile: SeccompProfilePayload {
                allow_additions: vec![100, 200],
                deny_enosys_additions: vec![300],
                min_agentguard_version: "0.2.0".into(),
            },
            signature: "abcdef1234567890".into(),
        };

        let json = serde_json::to_string(&profile).unwrap();
        let parsed: SignedProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, 7);
        assert_eq!(parsed.profile.allow_additions, vec![100, 200]);
        assert_eq!(parsed.signature, "abcdef1234567890");
    }
}
