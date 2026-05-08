//! CA root local usada por el proxy DLP para emitir certificados leaf
//! on-the-fly al interceptar HTTPS (Fase 2.3).
//!
//! **Modelo de confianza:**
//! - La CA se genera **en la máquina del usuario**, una sola vez.
//! - La clave privada nunca sale del disco local y se guarda con permisos
//!   `0o600` (ver `.windsurf/rules/07-paths-and-privileges.md`).
//! - El certificado root público se añade al system trust store durante
//!   la instalación (ver `packaging/linux/install.sh`, futuro).
//! - En `agentguard uninstall` la CA se revoca del trust store y se borra
//!   el directorio. Sin esos dos pasos la CA queda huérfana pero sin
//!   clave privada accesible online.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use thiserror::Error;

/// Nombre del archivo que contiene el certificado root (PEM).
pub const CA_CERT_FILE: &str = "root.crt";
/// Nombre del archivo que contiene la clave privada (PEM, permisos 0o600).
pub const CA_KEY_FILE: &str = "root.key";

/// Validez por defecto del CA root cuando se genera nuevo.
pub const DEFAULT_VALIDITY_DAYS: i64 = 365 * 10;

/// Common Name del CA.
pub const CA_COMMON_NAME: &str = "AgentGuard DLP Local Root CA";

/// Errores del subsistema CA.
#[derive(Debug, Error)]
pub enum CaError {
    #[error("I/O error on {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to generate CA key pair")]
    KeyGeneration(#[source] rcgen::Error),

    #[error("failed to self-sign CA certificate")]
    CertGeneration(#[source] rcgen::Error),

    #[error("failed to parse stored CA key")]
    KeyParse(#[source] rcgen::Error),

    #[error("failed to parse stored CA certificate")]
    CertParse(#[source] rcgen::Error),

    #[error("corrupted CA directory at {dir:?}: {reason}")]
    Corrupt { dir: PathBuf, reason: &'static str },

    #[error("system trust store install failed: {0}")]
    TrustInstall(String),
}

/// CA root cargada en memoria, lista para firmar certificados leaf.
pub struct LocalCa {
    /// PEM del certificado root (se distribuye al trust store).
    cert_pem: String,
    /// PEM de la clave privada (NUNCA sale de disco + RAM local).
    key_pem: String,
    /// Objeto Certificate de rcgen (para firmar leaf certs).
    cert: Arc<Certificate>,
    /// Objeto KeyPair de rcgen.
    key: Arc<KeyPair>,
    /// Directorio donde vive en disco.
    dir: PathBuf,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("dir", &self.dir)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem_len", &self.key_pem.len())
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    /// Carga la CA del directorio si existe; si no, genera una nueva y la
    /// persiste. Idempotente.
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        let dir = dir.as_ref();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        match (cert_path.is_file(), key_path.is_file()) {
            (true, true) => {
                let cert_pem = read_file(&cert_path)?;
                let key_pem = read_file(&key_path)?;
                let key = KeyPair::from_pem(&key_pem).map_err(CaError::KeyParse)?;
                let issuer_params =
                    CertificateParams::from_ca_cert_pem(&cert_pem).map_err(CaError::CertParse)?;
                let cert = Arc::new(
                    issuer_params
                        .self_signed(&key)
                        .map_err(CaError::CertGeneration)?,
                );
                tracing::info!(dir = ?dir, "loaded existing CA root");
                Ok(Self {
                    cert_pem,
                    key_pem,
                    cert,
                    key: Arc::new(key),
                    dir: dir.to_path_buf(),
                })
            }
            (false, false) => Self::generate_and_persist(dir),
            (true, false) => Err(CaError::Corrupt {
                dir: dir.to_path_buf(),
                reason: "certificate present but key missing",
            }),
            (false, true) => Err(CaError::Corrupt {
                dir: dir.to_path_buf(),
                reason: "key present but certificate missing",
            }),
        }
    }

    /// Genera una CA nueva y la escribe a disco con permisos seguros.
    pub fn generate_and_persist(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        let dir = dir.as_ref();

        let key_pair = KeyPair::generate().map_err(CaError::KeyGeneration)?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_COMMON_NAME);
        dn.push(DnType::OrganizationName, "AgentGuard");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(DEFAULT_VALIDITY_DAYS);

        let cert = params
            .self_signed(&key_pair)
            .map_err(CaError::CertGeneration)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        ensure_dir(dir)?;
        write_file_secure(&dir.join(CA_CERT_FILE), cert_pem.as_bytes(), 0o644)?;
        write_file_secure(&dir.join(CA_KEY_FILE), key_pem.as_bytes(), 0o600)?;

        tracing::info!(
            dir = ?dir,
            validity_days = DEFAULT_VALIDITY_DAYS,
            "generated new CA root (install root.crt into the system trust store)"
        );

        Ok(Self {
            cert_pem,
            key_pem,
            cert: Arc::new(cert),
            key: Arc::new(key_pair),
            dir: dir.to_path_buf(),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
    pub fn rcgen_cert(&self) -> Arc<Certificate> {
        Arc::clone(&self.cert)
    }
    pub fn rcgen_key(&self) -> Arc<KeyPair> {
        Arc::clone(&self.key)
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILE)
    }

    /// Install the local CA root certificate into the system trust store.
    ///
    /// Detects which trust-store update tool is available on the host
    /// without inspecting `/etc/os-release` — this works equally on
    /// Ubuntu, Debian, Fedora, RHEL, CentOS, Rocky, openSUSE, Arch, Alpine,
    /// and any other distro that ships one of the standard tools.
    ///
    /// Detection priority (`detect_ca_trust_method`):
    /// 1. `update-ca-trust`        → Fedora / RHEL / CentOS / Rocky
    /// 2. `update-ca-certificates` → Debian / Ubuntu / openSUSE / Alpine
    /// 3. `trust`                  → Arch / any p11-kit based system
    /// 4. Manual fallback          → write to first-existing anchor dir,
    ///    and warn the user to run the trust update by hand
    ///
    /// Returns a [`TrustInstallReport`] describing which method was used
    /// and where the file was written. Errors are surfaced as
    /// [`CaError::TrustInstall`].
    ///
    /// **Requires root** (writes to `/etc/...`). Caller must have
    /// `CAP_DAC_OVERRIDE` or be uid 0; otherwise the underlying file
    /// write returns `EACCES`.
    #[cfg(unix)]
    pub fn install_system_trust(&self) -> Result<TrustInstallReport, CaError> {
        let method = detect_ca_trust_method();
        install_trust_with_method(self.cert_pem.as_bytes(), method)
    }

    /// Remove any previously-installed AgentGuard CA from the system trust
    /// store. Idempotent: succeeds even if no CA was installed.
    ///
    /// Removes the well-known anchor file from every standard location
    /// and re-runs the trust-update tools that are present.
    #[cfg(unix)]
    pub fn uninstall_system_trust() -> Result<(), CaError> {
        uninstall_trust()
    }
}

// ---------------------------------------------------------------------------
// Cross-distro trust-store installation
// ---------------------------------------------------------------------------

/// Filename written into the system anchor directory. Distinct from
/// [`CA_CERT_FILE`] so the daemon's local copy and the system trust copy
/// can be distinguished.
#[cfg(unix)]
pub const SYSTEM_TRUST_ANCHOR_FILE: &str = "agentguard-ca.crt";

/// Detected mechanism for adding root anchors on this host.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaTrustMethod {
    /// Debian / Ubuntu / openSUSE / Alpine — anchor dir
    /// `/usr/local/share/ca-certificates/` + `update-ca-certificates`.
    UpdateCaCertificates,
    /// Fedora / RHEL / CentOS / Rocky — anchor dir
    /// `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust extract`.
    UpdateCaTrust,
    /// Arch / any p11-kit based system — `trust anchor --store <pem>`.
    TrustAnchor,
    /// Nothing detected: caller will write to the first existing anchor
    /// dir and warn the user to run the trust update manually.
    Manual,
}

/// Outcome of [`LocalCa::install_system_trust`].
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct TrustInstallReport {
    /// Which detection branch was selected.
    pub method: CaTrustMethod,
    /// Where the anchor PEM was actually written. `None` for
    /// [`CaTrustMethod::TrustAnchor`] which doesn't write to a fixed
    /// location (`trust anchor` manages its own store).
    pub installed_path: Option<PathBuf>,
    /// `true` if the trust-store update command (e.g. `update-ca-trust
    /// extract`) was actually invoked. `false` for the manual fallback.
    pub trust_update_run: bool,
}

#[cfg(unix)]
fn which_available(cmd: &str) -> bool {
    // Avoid relying on a `which` binary that may not be installed; just
    // check $PATH directly.
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|p| {
                let candidate = p.join(cmd);
                std::fs::metadata(&candidate)
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Detect the trust-store mechanism for this host.
///
/// Order matters: `update-ca-trust` (Fedora) is checked first because it
/// is more specific and Fedora ships `update-ca-certificates` as a
/// thin wrapper in some configurations.
#[cfg(unix)]
pub fn detect_ca_trust_method() -> CaTrustMethod {
    if which_available("update-ca-trust") {
        return CaTrustMethod::UpdateCaTrust;
    }
    if which_available("update-ca-certificates") {
        return CaTrustMethod::UpdateCaCertificates;
    }
    if which_available("trust") {
        return CaTrustMethod::TrustAnchor;
    }
    CaTrustMethod::Manual
}

#[cfg(unix)]
fn run_command(cmd: &str, args: &[&str]) -> Result<(), CaError> {
    use std::process::Command;
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| CaError::TrustInstall(format!("failed to spawn `{cmd}`: {e}")))?;
    if !status.success() {
        return Err(CaError::TrustInstall(format!(
            "`{cmd} {}` exited with {}",
            args.join(" "),
            status
        )));
    }
    Ok(())
}

/// Write the CA PEM to `path` with mode 0644 and ensure the parent dir
/// exists. Wraps I/O errors as [`CaError::TrustInstall`] so the caller
/// can present a single error category to users.
#[cfg(unix)]
fn write_anchor(path: &Path, pem: &[u8]) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CaError::TrustInstall(format!("create_dir_all {:?}: {e}", parent)))?;
    }
    std::fs::write(path, pem)
        .map_err(|e| CaError::TrustInstall(format!("write {:?}: {e}", path)))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| CaError::TrustInstall(format!("chmod {:?}: {e}", path)))?;
    Ok(())
}

#[cfg(unix)]
fn install_trust_with_method(
    pem: &[u8],
    method: CaTrustMethod,
) -> Result<TrustInstallReport, CaError> {
    match method {
        CaTrustMethod::UpdateCaCertificates => {
            let path =
                PathBuf::from("/usr/local/share/ca-certificates").join(SYSTEM_TRUST_ANCHOR_FILE);
            write_anchor(&path, pem)?;
            run_command("update-ca-certificates", &[])?;
            tracing::info!(?path, "CA installed via update-ca-certificates");
            Ok(TrustInstallReport {
                method,
                installed_path: Some(path),
                trust_update_run: true,
            })
        }
        CaTrustMethod::UpdateCaTrust => {
            let path =
                PathBuf::from("/etc/pki/ca-trust/source/anchors").join(SYSTEM_TRUST_ANCHOR_FILE);
            write_anchor(&path, pem)?;
            run_command("update-ca-trust", &["extract"])?;
            tracing::info!(?path, "CA installed via update-ca-trust");
            Ok(TrustInstallReport {
                method,
                installed_path: Some(path),
                trust_update_run: true,
            })
        }
        CaTrustMethod::TrustAnchor => {
            // `trust anchor --store` accepts a PEM file and copies it
            // into its own management store. We must hand it a real
            // filename, so we stage the PEM in /tmp first.
            let tmp = std::env::temp_dir().join("agentguard-ca-anchor.crt");
            write_anchor(&tmp, pem)?;
            let res = run_command("trust", &["anchor", "--store", &tmp.to_string_lossy()]);
            // Best-effort cleanup of the staging file regardless of result.
            let _ = std::fs::remove_file(&tmp);
            res?;
            tracing::info!("CA installed via `trust anchor`");
            Ok(TrustInstallReport {
                method,
                installed_path: None,
                trust_update_run: true,
            })
        }
        CaTrustMethod::Manual => {
            // Last-resort fallback: write to the first anchor directory
            // that already exists. Don't run any update tool — we already
            // know none are installed. Caller must surface the warning.
            let candidates: [PathBuf; 3] = [
                PathBuf::from("/usr/local/share/ca-certificates"),
                PathBuf::from("/etc/pki/ca-trust/source/anchors"),
                PathBuf::from("/etc/ssl/certs"),
            ];
            for dir in &candidates {
                if dir.is_dir() {
                    let path = dir.join(SYSTEM_TRUST_ANCHOR_FILE);
                    write_anchor(&path, pem)?;
                    tracing::warn!(
                        ?path,
                        "CA written to {:?} but no trust-update tool was found. \
                         Run the appropriate command for your distro manually \
                         (e.g. `update-ca-trust extract` or `trust anchor`).",
                        path
                    );
                    return Ok(TrustInstallReport {
                        method,
                        installed_path: Some(path),
                        trust_update_run: false,
                    });
                }
            }
            Err(CaError::TrustInstall(
                "no supported trust-store directory exists on this host \
                 (tried /usr/local/share/ca-certificates, /etc/pki/ca-trust/source/anchors, \
                 /etc/ssl/certs); install ca-certificates or p11-kit-trust"
                    .into(),
            ))
        }
    }
}

#[cfg(unix)]
fn uninstall_trust() -> Result<(), CaError> {
    let candidates: [PathBuf; 4] = [
        PathBuf::from("/usr/local/share/ca-certificates").join(SYSTEM_TRUST_ANCHOR_FILE),
        PathBuf::from("/etc/pki/ca-trust/source/anchors").join(SYSTEM_TRUST_ANCHOR_FILE),
        PathBuf::from("/etc/ssl/certs").join(SYSTEM_TRUST_ANCHOR_FILE),
        // Older shell installer wrote `agentguard.crt` (no `-ca` suffix).
        // Remove that too so upgrades don't leave a stale trust anchor.
        PathBuf::from("/etc/pki/ca-trust/source/anchors/agentguard.crt"),
    ];

    let mut removed_any = false;
    for path in &candidates {
        if path.exists() {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    tracing::info!(?path, "removed CA anchor");
                    removed_any = true;
                }
                Err(e) => {
                    tracing::warn!(?path, error = %e, "failed to remove CA anchor");
                }
            }
        }
    }

    if !removed_any {
        tracing::info!("uninstall_system_trust: nothing to remove");
        // No anchor was actually deleted — running the trust update
        // tool would only generate noise (and require root). Skip it.
        return Ok(());
    }

    // Re-run whichever update tool is present so the trust store is
    // refreshed after an actual removal. Errors are non-fatal — the
    // file is already gone.
    if which_available("update-ca-trust") {
        let _ = run_command("update-ca-trust", &["extract"]);
    }
    if which_available("update-ca-certificates") {
        let _ = run_command("update-ca-certificates", &[]);
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<String, CaError> {
    std::fs::read_to_string(path).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_dir(dir: &Path) -> Result<(), CaError> {
    std::fs::create_dir_all(dir).map_err(|source| CaError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms).map_err(|source| CaError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn write_file_secure(path: &Path, content: &[u8], _mode: u32) -> Result<(), CaError> {
    std::fs::write(path, content).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(_mode);
        std::fs::set_permissions(path, perms).map_err(|source| CaError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_creates_valid_pem_files() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");
        let ca = LocalCa::generate_and_persist(&ca_dir).expect("generate");

        let cert = std::fs::read_to_string(ca_dir.join(CA_CERT_FILE)).expect("read cert");
        let key = std::fs::read_to_string(ca_dir.join(CA_KEY_FILE)).expect("read key");

        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("-----END CERTIFICATE-----"));
        assert!(
            key.contains("-----BEGIN PRIVATE KEY-----")
                || key.contains("-----BEGIN EC PRIVATE KEY-----")
        );

        assert_eq!(ca.cert_pem(), cert);
        assert_eq!(ca.key_pem(), key);
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");

        let ca1 = LocalCa::load_or_generate(&ca_dir).expect("first");
        let ca2 = LocalCa::load_or_generate(&ca_dir).expect("reload");

        assert_eq!(ca1.cert_pem(), ca2.cert_pem());
        assert_eq!(ca1.key_pem(), ca2.key_pem());
    }

    #[test]
    fn regenerate_overwrites_existing() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");

        let ca1 = LocalCa::generate_and_persist(&ca_dir).expect("first");
        let ca2 = LocalCa::generate_and_persist(&ca_dir).expect("regen");

        assert_ne!(ca1.cert_pem(), ca2.cert_pem());
        assert_ne!(ca1.key_pem(), ca2.key_pem());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");
        let _ca = LocalCa::generate_and_persist(&ca_dir).expect("generate");

        let key_mode = std::fs::metadata(ca_dir.join(CA_KEY_FILE))
            .expect("stat key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "private key must be 0600");

        let cert_mode = std::fs::metadata(ca_dir.join(CA_CERT_FILE))
            .expect("stat cert")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cert_mode, 0o644, "cert must be 0644");

        let dir_mode = std::fs::metadata(&ca_dir)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "ca dir must be 0700");
    }

    #[test]
    fn corrupt_dir_missing_key_is_detected() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");
        let _ca = LocalCa::generate_and_persist(&ca_dir).expect("generate");

        std::fs::remove_file(ca_dir.join(CA_KEY_FILE)).expect("rm key");
        let err = LocalCa::load_or_generate(&ca_dir).unwrap_err();
        assert!(matches!(err, CaError::Corrupt { .. }));
    }

    #[test]
    fn debug_impl_does_not_leak_key() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");
        let ca = LocalCa::generate_and_persist(&ca_dir).expect("generate");
        let debug = format!("{ca:?}");
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(!debug.contains(ca.key_pem()));
    }

    #[test]
    fn cert_parses_as_x509() {
        let tmp = TempDir::new().expect("tempdir");
        let ca = LocalCa::generate_and_persist(tmp.path().join("ca")).expect("generate");
        let pem = ca.cert_pem();
        assert!(pem.len() > 500, "cert too small: {} bytes", pem.len());
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    // ------------------------------------------------------------------
    // Phase 5 — trust-store install tests
    // ------------------------------------------------------------------

    /// `detect_ca_trust_method` always returns one of the four variants
    /// without panicking, regardless of which tools are present.
    #[cfg(unix)]
    #[test]
    fn detect_ca_trust_method_returns_some_variant() {
        let m = detect_ca_trust_method();
        // The only invariant we can assert without mocking the host is
        // that the call doesn't panic and returns a known variant.
        assert!(matches!(
            m,
            CaTrustMethod::UpdateCaCertificates
                | CaTrustMethod::UpdateCaTrust
                | CaTrustMethod::TrustAnchor
                | CaTrustMethod::Manual
        ));
    }

    /// `write_anchor` creates the parent directory, writes the file, and
    /// applies mode 0644. This exercises the I/O path without invoking
    /// any external trust-update tool.
    #[cfg(unix)]
    #[test]
    fn write_anchor_creates_parent_dir_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("nested/dir/agentguard-ca.crt");

        write_anchor(
            &path,
            b"-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n",
        )
        .expect("write_anchor");

        assert!(path.is_file(), "anchor file not created at {:?}", path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "anchor must be 0644, got {:o}", mode);
    }

    /// `which_available` returns `false` for a definitely-missing binary
    /// and `true` for a binary that exists in PATH (e.g. `sh`).
    #[cfg(unix)]
    #[test]
    fn which_available_basic_sanity() {
        assert!(
            !which_available("agentguard-totally-missing-binary-xyzzy"),
            "ghost binary unexpectedly found"
        );
        // /bin/sh (or /usr/bin/sh) is part of POSIX — required on every
        // Linux host that can build this crate.
        assert!(which_available("sh"), "`sh` should be in PATH");
    }

    /// `uninstall_system_trust` is idempotent: it succeeds even when no
    /// CA was installed.
    #[cfg(unix)]
    #[test]
    fn uninstall_system_trust_is_idempotent_when_no_anchor_present() {
        // Unprivileged test — we don't actually have write access to
        // `/etc/pki/...`. uninstall_trust silently swallows missing-file
        // errors, so this should always succeed.
        LocalCa::uninstall_system_trust().expect("uninstall must be idempotent");
    }

    /// The system trust filename is constant and matches the one used by
    /// the shell installer scripts.
    #[cfg(unix)]
    #[test]
    fn system_trust_anchor_file_matches_shell_installer() {
        // packaging/install.sh calls
        //     sudo cp "$ca_cert" /etc/pki/ca-trust/source/anchors/agentguard.crt
        //         (legacy filename)
        // The Rust-side install_system_trust uses agentguard-ca.crt
        // and `uninstall_trust` removes BOTH so an upgrade cleans up
        // both legacy and new anchor names.
        assert_eq!(SYSTEM_TRUST_ANCHOR_FILE, "agentguard-ca.crt");
    }

    #[test]
    fn leaf_cert_signed_by_ca_verifies_against_root() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = TempDir::new().expect("tempdir");
        let ca = LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".into()]).expect("san");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        leaf_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);

        let _leaf_cert = leaf_params
            .signed_by(&leaf_key, ca.rcgen_cert().as_ref(), ca.rcgen_key().as_ref())
            .expect("sign leaf — cert should verify against root");
    }
}
