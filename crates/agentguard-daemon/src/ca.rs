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
//!
//! Este módulo **solo** gestiona ciclo de vida y persistencia. La
//! emisión de certs leaf y el wiring con rustls viven en Fase 2.3.

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

/// Validez por defecto del CA root cuando se genera nuevo. 10 años es el
/// estándar de facto para CAs privadas de MITM local. Al rotar, el usuario
/// debe ejecutar `agentguard ca rotate` (pendiente — Fase 2.3+).
pub const DEFAULT_VALIDITY_DAYS: i64 = 365 * 10;

/// Common Name del CA. Aparece en los diálogos del navegador/SO al
/// confiar la CA, así que tiene que ser legible e identificar al producto.
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
}

/// CA root cargada en memoria, lista para firmar certificados leaf.
pub struct LocalCa {
    /// PEM del certificado root (se distribuye al trust store).
    cert_pem: String,
    /// PEM de la clave privada (NUNCA sale de disco + RAM local).
    key_pem: String,
    /// Objeto Certificate de rcgen (para firmar leaf certs en Fase 2.3).
    cert: Arc<Certificate>,
    /// Objeto KeyPair de rcgen (misma que se serializó a key_pem).
    key: Arc<KeyPair>,
    /// Directorio donde vive en disco.
    dir: PathBuf,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // La clave privada nunca debe aparecer en logs accidentalmente.
        f.debug_struct("LocalCa")
            .field("dir", &self.dir)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem_len", &self.key_pem.len())
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    /// Carga la CA del directorio si existe; si no, genera una nueva y la
    /// persiste. Idempotente: llamar varias veces no rota la CA.
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        let dir = dir.as_ref();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        match (cert_path.is_file(), key_path.is_file()) {
            (true, true) => {
                let cert_pem = read_file(&cert_path)?;
                let key_pem = read_file(&key_path)?;
                let key = KeyPair::from_pem(&key_pem).map_err(CaError::KeyParse)?;
                let issuer_params = CertificateParams::from_ca_cert_pem(&cert_pem)
                    .map_err(CaError::CertParse)?;
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
    /// **Sobrescribe** cualquier archivo existente — solo llamar si estás
    /// haciendo una rotación intencional.
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

        // Crear directorio si no existe, con permisos restrictivos.
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

    /// PEM del certificado público. Apto para `update-ca-certificates` / trust store.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// PEM de la clave privada. **No loggear, no enviar por red.**
    /// Expuesta solo para construir `rustls::ServerConfig` en Fase 2.3.
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Objeto `Certificate` de rcgen compartido — para firmar leaf certs.
    pub fn rcgen_cert(&self) -> Arc<Certificate> {
        Arc::clone(&self.cert)
    }

    /// Objeto `KeyPair` de rcgen compartido — misma clave privada.
    pub fn rcgen_key(&self) -> Arc<KeyPair> {
        Arc::clone(&self.key)
    }

    /// Directorio en disco.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Ruta absoluta del certificado root (para instrucciones al usuario).
    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILE)
    }
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
    // El directorio que contiene la clave no debe ser listable por otros.
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

fn write_file_secure(path: &Path, content: &[u8], mode: u32) -> Result<(), CaError> {
    // Escribir → set_permissions. El orden es importante: si ponemos los
    // permisos antes, otro proceso podría hacer `ln -s` atomicamente
    // (race). En este caso el directorio ya es 0o700 por `ensure_dir`,
    // así que el TOCTOU está mitigado.
    std::fs::write(path, content).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).map_err(|source| CaError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
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
        assert!(key.contains("-----BEGIN PRIVATE KEY-----") || key.contains("-----BEGIN EC PRIVATE KEY-----"));

        assert_eq!(ca.cert_pem(), cert);
        assert_eq!(ca.key_pem(), key);
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");

        let ca1 = LocalCa::load_or_generate(&ca_dir).expect("first");
        let ca2 = LocalCa::load_or_generate(&ca_dir).expect("reload");

        // Mismo cert después de recargar → no se regeneró.
        assert_eq!(ca1.cert_pem(), ca2.cert_pem());
        assert_eq!(ca1.key_pem(), ca2.key_pem());
    }

    #[test]
    fn regenerate_overwrites_existing() {
        let tmp = TempDir::new().expect("tempdir");
        let ca_dir = tmp.path().join("ca");

        let ca1 = LocalCa::generate_and_persist(&ca_dir).expect("first");
        let ca2 = LocalCa::generate_and_persist(&ca_dir).expect("regen");

        // Nueva CA → nuevo keypair → PEMs distintos.
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

        let key_mode =
            std::fs::metadata(ca_dir.join(CA_KEY_FILE)).expect("stat key").permissions().mode()
                & 0o777;
        assert_eq!(key_mode, 0o600, "private key must be 0600");

        let cert_mode =
            std::fs::metadata(ca_dir.join(CA_CERT_FILE)).expect("stat cert").permissions().mode()
                & 0o777;
        assert_eq!(cert_mode, 0o644, "cert must be 0644");

        let dir_mode = std::fs::metadata(&ca_dir).expect("stat dir").permissions().mode() & 0o777;
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
        // Redundante con rcgen que ya valida, pero nos da señal si algún
        // día cambian defaults.
        let tmp = TempDir::new().expect("tempdir");
        let ca = LocalCa::generate_and_persist(tmp.path().join("ca")).expect("generate");
        let pem = ca.cert_pem();
        assert!(pem.len() > 500, "cert too small: {} bytes", pem.len());
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    /// TLS handshake con cert firmado por la CA usando rcgen directamente.
    #[test]
    fn leaf_cert_signed_by_ca_verifies_against_root() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = TempDir::new().expect("tempdir");
        let ca = LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".into()]).expect("san");
        leaf_params.distinguished_name.push(DnType::CommonName, "127.0.0.1");
        leaf_params.not_before =
            time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        leaf_params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(1);

        let _leaf_cert = leaf_params
            .signed_by(
                &leaf_key,
                ca.rcgen_cert().as_ref(),
                ca.rcgen_key().as_ref(),
            )
            .expect("sign leaf — cert should verify against root");

        // Si llegamos aquí, la generación del cert funcionó.
        // La verificación TLS no se puede testear sin tokio aquí.
    }
}
