//! Emisor de certificados leaf firmados por la CA local para HTTPS MITM.
//!
//! **Seguridad:** la clave privada de la CA nunca sale de memoria del
//! daemon. Los leaf certs viven solo en RAM; no los persistimos.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use thiserror::Error;

use crate::ca::LocalCa;

/// Validez de cada leaf cert (en días).
pub const LEAF_VALIDITY_DAYS: i64 = 30;

/// Tope del cache de leaf certs.
pub const MAX_CACHE_ENTRIES: usize = 512;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to parse CA key from PEM")]
    CaKeyParse(#[source] rcgen::Error),

    #[error("failed to parse CA certificate from PEM")]
    CaCertParse(#[source] rcgen::Error),

    #[error("failed to build leaf certificate for {host:?}")]
    LeafBuild {
        host: String,
        #[source]
        source: rcgen::Error,
    },

    #[error("failed to build rustls ServerConfig for {host:?}")]
    ServerConfig {
        host: String,
        #[source]
        source: rustls::Error,
    },

    #[error("hostname {0:?} is not a valid DNS name")]
    InvalidHostname(String),
}

#[derive(Clone)]
pub struct LeafIssuer {
    inner: Arc<Inner>,
}

struct Inner {
    issuer_cert: Arc<Certificate>,
    issuer_key: Arc<KeyPair>,
    cache: Mutex<HashMap<String, CachedConfig>>,
}

struct CachedConfig {
    config: Arc<ServerConfig>,
    created_at: u64,
}

impl LeafIssuer {
    pub fn new(ca: &LocalCa) -> Result<Self, TlsError> {
        Ok(Self {
            inner: Arc::new(Inner {
                issuer_cert: ca.rcgen_cert(),
                issuer_key: ca.rcgen_key(),
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, TlsError> {
        if let Some(cfg) = self.cache_get(host) {
            return Ok(cfg);
        }
        let config = self.issue_and_cache(host)?;
        Ok(config)
    }

    fn cache_get(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let now = now_unix();
        let max_age = (LEAF_VALIDITY_DAYS as u64).saturating_mul(86_400);
        let cache = match self.inner.cache.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = cache.get(host)?;
        if now.saturating_sub(entry.created_at) > max_age.saturating_sub(3_600) {
            return None;
        }
        Some(Arc::clone(&entry.config))
    }

    fn issue_and_cache(&self, host: &str) -> Result<Arc<ServerConfig>, TlsError> {
        validate_hostname(host)?;

        let leaf_key = KeyPair::generate().map_err(|source| TlsError::LeafBuild {
            host: host.to_string(),
            source,
        })?;

        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(|source| {
            TlsError::LeafBuild {
                host: host.to_string(),
                source,
            }
        })?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(LEAF_VALIDITY_DAYS);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.inner.issuer_cert, &self.inner.issuer_key)
            .map_err(|source| TlsError::LeafBuild {
                host: host.to_string(),
                source,
            })?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|source| TlsError::ServerConfig {
                host: host.to_string(),
                source,
            })?;

        let arc = Arc::new(server_config);

        let mut cache = match self.inner.cache.lock() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };
        if cache.len() >= MAX_CACHE_ENTRIES {
            evict_oldest(&mut cache);
        }
        cache.insert(
            host.to_string(),
            CachedConfig {
                config: Arc::clone(&arc),
                created_at: now_unix(),
            },
        );
        Ok(arc)
    }

    pub fn cache_len(&self) -> usize {
        self.inner.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for LeafIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafIssuer")
            .field("cache_len", &self.cache_len())
            .finish_non_exhaustive()
    }
}

fn validate_hostname(host: &str) -> Result<(), TlsError> {
    if host.is_empty() || host.len() > 253 {
        return Err(TlsError::InvalidHostname(host.to_string()));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(TlsError::InvalidHostname(host.to_string()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(TlsError::InvalidHostname(host.to_string()));
        }
    }
    Ok(())
}

fn evict_oldest(cache: &mut HashMap<String, CachedConfig>) {
    if let Some((oldest_key, _)) = cache
        .iter()
        .min_by_key(|(_, v)| v.created_at)
        .map(|(k, v)| (k.clone(), v.created_at))
    {
        cache.remove(&oldest_key);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ca() -> LocalCa {
        let tmp = TempDir::new().expect("tempdir");
        let ca = LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");
        std::mem::forget(tmp);
        ca
    }

    #[test]
    fn issues_cert_for_hostname_and_caches_it() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = make_ca();
        let issuer = LeafIssuer::new(&ca).expect("issuer");
        assert_eq!(issuer.cache_len(), 0);

        let cfg1 = issuer.server_config_for("api.openai.com").expect("issue");
        assert_eq!(issuer.cache_len(), 1);

        let cfg2 = issuer.server_config_for("api.openai.com").expect("cache");
        assert!(Arc::ptr_eq(&cfg1, &cfg2));
    }

    #[test]
    fn different_hosts_get_different_configs() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = make_ca();
        let issuer = LeafIssuer::new(&ca).expect("issuer");

        let a = issuer.server_config_for("example.com").expect("a");
        let b = issuer.server_config_for("another.test").expect("b");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(issuer.cache_len(), 2);
    }

    #[test]
    fn rejects_invalid_hostname() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = make_ca();
        let issuer = LeafIssuer::new(&ca).expect("issuer");

        for bad in &["", "too..many..dots", "spaces here", "!@#$"] {
            let err = issuer.server_config_for(bad).unwrap_err();
            assert!(matches!(err, TlsError::InvalidHostname(_)), "host {bad:?}");
        }
    }

    #[test]
    fn cache_respects_max_size() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = make_ca();
        let issuer = LeafIssuer::new(&ca).expect("issuer");

        for i in 0..(MAX_CACHE_ENTRIES + 10) {
            let host = format!("host-{i}.test");
            let _ = issuer.server_config_for(&host).expect("issue");
        }
        assert!(issuer.cache_len() <= MAX_CACHE_ENTRIES);
    }

    #[test]
    fn debug_impl_does_not_leak_keys() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = make_ca();
        let issuer = LeafIssuer::new(&ca).expect("issuer");
        let dbg = format!("{issuer:?}");
        assert!(!dbg.contains("PRIVATE"));
        assert!(!dbg.contains("BEGIN"));
    }
}
