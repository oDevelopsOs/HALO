//! Vault de snapshots — copia-en-disco con deduplicación BLAKE3.
//!
//! Diseño:
//! - Cada snapshot vive en `<vault_dir>/<uuid>/`.
//! - Dentro, el `manifest.json` lista los archivos originales + su hash
//!   BLAKE3, tamaño y permisos.
//! - El contenido real se guarda como `<hash>` en el mismo directorio; si
//!   dos archivos tienen el mismo hash, se escribe una vez sola.
//!
//! No se usa git — un formato plano con manifesto JSON es más sencillo de
//! auditar, no tiene dependencias nativas, y el coste en disco es bajo
//! gracias a la deduplicación.
//!
//! Ver `.windsurf/rules/02-no-unwrap.md`: este módulo está en código
//! productivo, así que nada de `.unwrap()` ni `.expect(...)`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

/// Errores del subsistema Vault.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error on {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize manifest")]
    ManifestSerialize(#[from] serde_json::Error),

    #[error("system clock is before UNIX epoch")]
    Clock(#[from] SystemTimeError),

    #[error("snapshot {0} not found")]
    NotFound(String),

    #[error("snapshot manifest is corrupted at {path:?}")]
    CorruptManifest {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("snapshot content missing: hash {hash} not in snapshot {id}")]
    MissingBlob { id: String, hash: String },
}

/// Snapshot persistido en disco.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// UUID v4 identificador del snapshot.
    pub id: String,
    /// Timestamp de creación (segundos desde UNIX epoch).
    pub timestamp: u64,
    /// Etiqueta semántica libre: "pre-session", "manual", "startup", ...
    pub label: String,
    /// Listado de archivos respaldados.
    pub files: Vec<FileEntry>,
    /// Bytes totales (antes de deduplicación).
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub original_path: PathBuf,
    /// Hash BLAKE3 hex (64 chars).
    pub hash: String,
    pub size: u64,
    /// Modo Unix; 0 si no disponible (ej: Windows en el futuro).
    pub permissions: u32,
}

/// Handle del vault. Es barato de clonar — mantiene solo el path base.
#[derive(Debug, Clone)]
pub struct Vault {
    vault_dir: PathBuf,
}

impl Vault {
    /// Crea un vault anclado a un directorio específico. El directorio se
    /// crea si no existe.
    pub fn with_dir(vault_dir: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let vault_dir = vault_dir.into();
        std::fs::create_dir_all(&vault_dir).map_err(|source| VaultError::Io {
            path: vault_dir.clone(),
            source,
        })?;
        Ok(Self { vault_dir })
    }

    /// Ruta base del vault.
    pub fn root(&self) -> &Path {
        &self.vault_dir
    }

    /// Crea un snapshot que contiene **todos los archivos** bajo las rutas
    /// indicadas (recursivamente). Símbolos y archivos inaccesibles se
    /// saltan con un warning en el log (no fallan el snapshot entero).
    pub async fn create_snapshot(
        &self,
        protected_paths: &[PathBuf],
        label: &str,
    ) -> Result<Snapshot, VaultError> {
        let id = uuid::Uuid::new_v4().to_string();
        let snapshot_dir = self.vault_dir.join(&id);
        fs::create_dir_all(&snapshot_dir)
            .await
            .map_err(|source| VaultError::Io {
                path: snapshot_dir.clone(),
                source,
            })?;

        let mut files: Vec<FileEntry> = Vec::new();
        let mut total_size: u64 = 0;
        let mut already_written: BTreeSet<String> = BTreeSet::new();

        for protected_path in protected_paths {
            let entries = collect_files(protected_path).await?;
            for entry_path in entries {
                let content = match fs::read(&entry_path).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            path = ?entry_path,
                            error = %e,
                            "skipping unreadable file in snapshot"
                        );
                        continue;
                    }
                };

                let hash = blake3::hash(&content).to_hex().to_string();
                let size = content.len() as u64;
                total_size = total_size.saturating_add(size);

                let stored_path = snapshot_dir.join(&hash);
                if !already_written.contains(&hash) {
                    fs::write(&stored_path, &content).await.map_err(|source| {
                        VaultError::Io {
                            path: stored_path.clone(),
                            source,
                        }
                    })?;
                    already_written.insert(hash.clone());
                }

                files.push(FileEntry {
                    original_path: entry_path.clone(),
                    hash,
                    size,
                    permissions: get_permissions(&entry_path),
                });
            }
        }

        let snapshot = Snapshot {
            id: id.clone(),
            timestamp: now_unix()?,
            label: label.to_string(),
            files,
            total_size,
        };

        let manifest_path = snapshot_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&snapshot)?;
        fs::write(&manifest_path, manifest_json)
            .await
            .map_err(|source| VaultError::Io {
                path: manifest_path,
                source,
            })?;

        tracing::info!(
            id = %snapshot.id,
            files = snapshot.files.len(),
            bytes = snapshot.total_size,
            label = %label,
            "snapshot created"
        );
        Ok(snapshot)
    }

    /// Restaura un snapshot por ID. Sobrescribe los archivos originales.
    pub async fn restore(&self, snapshot_id: &str) -> Result<(), VaultError> {
        let snapshot = self.load_manifest(snapshot_id).await?;
        let snapshot_dir = self.vault_dir.join(snapshot_id);

        for file_entry in &snapshot.files {
            let stored = snapshot_dir.join(&file_entry.hash);
            let content = match fs::read(&stored).await {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VaultError::MissingBlob {
                        id: snapshot_id.to_string(),
                        hash: file_entry.hash.clone(),
                    });
                }
                Err(source) => {
                    return Err(VaultError::Io {
                        path: stored,
                        source,
                    });
                }
            };

            if let Some(parent) = file_entry.original_path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|source| VaultError::Io {
                        path: parent.to_path_buf(),
                        source,
                    })?;
            }

            fs::write(&file_entry.original_path, &content)
                .await
                .map_err(|source| VaultError::Io {
                    path: file_entry.original_path.clone(),
                    source,
                })?;

            restore_permissions(&file_entry.original_path, file_entry.permissions)?;

            tracing::debug!(path = ?file_entry.original_path, "restored");
        }

        tracing::info!(
            id = %snapshot_id,
            files = snapshot.files.len(),
            "snapshot restored"
        );
        Ok(())
    }

    /// Lista todos los snapshots ordenados del más reciente al más antiguo.
    pub async fn list(&self) -> Result<Vec<Snapshot>, VaultError> {
        let mut snapshots = Vec::new();
        let mut entries = fs::read_dir(&self.vault_dir)
            .await
            .map_err(|source| VaultError::Io {
                path: self.vault_dir.clone(),
                source,
            })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| VaultError::Io {
                path: self.vault_dir.clone(),
                source,
            })?
        {
            let manifest_path = entry.path().join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }
            match read_manifest(&manifest_path).await {
                Ok(s) => snapshots.push(s),
                Err(e) => {
                    tracing::warn!(
                        path = ?manifest_path,
                        error = %e,
                        "skipping unreadable snapshot manifest"
                    );
                }
            }
        }

        snapshots.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
        Ok(snapshots)
    }

    /// Elimina snapshots con timestamp anterior a `now - keep_days * 86400`.
    pub async fn cleanup(&self, keep_days: u64) -> Result<usize, VaultError> {
        let now = now_unix()?;
        let cutoff = now.saturating_sub(keep_days.saturating_mul(86_400));
        let mut removed = 0;
        for snapshot in self.list().await? {
            if snapshot.timestamp < cutoff {
                let snapshot_dir = self.vault_dir.join(&snapshot.id);
                fs::remove_dir_all(&snapshot_dir)
                    .await
                    .map_err(|source| VaultError::Io {
                        path: snapshot_dir,
                        source,
                    })?;
                tracing::info!(id = %snapshot.id, "cleaned up old snapshot");
                removed += 1;
            }
        }
        Ok(removed)
    }

    async fn load_manifest(&self, snapshot_id: &str) -> Result<Snapshot, VaultError> {
        let manifest_path = self.vault_dir.join(snapshot_id).join("manifest.json");
        if !manifest_path.is_file() {
            return Err(VaultError::NotFound(snapshot_id.to_string()));
        }
        read_manifest(&manifest_path).await
    }
}

async fn read_manifest(path: &Path) -> Result<Snapshot, VaultError> {
    let text = fs::read_to_string(path).await.map_err(|source| VaultError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| VaultError::CorruptManifest {
        path: path.to_path_buf(),
        source,
    })
}

/// Descubrimiento recursivo de archivos.
async fn collect_files(root: &Path) -> Result<Vec<PathBuf>, VaultError> {
    let mut files = Vec::new();
    let metadata = match fs::symlink_metadata(root).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(path = ?root, "protected path missing, skipping");
            return Ok(files);
        }
        Err(source) => {
            return Err(VaultError::Io {
                path: root.to_path_buf(),
                source,
            });
        }
    };

    if metadata.is_file() {
        files.push(root.to_path_buf());
        return Ok(files);
    }
    if !metadata.is_dir() {
        return Ok(files);
    }

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir).await.map_err(|source| VaultError::Io {
            path: dir.clone(),
            source,
        })?;
        while let Some(entry) = entries.next_entry().await.map_err(|source| VaultError::Io {
            path: dir.clone(),
            source,
        })? {
            let entry_path = entry.path();
            let md = match fs::symlink_metadata(&entry_path).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(path = ?entry_path, error = %e, "stat failed, skipping");
                    continue;
                }
            };
            if md.is_dir() {
                stack.push(entry_path);
            } else if md.is_file() {
                files.push(entry_path);
            }
        }
    }

    Ok(files)
}

fn get_permissions(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map(|m| m.mode()).unwrap_or(0o644)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
    }
}

fn restore_permissions(path: &Path, mode: u32) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if mode != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(
                |source| VaultError::Io {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn now_unix() -> Result<u64, VaultError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(p: &Path, content: &[u8]) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    #[tokio::test]
    async fn create_and_restore_single_file() {
        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        let file = zone.join("doc.md");
        write_file(&file, b"original content");

        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();
        let snap = vault
            .create_snapshot(std::slice::from_ref(&zone), "test")
            .await
            .unwrap();
        assert_eq!(snap.files.len(), 1);
        assert_eq!(snap.label, "test");

        std::fs::remove_file(&file).unwrap();
        assert!(!file.exists());

        vault.restore(&snap.id).await.unwrap();
        assert!(file.exists());
        assert_eq!(std::fs::read(&file).unwrap(), b"original content");
    }

    #[tokio::test]
    async fn dedup_identical_content() {
        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        write_file(&zone.join("a.txt"), b"dup");
        write_file(&zone.join("b.txt"), b"dup");
        write_file(&zone.join("c.txt"), b"different");

        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();
        let snap = vault.create_snapshot(&[zone], "dedup").await.unwrap();
        assert_eq!(snap.files.len(), 3);

        let snap_dir = vault.root().join(&snap.id);
        let blob_count = std::fs::read_dir(&snap_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != "manifest.json")
            .count();
        assert_eq!(blob_count, 2, "expected deduplication to produce 2 blobs");
    }

    #[tokio::test]
    async fn recursive_snapshot_covers_nested_files() {
        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        write_file(&zone.join("top.md"), b"1");
        write_file(&zone.join("sub/mid.md"), b"2");
        write_file(&zone.join("sub/deeper/leaf.md"), b"3");

        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();
        let snap = vault.create_snapshot(std::slice::from_ref(&zone), "nested").await.unwrap();
        assert_eq!(snap.files.len(), 3);
        assert_eq!(snap.total_size, 3);
    }

    #[tokio::test]
    async fn list_returns_newest_first() {
        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        write_file(&zone.join("f"), b"x");
        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();

        let s1 = vault.create_snapshot(std::slice::from_ref(&zone), "first").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let s2 = vault.create_snapshot(&[zone], "second").await.unwrap();

        let list = vault.list().await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, s2.id);
        assert_eq!(list[1].id, s1.id);
    }

    #[tokio::test]
    async fn restore_of_unknown_id_fails_with_not_found() {
        let tmp = TempDir::new().unwrap();
        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();
        let err = vault.restore("does-not-exist").await.unwrap_err();
        assert!(matches!(err, VaultError::NotFound(_)));
    }

    #[tokio::test]
    async fn cleanup_removes_only_old_snapshots() {
        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        write_file(&zone.join("f"), b"x");
        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();

        let snap = vault.create_snapshot(&[zone], "recent").await.unwrap();
        let removed = vault.cleanup(30).await.unwrap();
        assert_eq!(removed, 0);
        assert!(vault.root().join(&snap.id).exists());

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let removed = vault.cleanup(0).await.unwrap();
        assert_eq!(removed, 1);
        assert!(!vault.root().join(&snap.id).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_preserves_unix_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let zone = tmp.path().join("zone");
        let file = zone.join("secret");
        write_file(&file, b"confidential");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let vault = Vault::with_dir(tmp.path().join("vault")).unwrap();
        let snap = vault.create_snapshot(&[zone], "perms").await.unwrap();

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_file(&file).unwrap();

        vault.restore(&snap.id).await.unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
