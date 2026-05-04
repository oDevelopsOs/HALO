//! Tests de integración del subsistema Vault.
//!
//! Escenarios end-to-end que ejercitan varios métodos de `Vault` juntos.
//! Nunca tocan `$HOME` del desarrollador: todo ocurre bajo un `TempDir`.

use std::fs;
use std::path::PathBuf;

use agentguard_core::Vault;
use tempfile::TempDir;

fn write(p: &PathBuf, content: &[u8]) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(p, content).expect("write file");
}

#[tokio::test]
async fn full_cycle_snapshot_destroy_restore() {
    let tmp = TempDir::new().expect("tempdir");
    let zone = tmp.path().join("zone");
    let doc = zone.join("important.md");
    let env = zone.join("secrets/.env");
    let nested = zone.join("a/b/c/deep.md");

    write(&doc, b"CONTENIDO IMPORTANTE");
    write(&env, b"API_KEY=sk-xxx");
    write(&nested, b"nested payload");

    let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
    let snap = vault
        .create_snapshot(std::slice::from_ref(&zone), "pre-session")
        .await
        .expect("snapshot");
    assert_eq!(snap.files.len(), 3);
    assert_eq!(snap.label, "pre-session");

    // "Agente loco" destruye todo
    fs::remove_dir_all(&zone).expect("destroy zone");
    assert!(!zone.exists());

    // Restore completo
    vault.restore(&snap.id).await.expect("restore");

    assert_eq!(fs::read(&doc).expect("read doc"), b"CONTENIDO IMPORTANTE");
    assert_eq!(fs::read(&env).expect("read env"), b"API_KEY=sk-xxx");
    assert_eq!(fs::read(&nested).expect("read nested"), b"nested payload");
}

#[tokio::test]
async fn list_and_cleanup_interact_correctly() {
    let tmp = TempDir::new().expect("tempdir");
    let zone = tmp.path().join("zone");
    write(&zone.join("file"), b"x");

    let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
    for i in 0..3 {
        vault
            .create_snapshot(std::slice::from_ref(&zone), &format!("snap-{i}"))
            .await
            .expect("snap");
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }

    let list = vault.list().await.expect("list");
    assert_eq!(list.len(), 3);
    // Ordenado newest-first
    for w in list.windows(2) {
        assert!(w[0].timestamp >= w[1].timestamp);
    }

    // Cleanup agresivo
    let removed = vault.cleanup(0).await.expect("cleanup");
    assert_eq!(removed, 3);
    assert_eq!(vault.list().await.expect("list empty").len(), 0);
}

#[tokio::test]
async fn hash_stability_across_snapshots() {
    // Dos snapshots de un mismo archivo inmutable → mismo hash.
    let tmp = TempDir::new().expect("tempdir");
    let zone = tmp.path().join("zone");
    let file = zone.join("immutable.md");
    write(&file, b"never changes");

    let vault = Vault::with_dir(tmp.path().join("vault")).expect("vault");
    let s1 = vault
        .create_snapshot(std::slice::from_ref(&zone), "a")
        .await
        .expect("s1");
    let s2 = vault
        .create_snapshot(std::slice::from_ref(&zone), "b")
        .await
        .expect("s2");

    assert_eq!(s1.files[0].hash, s2.files[0].hash);
    // Hash BLAKE3 de "never changes"
    assert_eq!(s1.files[0].hash.len(), 64);
}
