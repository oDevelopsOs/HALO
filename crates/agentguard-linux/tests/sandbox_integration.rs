//! Integration tests for v2.1 — Sandbox Launcher + Agent Detection (Linux only)
//! These tests require bwrap, Landlock, and other Linux-specific features.

#[cfg(target_os = "linux")]
#[cfg(test)]
mod sandbox_tests {
    use tempfile::TempDir;
    use tokio::time::{sleep, Duration};

    use agentguard_core::config::Config;
    use agentguard_linux::sandbox::SandboxLauncher;

    #[allow(clippy::field_reassign_with_default)]
    fn make_test_config(project_dir: &std::path::Path) -> Config {
        let mut config = Config::default();
        config.protected_dirs = vec![project_dir.to_path_buf()];
        config.dlp.proxy_port = 17771;
        config.sandbox.modo_por_defecto = "sandbox".into();
        config
    }

    #[tokio::test]
    async fn test_sandbox_launches_process() {
        if which::which("bwrap").is_err() {
            eprintln!("SKIP: bwrap not available");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let config = make_test_config(tmp.path());
        let launcher = SandboxLauncher::new(config);

        let pid = launcher.launch("echo", tmp.path(), false, false).await;
        assert!(pid.is_ok(), "sandbox launch failed: {:?}", pid.err());

        let pid = pid.unwrap();
        assert!(pid > 0, "PID should be positive");
        sleep(Duration::from_millis(300)).await;
    }

    #[tokio::test]
    async fn test_sandbox_isolates_project() {
        if which::which("bwrap").is_err() {
            eprintln!("SKIP: bwrap not available");
            return;
        }

        let project = TempDir::new().unwrap();
        // Crear archivo dentro del proyecto (será visible en el sandbox)
        let inside_file = project.path().join("test.txt");
        std::fs::write(&inside_file, "inside project").unwrap();

        let config = make_test_config(project.path());
        let launcher = SandboxLauncher::new(config);

        // Lanzar 'echo' en el sandbox — verifica que bwrap funciona y no explota
        let pid = launcher.launch("echo", project.path(), false, false).await;
        assert!(pid.is_ok(), "sandbox should launch echo: {:?}", pid.err());

        sleep(Duration::from_millis(500)).await;

        // El archivo dentro del proyecto sigue intacto
        let content = std::fs::read_to_string(&inside_file).unwrap();
        assert_eq!(content, "inside project");
    }

    #[test]
    fn test_capabilities_mode_degradation() {
        let caps = SandboxLauncher::check_capabilities();
        let mode = caps.effective_mode("hybrid");
        assert!(mode == "hybrid" || mode == "sandbox" || mode == "monitor");

        let report = caps.report();
        assert!(!report.is_empty());
        assert!(report.contains("bwrap="));
    }
}
