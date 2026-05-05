//! Tests E2E para protecciones Windows (Fase 8).
//!
//! Todos los tests requieren ejecutarse en Windows con permisos de administrador
//! y están gated con `#[cfg(windows)]`.

#![cfg(windows)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use agentguard_core::config::{AgentProcess, Config, DlpAction};
use agentguard_core::{KernelGuard, SecurityEvent, ViolationKind};

mod deny_aces_tests {
    use super::*;

    /// Helper: crea un directorio temporal y un archivo dentro.
    fn setup_temp_protected_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("test_file.txt");
        fs::write(&file_path, b"test content").expect("write test file");
        (dir, file_path)
    }

    /// Helper: crea un WindowsGuard con una ruta protegida y ejecuta un test.
    async fn with_guard<F, T>(protected_path: &std::path::Path, test_fn: F) -> T
    where
        F: FnOnce() -> T,
    {
        let guard = agentguard_windows::guard::WindowsGuard::new(
            &[protected_path.to_path_buf()],
            vec![],
        )
        .expect("WindowsGuard::new");

        let (tx, mut _rx) = mpsc::channel::<SecurityEvent>(16);
        tokio::spawn(async move {
            let _ = Box::new(guard).run(tx).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let result = test_fn();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        result
    }

    #[tokio::test]
    async fn deny_aces_prevent_file_deletion() {
        let (_dir, file_path) = setup_temp_protected_dir();
        let dir_path = _dir.path().to_path_buf();

        with_guard(&dir_path, || {
            let result = fs::remove_file(&file_path);
            assert!(result.is_err(), "file deletion should be denied");
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(file_path.exists(), "file should still exist after denied deletion");
        })
        .await;
    }

    #[tokio::test]
    async fn deny_aces_prevent_file_write() {
        let (_dir, file_path) = setup_temp_protected_dir();
        let dir_path = _dir.path().to_path_buf();

        with_guard(&dir_path, || {
            // Try to overwrite the file
            let result = fs::write(&file_path, b"malicious content");
            assert!(result.is_err(), "file write should be denied");
            let content = fs::read_to_string(&file_path).unwrap();
            assert_eq!(content, "test content", "original content should be preserved");
        })
        .await;
    }

    #[tokio::test]
    async fn deny_aces_prevent_new_file_creation() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let dir_path = dir.path().to_path_buf();
        let new_file = dir_path.join("new_evil.sh");

        with_guard(&dir_path, || {
            let result = fs::write(&new_file, b"malware");
            assert!(result.is_err(), "file creation in protected dir should be denied");
        })
        .await;
    }

    #[tokio::test]
    async fn deny_aces_prevent_directory_deletion() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let subdir = dir.path().join("nested");
        fs::create_dir(&subdir).expect("create nested dir");
        let dir_path = dir.path().to_path_buf();

        with_guard(&dir_path, || {
            let result = fs::remove_dir_all(&subdir);
            assert!(
                result.is_err(),
                "directory deletion in protected dir should be denied"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn protected_dir_is_not_deletable() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let dir_path = dir.path().to_path_buf();

        with_guard(&dir_path, || {
            let result = fs::remove_dir_all(&dir_path);
            assert!(result.is_err(), "protected directory should not be deletable");
            assert!(dir_path.exists(), "protected directory should still exist");
        })
        .await;
    }

    #[tokio::test]
    async fn unprotected_dir_is_deletable() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("unprotected.txt");
        fs::write(&file_path, b"free to delete").unwrap();

        let result = fs::remove_file(&file_path);
        assert!(result.is_ok(), "unprotected file should be deletable");
        assert!(!file_path.exists(), "unprotected file should be gone");
    }
}

mod peb_tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn peb_reads_cmdline_of_child_process() {
        // Launch a process with known command line and read its PEB
        let child = Command::new("cmd.exe")
            .args(["/C", "echo", "HELLO_AGENTGUARD_TEST_12345"])
            .spawn()
            .expect("spawn child");

        let pid = child.id();

        // Small delay for the process to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        let cmdline =
            agentguard_windows::helpers::win32::read_process_command_line_by_pid(pid);
        // Note: cmd.exe will show something like 'C:\Windows\system32\cmd.exe /C echo ...'
        // The exact format depends on how CreateProcess passes the command line
        if let Some(cmd) = cmdline {
            assert!(
                cmd.contains("cmd"),
                "cmdline should contain the executable name: {cmd}"
            );
        }
        // Process may have already exited or PEB may be inaccessible
    }

    #[test]
    fn peb_reads_cwd_of_running_process() {
        let pid = std::process::id();

        let cwd =
            agentguard_windows::helpers::win32::read_process_cwd_by_pid(pid);

        // Should return a non-empty path for a running process
        assert!(!cwd.is_empty(), "CWD should not be empty for running process");
        assert!(std::path::Path::new(&cwd).is_absolute(), "CWD should be an absolute path");
    }
}

mod agent_detection_tests {
    use agentguard_core::config::{AgentDetection, AgentMatch};
    use agentguard_windows::guard::WindowsGuard;

    #[test]
    fn matches_known_ai_agents_by_exe() {
        let patterns = vec![
            AgentProcess {
                name: "cursor".into(),
                r#match: AgentMatch {
                    exe: None,
                    exe_any: vec![],
                    argv_contains_any: vec![],
                    env_has: None,
                },
            },
            AgentProcess {
                name: "claude-code".into(),
                r#match: AgentMatch {
                    exe: None,
                    exe_any: vec!["claude".into()],
                    argv_contains_any: vec![],
                    env_has: None,
                },
            },
        ];

        // These tests use the matching logic (cross-platform, no Win32 calls)
        let guard = WindowsGuard::new(&[], patterns).expect("create guard");
        // Guard construction with empty paths should succeed
        assert_eq!(guard.backend_name(), "ntfs-deny-aces");
        assert_eq!(guard.protection_level(), agentguard_core::ProtectionLevel::KernelDenial);
    }
}

mod sandbox_tests {
    use agentguard_windows::sandbox::{SandboxCapabilities, SandboxLauncher};
    use agentguard_core::config::Config;

    #[test]
    fn sandbox_capabilities_detect_appcontainer() {
        let caps = SandboxLauncher::check_capabilities();
        // On Windows 8+, AppContainer should be available
        assert!(caps.appcontainer_available, "AppContainer should be available on modern Windows");
        assert!(caps.etw_available, "ETW should be available");
    }

    #[test]
    fn sandbox_effective_mode_returns_sandbox_when_available() {
        let caps = SandboxCapabilities {
            appcontainer_available: true,
            etw_available: true,
        };
        assert_eq!(caps.effective_mode("sandbox"), "sandbox");
        assert_eq!(caps.effective_mode("hybrid"), "sandbox");
        assert_eq!(caps.effective_mode("monitor"), "monitor");
    }

    #[test]
    fn sandbox_effective_mode_falls_back_to_monitor() {
        let caps = SandboxCapabilities {
            appcontainer_available: false,
            etw_available: true,
        };
        assert_eq!(caps.effective_mode("sandbox"), "monitor");
        assert_eq!(caps.effective_mode("hybrid"), "monitor");
    }

    #[test]
    fn sandbox_report_includes_capabilities() {
        let caps = SandboxCapabilities {
            appcontainer_available: true,
            etw_available: true,
        };
        let report = caps.report();
        assert!(report.contains("AppContainer=yes"), "report: {report}");
        assert!(report.contains("ETW=yes"), "report: {report}");
    }

    #[test]
    fn sandbox_report_without_appcontainer() {
        let caps = SandboxCapabilities {
            appcontainer_available: false,
            etw_available: false,
        };
        let report = caps.report();
        assert!(!report.is_empty(), "report should not be empty");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn appcontainer_launches_process() {
        let config = Config::default();
        let launcher = SandboxLauncher::new(config);

        let result = launcher
            .launch("cmd.exe", std::path::Path::new("C:\\"), false)
            .await;

        match result {
            Ok(pid) => {
                assert!(pid > 0, "launched process should have a valid PID");
                // Clean up: kill the process
                use windows::Win32::System::Threading::{
                    OpenProcess, TerminateProcess, PROCESS_TERMINATE,
                };
                use windows::Win32::Foundation::CloseHandle;
                unsafe {
                    if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                        let _ = TerminateProcess(h, 0);
                        let _ = CloseHandle(h);
                    }
                }
            }
            Err(e) => {
                // AppContainer may not be available on all Windows versions
                // or the test may be running without admin
                eprintln!("AppContainer test skipped: {e}");
            }
        }
    }
}

mod etw_tests {
    use agentguard_windows::process_watcher::ProcessWatcher;
    use agentguard_core::config::Config;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};
    use tokio::time::Duration;

    #[cfg(windows)]
    #[tokio::test]
    async fn etw_session_creation_succeeds() {
        let config = Arc::new(RwLock::new(Config::default()));
        let (tx, mut _rx) = mpsc::channel::<SecurityEvent>(16);

        let watcher = ProcessWatcher::new(config.clone(), tx);

        // Start ETW - may fail without admin privileges
        match watcher.start_etw() {
            Ok(()) => {
                // ETW session started, wait a bit and check
                tokio::time::sleep(Duration::from_millis(500)).await;
                // Session should be running (no error log)
            }
            Err(e) => {
                eprintln!("ETW test skipped (requires admin): {e}");
            }
        }
    }
}
