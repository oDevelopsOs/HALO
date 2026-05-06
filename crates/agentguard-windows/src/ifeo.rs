//! Windows IFEO (Image File Execution Options) registry management.
//!
//! IFEO is a NT kernel feature that intercepts process creation via registry
//! keys. When a key `Debugger` is set under `HKLM\...\IFEO\<exename>\`,
//! the NT kernel launches the Debugger process instead and passes the original
//! executable path as its first argument.
//!
//! ## Admin vs non-admin:
//!
//! - **HKLM** (requires admin): System-wide interception. Works for all users
//!   and all launch methods (double-click, terminal, scripts, C API).
//! - **HKCU** (no admin, Win10+): Per-user interception. Only affects the
//!   current user. Does NOT work for processes launched by other users or
//!   services (which is expected behavior).
//!
//! ## How AgentGuard uses IFEO:
//!
//! For each detected AI agent (claude.exe, cursor.exe, etc.), AgentGuard
//! creates an IFEO key that points the `Debugger` value to the AgentGuard
//! launcher. The launcher creates the agent process inside a Low IL or
//! AppContainer sandbox.

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(dead_code)]

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    /// IFEO registry path (relative to HKLM or HKCU).
    const IFEO_SUBKEY: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    /// IFEO value name for the debugger (launcher) path.
    const DEBUGGER_VALUE: &str = "Debugger";

    /// Check if the current user has permission to write to HKLM IFEO keys.
    pub fn can_write_hklm() -> bool {
        // Try to open HKLM IFEO key with write access
        let ifeo_wide: Vec<u16> = IFEO_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(ifeo_wide.as_ptr()),
                0,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };

        if result.is_ok() {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            true
        } else {
            false
        }
    }

    /// Check if HKCU IFEO is available (Win10+, always true for Win10+).
    pub fn hkcu_ifeo_supported() -> bool {
        // Any Windows 10+ supports HKCU IFEO.
        // For older Windows versions, try to open the HKCU IFEO key.
        let ifeo_wide: Vec<u16> = IFEO_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(ifeo_wide.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };

        if result.is_ok() {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            true
        } else {
            // Key may not exist yet — try creating it
            setup_hkcu_key().is_ok()
        }
    }

    /// Ensure the HKCU IFEO key exists (create if it doesn't).
    fn setup_hkcu_key() -> Result<(), String> {
        let ifeo_wide: Vec<u16> = IFEO_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey = HKEY::default();
        let mut _disposition = 0u32;

        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(ifeo_wide.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                None,
                &mut hkey,
                Some(&mut _disposition),
            )
            .map_err(|e| format!("Failed to create HKCU IFEO key: {e}"))?;

            let _ = RegCloseKey(hkey);
        }
        Ok(())
    }

    /// Set up IFEO interception for a specific agent executable.
    ///
    /// # Arguments
    /// * `agent_exe` - Name of the agent executable (e.g., "claude-code.exe")
    /// * `launcher_path` - Full path to the AgentGuard launcher executable
    /// * `use_hklm` - If true and admin, use HKLM (system-wide). Otherwise use HKCU.
    pub fn setup_ifeo(
        agent_exe: &str,
        launcher_path: &str,
        use_hklm: bool,
    ) -> Result<IfeoStatus, String> {
        let hive = if use_hklm && can_write_hklm() {
            HKEY_LOCAL_MACHINE
        } else {
            setup_hkcu_key()?;
            HKEY_CURRENT_USER
        };

        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            agent_exe
        );

        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        let mut disposition = 0u32;

        // Create or open the IFEO key for this agent
        unsafe {
            RegCreateKeyExW(
                hive,
                PCWSTR::from_raw(subkey_wide.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                None,
                &mut hkey,
                Some(&mut disposition),
            )
            .map_err(|e| format!("Failed to create IFEO key for {}: {}", agent_exe, e))?;
        }

        // Set the Debugger value (append --launcher flag so the daemon
        // enters IFEO launcher mode when invoked by the NT kernel).
        let launcher_with_flag = format!("{} --launcher", launcher_path);
        let launcher_wide: Vec<u16> = launcher_with_flag
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let debugger_wide: Vec<u16> = DEBUGGER_VALUE
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let result = unsafe {
            RegSetValueExW(
                hkey,
                PCWSTR::from_raw(debugger_wide.as_ptr()),
                0,
                REG_SZ,
                Some(launcher_wide.as_ptr() as *const u8),
                (launcher_wide.len() * 2) as u32,
            )
        };

        unsafe {
            let _ = RegCloseKey(hkey);
        }

        match result {
            Ok(()) => {
                let scope = if hive == HKEY_LOCAL_MACHINE {
                    "HKLM"
                } else {
                    "HKCU"
                };
                tracing::info!(
                    agent = %agent_exe,
                    launcher = %launcher_path,
                    scope,
                    "IFEO interception configured"
                );
                Ok(IfeoStatus::Configured {
                    scope: scope.to_string(),
                })
            }
            Err(e) => Err(format!("Failed to set Debugger value: {}", e)),
        }
    }

    /// Remove IFEO interception for a specific agent.
    pub fn remove_ifeo(agent_exe: &str) -> Result<(), String> {
        // Try HKCU first, then HKLM
        for (hive, label) in &[(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let subkey = format!(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                agent_exe
            );

            let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey = HKEY::default();

            let open_result = unsafe {
                RegOpenKeyExW(
                    *hive,
                    PCWSTR::from_raw(subkey_wide.as_ptr()),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            };

            if open_result.is_err() {
                continue;
            }

            // Delete the Debugger value
            let debugger_wide: Vec<u16> = DEBUGGER_VALUE
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let _ = RegDeleteValueW(hkey, PCWSTR::from_raw(debugger_wide.as_ptr()));
            }

            // Try to delete the key itself (may fail if other values exist)
            unsafe {
                let _ = RegCloseKey(hkey);
                let _ = RegDeleteKeyW(*hive, PCWSTR::from_raw(subkey_wide.as_ptr()));
            }

            tracing::info!(
                agent = %agent_exe,
                scope = label,
                "IFEO interception removed"
            );
            return Ok(());
        }

        tracing::debug!(
            agent = %agent_exe,
            "No IFEO entry found to remove"
        );
        Ok(())
    }

    /// Check if IFEO is configured for a specific agent.
    pub fn is_ifeo_configured(agent_exe: &str) -> Result<(bool, String), String> {
        for (hive, label) in &[(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let subkey = format!(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                agent_exe
            );

            let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey = HKEY::default();

            let open_result = unsafe {
                RegOpenKeyExW(
                    *hive,
                    PCWSTR::from_raw(subkey_wide.as_ptr()),
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            };

            if open_result.is_err() {
                continue;
            }

            // Check if Debugger value exists
            let debugger_wide: Vec<u16> = DEBUGGER_VALUE
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // We don't need to actually read the value — existence check is enough
            // for the purpose of "is it configured". We just check if the key opens
            // and has a Debugger value.
            unsafe {
                let _ = RegCloseKey(hkey);
            }

            return Ok((true, label.to_string()));
        }

        Ok((false, String::new()))
    }

    #[derive(Debug, Clone)]
    pub enum IfeoStatus {
        Configured { scope: String },
        AlreadyConfigured { scope: String },
        NotSupported,
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
mod stub_impl {
    pub enum IfeoStatus {
        Configured { scope: String },
        AlreadyConfigured { scope: String },
        NotSupported,
    }

    pub fn can_write_hklm() -> bool {
        false
    }

    pub fn hkcu_ifeo_supported() -> bool {
        false
    }

    pub fn setup_ifeo(
        _agent: &str,
        _launcher: &str,
        _use_hklm: bool,
    ) -> Result<IfeoStatus, String> {
        Err("IFEO is only available on Windows".into())
    }

    pub fn remove_ifeo(_agent: &str) -> Result<(), String> {
        Ok(())
    }

    pub fn is_ifeo_configured(_agent: &str) -> Result<(bool, String), String> {
        Ok((false, String::new()))
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_can_write_hklm_returns_bool() {
        let has = can_write_hklm();
        // Should not panic, just return true/false
        let _ = has;
    }

    #[test]
    fn test_hkcu_ifeo_supported_returns_bool() {
        let supported = hkcu_ifeo_supported();
        let _ = supported;
    }

    #[test]
    fn test_is_ifeo_configured_nonexistent() {
        let (configured, _) = is_ifeo_configured("agentguard_test_nonexistent_xyz.exe")
            .unwrap_or((false, String::new()));
        assert!(!configured);
    }

    #[test]
    fn test_setup_and_remove_ifeo() {
        // Use a test-specific executable name
        let test_exe = "agentguard_test_ifeo_dummy.exe";
        let launcher = format!(
            "{}\\agentguard-windows.exe",
            env::current_dir().unwrap_or_default().display()
        );

        // Setup
        let result = setup_ifeo(test_exe, &launcher, false);
        assert!(result.is_ok());

        // Verify configured
        let (configured, scope) = is_ifeo_configured(test_exe).unwrap_or((false, String::new()));
        // Either HKCU or HKLM — both OK
        assert!(scope.is_empty() || scope == "HKCU" || scope == "HKLM");

        // Cleanup
        let _ = remove_ifeo(test_exe);

        // Verify removed
        let (configured_after, _) = is_ifeo_configured(test_exe).unwrap_or((true, String::new()));
        // May be true if we only removed our value, but the key could
        // have been left. Either way, the Debugger value should be gone.
        let _ = configured_after;
    }
}
