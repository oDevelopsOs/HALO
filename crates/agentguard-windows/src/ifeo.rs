//! Windows IFEO (Image File Execution Options) registry management.

#![allow(dead_code, unused_imports)]

use std::path::Path;

// ── Windows implementation ────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const IFEO_SUBKEY: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    const DEBUGGER_VALUE: &str = "Debugger";

    pub fn can_write_hklm() -> bool {
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
        if result.0 == 0 {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            true
        } else {
            false
        }
    }

    pub fn hkcu_ifeo_supported() -> bool {
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
        if result.0 == 0 {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            return true;
        }
        setup_hkcu_raw().is_ok()
    }

    fn setup_hkcu_raw() -> Result<(), String> {
        let ifeo_wide: Vec<u16> = IFEO_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey = HKEY::default();
        let mut disp = 0u32;
        let ret = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(ifeo_wide.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                None,
                &mut hkey,
                Some(&mut disp),
            )
        };
        if ret.0 != 0 {
            return Err(format!("Failed: {:?}", ret));
        }
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        Ok(())
    }

    pub fn setup_ifeo(
        agent_exe: &str,
        launcher_path: &str,
        use_hklm: bool,
    ) -> Result<IfeoStatus, String> {
        let hive = if use_hklm && can_write_hklm() {
            HKEY_LOCAL_MACHINE
        } else {
            setup_hkcu_raw()?;
            HKEY_CURRENT_USER
        };
        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            agent_exe
        );
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        let mut disp = 0u32;
        let ret = unsafe {
            RegCreateKeyExW(
                hive,
                PCWSTR::from_raw(subkey_wide.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                None,
                &mut hkey,
                Some(&mut disp),
            )
        };
        if ret.0 != 0 {
            return Err(format!("Failed IFEO key: {:?}", ret));
        }

        let launcher_with_flag = format!("{} --launcher", launcher_path);
        let launcher_wide: Vec<u16> = launcher_with_flag
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let debugger_wide: Vec<u16> = DEBUGGER_VALUE
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let ret = unsafe {
            RegSetValueExW(
                hkey,
                PCWSTR::from_raw(debugger_wide.as_ptr()),
                0,
                REG_SZ,
                Some(launcher_wide.as_slice()),
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }

        if ret.0 == 0 {
            let scope = if hive == HKEY_LOCAL_MACHINE {
                "HKLM"
            } else {
                "HKCU"
            };
            Ok(IfeoStatus::Configured {
                scope: scope.into(),
            })
        } else {
            Err(format!("Failed Debugger value: {:?}", ret))
        }
    }

    pub fn remove_ifeo(agent_exe: &str) -> Result<(), String> {
        for (hive, _label) in &[(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let subkey = format!(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                agent_exe
            );
            let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey = HKEY::default();
            let r = unsafe {
                RegOpenKeyExW(
                    *hive,
                    PCWSTR::from_raw(subkey_wide.as_ptr()),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            };
            if r.0 != 0 {
                continue;
            }
            let dw: Vec<u16> = DEBUGGER_VALUE
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let _ = RegDeleteValueW(hkey, PCWSTR::from_raw(dw.as_ptr()));
            }
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            unsafe {
                let _ = RegDeleteKeyW(*hive, PCWSTR::from_raw(subkey_wide.as_ptr()));
            }
            return Ok(());
        }
        Ok(())
    }

    pub fn is_ifeo_configured(agent_exe: &str) -> Result<(bool, String), String> {
        for (hive, label) in &[(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let subkey = format!(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                agent_exe
            );
            let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey = HKEY::default();
            let r = unsafe {
                RegOpenKeyExW(
                    *hive,
                    PCWSTR::from_raw(subkey_wide.as_ptr()),
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            };
            if r.0 != 0 {
                continue;
            }
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

// ── Non-Windows stubs ────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod stub_impl {
    #[derive(Debug, Clone)]
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
    pub fn setup_ifeo(_a: &str, _l: &str, _u: bool) -> Result<IfeoStatus, String> {
        Err("IFEO only available on Windows".into())
    }
    pub fn remove_ifeo(_a: &str) -> Result<(), String> {
        Ok(())
    }
    pub fn is_ifeo_configured(_a: &str) -> Result<(bool, String), String> {
        Ok((false, String::new()))
    }
}

// ── Re-exports ────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub use stub_impl::*;
#[cfg(target_os = "windows")]
pub use windows_impl::*;
