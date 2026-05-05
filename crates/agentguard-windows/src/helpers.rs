//! Helpers Win32 compartidos: estructuras PEB y bindings FFI raw.
//!
//! windows-rs v0.58 no expone NtQueryInformationProcess ni CreateAppContainerProfile.
//! Los bindings aquí son estables (ABI de kernel inmutable desde Vista/Windows 7).

#[cfg(target_os = "windows")]
pub(crate) mod win32 {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // ── NtQueryInformationProcess (ntdll.dll) ──────────────

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: HANDLE,
            process_information_class: u32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    const PROCESS_BASIC_INFORMATION: u32 = 0;

    #[repr(C)]
    #[derive(Debug)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    // ── PEB structures (estables desde Vista 64-bit) ───────

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct RtlUserProcessParameters {
        _maximum_length: u32,
        _length: u32,
        _flags: u32,
        _debug_flags: u32,
        _console_handle: *mut c_void,
        _console_flags: u32,
        _padding: [u8; 4],
        _standard_input: *mut c_void,
        _standard_output: *mut c_void,
        _standard_error: *mut c_void,
        _current_directory: [u8; 24],
        _dll_path: UnicodeString,
        _image_path_name: UnicodeString,
        command_line: UnicodeString,
        _environment: *mut c_void,
    }

    // Offset of command_line within RtlUserProcessParameters (64-bit)
    // Layout: 4×u32(16) + handle(8) + u32+pad(8) + 3×handle(24) + curdir(24) + 2×ustr(32) = 112
    const CMDLINE_OFFSET: usize = 112;

    // Offset of _current_directory within RtlUserProcessParameters (64-bit)
    // Layout: 4×u32(16) + handle(8) + u32+pad(8) + 3×handle(24) = 56
    const CWD_OFFSET: usize = 56;

    #[repr(C)]
    struct Peb {
        _inherited_address_space: u8,
        _read_image_file_exec_options: u8,
        _being_debugged: u8,
        _bit_field: u8,
        _padding0: [u8; 4],
        _mutant: *mut c_void,
        _image_base_address: *mut c_void,
        _ldr: *mut c_void,
        process_parameters: *mut RtlUserProcessParameters,
    }

    /// Abre un proceso con permisos mínimos para leer su PEB.
    pub fn open_process_for_peb(pid: u32) -> windows::core::Result<HANDLE> {
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
    }

    /// Lee la línea de comandos de un proceso remoto vía PEB.
    /// Retorna None si el proceso ya terminó o no se puede leer.
    pub fn read_remote_command_line(
        process: HANDLE,
    ) -> Option<String> {
        // 1. Query PEB base address
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return None;
        }

        let peb_addr = pbi.peb_base_address;
        if peb_addr.is_null() {
            return None;
        }

        // 2. Read PEB to get process_parameters pointer
        let peb = read_process_memory_typed::<Peb>(process, peb_addr)?;
        let params_addr = peb.process_parameters;
        if params_addr.is_null() {
            return None;
        }

        // 3. Read command_line UnicodeString from remote process parameters
        let cmdline_field_addr =
            unsafe { (params_addr as *const u8).add(CMDLINE_OFFSET) as *const c_void };
        let cmdline_ustr = read_process_memory_typed::<UnicodeString>(process, cmdline_field_addr)?;

        // 4. Read the actual command line buffer (UTF-16)
        if cmdline_ustr.buffer.is_null() || cmdline_ustr.length == 0 {
            return None;
        }

        let buf_bytes = cmdline_ustr.length as usize;
        let buf = read_process_memory_slice(process, cmdline_ustr.buffer as *const c_void, buf_bytes)?;

        // 5. Convert UTF-16 → String
        let wchars: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let cmdline = String::from_utf16_lossy(&wchars);

        Some(cmdline)
    }

    /// Lee el directorio de trabajo actual de un proceso remoto vía PEB.
    /// Retorna String vacío si no se puede leer.
    pub fn read_remote_cwd(process: HANDLE) -> String {
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return String::new();
        }

        let peb_addr = pbi.peb_base_address;
        if peb_addr.is_null() {
            return String::new();
        }

        let peb = match read_process_memory_typed::<Peb>(process, peb_addr) {
            Some(p) => p,
            None => return String::new(),
        };

        let params_addr = peb.process_parameters;
        if params_addr.is_null() {
            return String::new();
        }

        // Read _current_directory offset (24 bytes, UTF-16 buffer embedded)
        let cwd_field_addr =
            unsafe { (params_addr as *const u8).add(CWD_OFFSET) as *const c_void };
        let cwd_bytes = match read_process_memory_slice(process, cwd_field_addr, 24) {
            Some(b) => b,
            None => return String::new(),
        };

        let wchars: Vec<u16> = cwd_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&wchars)
    }

    /// Helper: lee N bytes de la memoria de un proceso remoto.
    fn read_process_memory_slice(
        process: HANDLE,
        base: *const c_void,
        size: usize,
    ) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut bytes_read = 0usize;
        let ret = unsafe {
            ReadProcessMemory(process, base, buf.as_mut_ptr() as *mut c_void, size, Some(&mut bytes_read))
        };
        if ret.is_err() || bytes_read < size {
            return None;
        }
        Some(buf)
    }

    /// Helper: lee una struct T de la memoria de un proceso remoto.
    fn read_process_memory_typed<T>(process: HANDLE, base: *const c_void) -> Option<T> {
        let mut val: T = unsafe { std::mem::zeroed() };
        let mut bytes_read = 0usize;
        let ret = unsafe {
            ReadProcessMemory(
                process,
                base,
                &mut val as *mut T as *mut c_void,
                std::mem::size_of::<T>(),
                Some(&mut bytes_read),
            )
        };
        if ret.is_err() || bytes_read < std::mem::size_of::<T>() {
            return None;
        }
        Some(val)
    }

    /// Abre un proceso por PID y lee su línea de comandos vía PEB.
    pub fn read_process_command_line_by_pid(pid: u32) -> Option<String> {
        let h = match open_process_for_peb(pid) {
            Ok(h) if !h.is_invalid() => h,
            _ => return None,
        };
        let cmdline = read_remote_command_line(h);
        let _ = unsafe { CloseHandle(h) };
        cmdline
    }

    /// Abre un proceso por PID y lee su CWD vía PEB.
    pub fn read_process_cwd_by_pid(pid: u32) -> String {
        let h = match open_process_for_peb(pid) {
            Ok(h) if !h.is_invalid() => h,
            _ => return String::new(),
        };
        let cwd = read_remote_cwd(h);
        let _ = unsafe { CloseHandle(h) };
        cwd
    }

    // ── AppContainer / LPAC bindings (userenv.dll + kernel32.dll) ──

    /// Security Capabilities structure for AppContainer process creation.
    #[repr(C)]
    pub struct SecurityCapabilities {
        pub app_container_sid: *mut c_void, // PSID
        pub capabilities: *mut SidAndAttributes,
        pub capability_count: u32,
        pub reserved: u32,
    }

    #[repr(C)]
    pub struct SidAndAttributes {
        pub sid: *mut c_void, // PSID
        pub attributes: u32,
    }

    /// PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20010
    pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x20010;

    #[link(name = "userenv")]
    extern "system" {
        pub fn CreateAppContainerProfile(
            app_container_name: *const u16,
            display_name: *const u16,
            description: *const u16,
            capabilities: *const SidAndAttributes,
            capability_count: u32,
            app_container_sid: *mut *mut c_void,
        ) -> i32; // HRESULT

        #[allow(dead_code)]
        pub fn DeleteAppContainerProfile(
            app_container_name: *const u16,
        ) -> i32;

        pub fn DeriveAppContainerSidFromAppContainerName(
            app_container_name: *const u16,
            app_container_sid: *mut *mut c_void,
        ) -> i32;
    }

    use windows::Win32::Security::{FreeSid, PSID};

    /// Crea o recupera un AppContainer profile.
    /// Retorna el SID y un flag indicando si ya existía.
    pub fn create_or_get_app_container(
        name: &str,
        display: &str,
    ) -> Result<(*mut c_void, bool), String> {
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let display_wide: Vec<u16> = display.encode_utf16().chain(std::iter::once(0)).collect();

        let mut sid: *mut c_void = std::ptr::null_mut();
        let hresult = unsafe {
            CreateAppContainerProfile(
                name_wide.as_ptr(),
                display_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };

        if hresult < 0 {
            // ERROR_ALREADY_EXISTS = 0x800700B7, try to derive existing SID
            if (hresult as u32) == 0x800700B7_u32.wrapping_neg() || hresult == -2147023689_i32 {
                let ret2 = unsafe {
                    DeriveAppContainerSidFromAppContainerName(name_wide.as_ptr(), &mut sid)
                };
                if ret2 < 0 {
                    return Err(format!(
                        "DeriveAppContainerSidFromAppContainerName failed: 0x{:08x}",
                        ret2 as u32
                    ));
                }
                return Ok((sid, true)); // already existed
            }
            return Err(format!(
                "CreateAppContainerProfile failed: 0x{:08x}",
                hresult as u32
            ));
        }

        Ok((sid, false)) // newly created
    }

    /// Libera un SID obtenido de CreateAppContainerProfile.
    pub fn free_app_container_sid(sid: *mut c_void) {
        if !sid.is_null() {
            unsafe { FreeSid(PSID(sid)) };
        }
    }

    /// Detecta si el sistema soporta AppContainer (Windows 8+).
    pub fn appcontainer_supported() -> bool {
        // Try to derive a well-known non-existent SID to test API availability
        let test_name: Vec<u16> = "AgentGuard.TestDetection\0"
            .encode_utf16()
            .collect();
        let mut sid: *mut c_void = std::ptr::null_mut();
        let ret = unsafe {
            DeriveAppContainerSidFromAppContainerName(test_name.as_ptr(), &mut sid)
        };
        if !sid.is_null() {
            unsafe { FreeSid(PSID(sid)) };
        }
        ret >= 0
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    /// Best-effort PEB test: reads CWD of current process.
    #[test]
    fn peb_reads_cwd_of_self() {
        let cwd = super::win32::read_process_cwd_by_pid(std::process::id());
        assert!(!cwd.is_empty(), "CWD should not be empty");
        assert!(
            std::path::Path::new(&cwd).is_absolute(),
            "CWD should be absolute: {cwd}"
        );
    }

    /// Best-effort: try to read cmdline of a spawned cmd.exe
    #[test]
    fn peb_reads_cmdline_of_child() {
        let child = std::process::Command::new("cmd.exe")
            .args(["/C", "echo", "HELLO_AGENTGUARD_TEST_12345"])
            .spawn()
            .expect("spawn cmd");
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let cmd = super::win32::read_process_command_line_by_pid(pid);
        // cmdline should contain the executable, or may be empty if process exited
        if let Some(c) = cmd {
            assert!(
                c.to_lowercase().contains("cmd") || c.contains("echo"),
                "expected cmd or echo in cmdline: {c}"
            );
        }
    }
}
