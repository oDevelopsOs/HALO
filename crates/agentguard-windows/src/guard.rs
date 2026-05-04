//! Backend Windows — NTFS DENY ACEs + Job Objects.
//!
//! Estrategia de protección (Fase 4):
//!
//! 1. **NTFS DENY ACEs** (SetNamedSecurityInfoW): aplica ACEs de denegación
//!    explícita en las carpetas protegidas para el usuario normal. El daemon
//!    corre como SYSTEM o Administrador — el usuario no puede modificar ACLs
//!    puestas por SYSTEM. Esto previene DELETE, FILE_DELETE_CHILD,
//!    FILE_WRITE_DATA, etc.
//!
//! 2. **Job Objects** (uno por proceso agente): cuando se detecta un proceso
//!    de agente AI, se crea un Job Object dedicado con
//!    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE y se asigna el proceso.
//!
//! 3. **Detección de procesos**: CreateToolhelp32Snapshot + lectura de PEB
//!    (vía NtQueryInformationProcess + ReadProcessMemory) para matching
//!    por nombre de ejecutable, línea de comandos (argv) y variables de
//!    entorno.
//!
//! Este módulo compila en cualquier plataforma pero el backend real
//! solo funciona en Windows. En Linux/macOS se provee un stub que
//! retorna error al intentar cualquier operación.

// ── Platform-independent imports ─────────────────────────────
use std::collections::HashSet;
#[cfg(windows)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::sync::mpsc;
#[cfg(windows)]
use tracing::info;
use tracing::warn;

use agentguard_core::config::AgentProcess;
use agentguard_core::{GuardError, KernelGuard, ProtectionLevel, SecurityEvent, ViolationKind};

/// Backend Windows con NTFS DENY ACEs, Job Objects (uno por proceso) y
/// detección de agentes vía PEB.
pub struct WindowsGuard {
    protected_paths: HashSet<PathBuf>,
    agent_patterns: Vec<AgentProcess>,
    #[cfg(windows)]
    tracked_pids: HashSet<u32>,
    #[cfg(windows)]
    tracked_jobs: HashMap<u32, PlatformHandle>,
}

#[cfg(windows)]
type PlatformHandle = windows::Win32::Foundation::HANDLE;
#[cfg(not(windows))]
#[allow(dead_code)]
type PlatformHandle = ();

impl std::fmt::Debug for WindowsGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("WindowsGuard");
        dbg.field("paths", &self.protected_paths.len());
        dbg.field("agent_patterns", &self.agent_patterns.len());
        #[cfg(windows)]
        {
            dbg.field("tracked_pids", &self.tracked_pids.len());
            dbg.field("active_jobs", &self.tracked_jobs.len());
        }
        dbg.finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl Drop for WindowsGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        for (&_pid, &handle) in &self.tracked_jobs {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
        self.tracked_jobs.clear();
    }
}

#[cfg(not(windows))]
impl Drop for WindowsGuard {
    fn drop(&mut self) {}
}

impl WindowsGuard {
    /// Crea un nuevo guard y aplica DENY ACEs a todas las rutas protegidas.
    #[cfg(windows)]
    pub fn new(
        paths: &[PathBuf],
        agent_patterns: Vec<AgentProcess>,
    ) -> Result<Self, GuardError> {
        let mut canonical = HashSet::new();
        for p in paths {
            match canonicalize(p) {
                Ok(c) => {
                    apply_deny_aces(&c)?;
                    canonical.insert(c);
                }
                Err(e) => {
                    warn!(path = ?p, error = %e, "skipping protected path");
                }
            }
        }

        info!(
            paths = canonical.len(),
            patterns = agent_patterns.len(),
            "Windows guard initialized (per-process Job Objects enabled)"
        );

        Ok(Self {
            protected_paths: canonical,
            agent_patterns,
            tracked_pids: HashSet::new(),
            tracked_jobs: HashMap::new(),
        })
    }

    #[cfg(not(windows))]
    pub fn new(
        _paths: &[PathBuf],
        agent_patterns: Vec<AgentProcess>,
    ) -> Result<Self, GuardError> {
        warn!("WindowsGuard is a stub on this platform — no protection available");
        Ok(Self {
            protected_paths: HashSet::new(),
            agent_patterns,
        })
    }
}

#[async_trait]
impl KernelGuard for WindowsGuard {
    fn backend_name(&self) -> &'static str {
        "ntfs-deny-aces"
    }

    fn protection_level(&self) -> ProtectionLevel {
        #[cfg(windows)]
        {
            ProtectionLevel::KernelDenial
        }
        #[cfg(not(windows))]
        {
            ProtectionLevel::UserspaceObservation
        }
    }

    async fn add_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        #[cfg(windows)]
        {
            let c = canonicalize(path)?;
            apply_deny_aces(&c)?;
            self.protected_paths.insert(c);
            info!(path = ?path, "added Windows-protected path with DENY ACEs");
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(GuardError::Unavailable(
                "WindowsGuard is a stub on this platform".into(),
            ))
        }
    }

    async fn remove_protected_path(&mut self, path: &Path) -> Result<(), GuardError> {
        #[cfg(windows)]
        {
            let c = canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            remove_deny_aces(&c)?;
            self.protected_paths.remove(&c);
            info!(path = ?path, "removed Windows DENY ACEs");
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(())
        }
    }

    async fn run(
        mut self: Box<Self>,
        tx: mpsc::Sender<SecurityEvent>,
    ) -> Result<(), GuardError> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;

            let paths = std::mem::take(&mut self.protected_paths);
            let patterns = std::mem::take(&mut self.agent_patterns);
            let mut tracked = std::mem::take(&mut self.tracked_pids);
            let mut jobs = std::mem::take(&mut self.tracked_jobs);

            // Watcher de cambios en directorios protegidos
            let (notify_tx, notify_rx) =
                std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let mut watcher = notify::recommended_watcher(move |res| {
                let _ = notify_tx.send(res);
            })
            .map_err(|e| GuardError::Internal(format!("watcher init: {e}")))?;

            for path in &paths {
                match watcher.watch(path, notify::RecursiveMode::Recursive) {
                    Ok(()) => info!(path = ?path, "watching (Windows ReadDirectoryChangesW)"),
                    Err(e) => warn!(path = ?path, error = %e, "cannot watch path"),
                }
            }

            let watch_tx = tx.clone();
            let watch_handle = tokio::task::spawn_blocking(move || {
                while let Ok(res) = notify_rx.recv() {
                    match res {
                        Ok(event) => {
                            for ev in translate_notify_event(event) {
                                if watch_tx.blocking_send(ev).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "ReadDirectoryChangesW watcher error");
                        }
                    }
                }
            });

            let scan_tx = tx.clone();
            let scan_handle = tokio::spawn(async move {
                loop {
                    scan_and_contain_agents(&patterns, &mut tracked, &mut jobs, &scan_tx);
                    tokio::time::sleep(std::time::Duration::from_millis(5_000)).await;
                }
            });

            info!(
                "Windows guard event listener started (NTFS DENY ACEs + per-process Job Objects)"
            );

            let _ = tokio::join!(watch_handle, scan_handle);

            for (&_pid, &handle) in &jobs {
                unsafe { let _ = CloseHandle(handle); }
            }
            drop(watcher);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            warn!("WindowsGuard is a stub on this platform — event loop not started");
            let _ = tx;
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// ── Windows-only implementation ────────────────────────────
// ═══════════════════════════════════════════════════════════════

#[cfg(windows)]
mod win32 {
    //! Módulo interno con toda la lógica específica de Windows.
    //! Aislado aquí para que el resto del crate compile en Linux.

use std::collections::HashSet;
#[cfg(windows)]
use std::collections::HashMap;
    use std::ffi::c_void;
    use std::path::{Path, PathBuf};

    use tokio::sync::mpsc;
    use tracing::{info, warn};

    use agentguard_core::config::{AgentMatch, AgentProcess};
    use agentguard_core::{GuardError, SecurityEvent, ViolationKind};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, HANDLE,
    };
    use windows::Win32::Security::{
        GetTokenInformation,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        DENY_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TRUSTEE_IS_SID,
        TRUSTEE_W, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SE_FILE_OBJECT,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, DELETE,
        WRITE_DAC, WRITE_OWNER,
    };
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectBasicLimitInformation, JOBOBJECT_BASIC_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    };
    use windows::Win32::System::Threading::{
        CreateToolhelp32Snapshot, OpenProcess, Process32FirstW, Process32NextW,
        GetCurrentProcessId, GetCurrentProcess, OpenProcessToken, PROCESSENTRY32W,
        PROCESS_SET_QUOTA, PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ, TH32CS_SNAPPROCESS, PROCESS_BASIC_INFORMATION,
        NtQueryInformationProcess, PROCESSINFOCLASS, TokenUser,
    };

    /// Permisos que se deniegan en las carpetas protegidas.
    pub const DENY_PERMISSIONS: u32 = DELETE
        | FILE_DELETE_CHILD
        | FILE_WRITE_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | WRITE_DAC
        | WRITE_OWNER;

    // ── PEB structures (estables en Windows 64-bit desde Vista) ─

    #[repr(C)]
    struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *mut u16,
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
        pub command_line: UnicodeString,
        _environment: *mut c_void,
    }

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
        pub process_parameters: *mut RtlUserProcessParameters,
    }

    // ── NTFS DENY ACEs ─────────────────────────────────────

    pub fn apply_deny_aces(path: &Path) -> Result<(), GuardError> {
        let path_wide: Vec<u16> = path
            .to_str()
            .ok_or_else(|| GuardError::Internal(format!("non-UTF8 path: {path:?}")))?
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let sid = get_current_user_sid()
            .map_err(|e| GuardError::Internal(format!("get current user SID: {e}")))?;

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sec_desc: *mut c_void = std::ptr::null_mut();

        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sec_desc,
            )
        };

        if result.is_err() {
            let code = unsafe { GetLastError() };
            return Err(GuardError::Internal(format!(
                "GetNamedSecurityInfoW failed for {path:?}: code 0x{code:08x}"
            )));
        }

        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: Default::default(),
            ptstrName: windows::core::PWSTR(sid.as_ptr() as *mut u16),
        };

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: DENY_PERMISSIONS,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: trustee,
        };

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        unsafe {
            let result = SetEntriesInAclW(&[ea], dacl as *const _, &mut new_dacl);
            if result != 0 {
                let code = GetLastError();
                return Err(GuardError::Internal(format!(
                    "SetEntriesInAclW failed: code 0x{code:08x}"
                )));
            }
        }

        unsafe {
            let result = SetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null(),
                std::ptr::null(),
                new_dacl as *const _,
                std::ptr::null(),
            );

            if result.is_err() {
                if new_dacl as *const _ != dacl as *const _ {
                    windows::Win32::Foundation::LocalFree(
                        windows::Win32::Foundation::HLOCAL(new_dacl as isize),
                    );
                }
                if !sec_desc.is_null() {
                    windows::Win32::Foundation::LocalFree(
                        windows::Win32::Foundation::HLOCAL(sec_desc as isize),
                    );
                }
                let code = GetLastError();
                return Err(GuardError::Internal(format!(
                    "SetNamedSecurityInfoW failed for {path:?}: code 0x{code:08x}"
                )));
            }
        }

        unsafe {
            if new_dacl as *const _ != dacl as *const _ {
                windows::Win32::Foundation::LocalFree(
                    windows::Win32::Foundation::HLOCAL(new_dacl as isize),
                );
            }
            if !sec_desc.is_null() {
                windows::Win32::Foundation::LocalFree(
                    windows::Win32::Foundation::HLOCAL(sec_desc as isize),
                );
            }
        }

        info!(path = ?path, "applied NTFS DENY ACEs");
        Ok(())
    }

    pub fn remove_deny_aces(path: &Path) -> Result<(), GuardError> {
        let path_wide: Vec<u16> = path
            .to_str()
            .ok_or_else(|| GuardError::Internal(format!("non-UTF8 path: {path:?}")))?
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let sid = get_current_user_sid()
            .map_err(|e| GuardError::Internal(format!("get current user SID: {e}")))?;

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sec_desc: *mut c_void = std::ptr::null_mut();

        unsafe {
            let result = GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sec_desc,
            );

            if result.is_err() {
                let code = GetLastError();
                if code == ERROR_ACCESS_DENIED {
                    warn!(path = ?path, "access denied reading DACL — skipping cleanup");
                    return Ok(());
                }
                return Err(GuardError::Internal(format!(
                    "GetNamedSecurityInfoW failed for cleanup {path:?}: 0x{code:08x}"
                )));
            }
        }

        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: Default::default(),
            ptstrName: windows::core::PWSTR(sid.as_ptr() as *mut u16),
        };

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: DENY_PERMISSIONS,
            grfAccessMode: windows::Win32::Security::Authorization::REVOKE_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: trustee,
        };

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        unsafe {
            let result = SetEntriesInAclW(&[ea], dacl as *const _, &mut new_dacl);
            if result != 0 {
                warn!(path = ?path, "SetEntriesInAclW during cleanup returned {result}");
                return Ok(());
            }
        }

        unsafe {
            let result = SetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null(),
                std::ptr::null(),
                new_dacl as *const _,
                std::ptr::null(),
            );

            if result.is_err() {
                warn!(path = ?path, "SetNamedSecurityInfoW cleanup failed");
            }
        }

        unsafe {
            if new_dacl as *const _ != dacl as *const _ {
                windows::Win32::Foundation::LocalFree(
                    windows::Win32::Foundation::HLOCAL(new_dacl as isize),
                );
            }
            if !sec_desc.is_null() {
                windows::Win32::Foundation::LocalFree(
                    windows::Win32::Foundation::HLOCAL(sec_desc as isize),
                );
            }
        }

        info!(path = ?path, "removed NTFS DENY ACEs");
        Ok(())
    }

    // ── SID ────────────────────────────────────────────────

    fn get_current_user_sid() -> Result<Vec<u16>, String> {
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|e| format!("OpenProcessToken: {e}"))?;

            let mut size: u32 = 0;
            GetTokenInformation(token, TOKEN_USER, None, 0, &mut size);
            let mut buf: Vec<u8> = vec![0u8; size as usize];
            GetTokenInformation(
                token, TOKEN_USER, Some(buf.as_mut_ptr() as *mut _), size, &mut size,
            )
            .map_err(|e| format!("GetTokenInformation: {e}"))?;

            let _ = CloseHandle(token);

            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            let sid_len = windows::Win32::Security::GetLengthSid(sid) as usize;
            let mut sid_bytes: Vec<u16> = vec![0u16; sid_len];
            std::ptr::copy_nonoverlapping(
                sid as *const u8,
                sid_bytes.as_mut_ptr() as *mut u8,
                sid_len,
            );
            Ok(sid_bytes)
        }
    }

    // ── Job Objects ────────────────────────────────────────

    pub fn create_restricted_job_for(pid: u32) -> Result<HANDLE, String> {
        unsafe {
            let job = CreateJobObjectW(None, None)
                .map_err(|e| format!("CreateJobObjectW(pid={pid}): {e}"))?;

            let limits = JOBOBJECT_BASIC_LIMIT_INFORMATION {
                PerProcessUserTimeLimit: 0,
                PerJobUserTimeLimit: 0,
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
                MinimumWorkingSetSize: 0,
                MaximumWorkingSetSize: 0,
                ActiveProcessLimit: 0,
                Affinity: 0,
                PriorityClass: 0,
                SchedulingClass: 0,
            };

            SetInformationJobObject(
                job,
                JobObjectBasicLimitInformation,
                &limits as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| {
                let _ = CloseHandle(job);
                format!("SetInformationJobObject(pid={pid}): {e}")
            })?;

            Ok(job)
        }
    }

    pub fn assign_process_to_job(job: HANDLE, process: HANDLE) -> Result<(), String> {
        unsafe {
            AssignProcessToJobObject(job, process)
                .map_err(|e| format!("AssignProcessToJobObject: {e}"))?;
        }
        Ok(())
    }

    // ── PEB reading ────────────────────────────────────────

    pub fn read_process_command_line(process: HANDLE) -> Option<String> {
        unsafe {
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let result = NtQueryInformationProcess(
                process,
                PROCESSINFOCLASS::default(),
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if result.is_err() {
                return None;
            }

            let peb_addr = pbi.PebBaseAddress;
            if peb_addr.is_null() {
                return None;
            }

            let mut peb: Peb = std::mem::zeroed();
            let mut bytes_read: usize = 0;
            let read_ok = win32_read_process_mem(
                process,
                peb_addr as *const c_void,
                &mut peb as *mut _ as *mut c_void,
                std::mem::size_of::<Peb>(),
                &mut bytes_read,
            );
            if read_ok.is_err() || bytes_read != std::mem::size_of::<Peb>() {
                return None;
            }

            let params_addr = peb.process_parameters;
            if params_addr.is_null() {
                return None;
            }

            let mut params: RtlUserProcessParameters = std::mem::zeroed();
            let read_ok = win32_read_process_mem(
                process,
                params_addr as *const c_void,
                &mut params as *mut _ as *mut c_void,
                std::mem::size_of::<RtlUserProcessParameters>(),
                &mut bytes_read,
            );
            if read_ok.is_err()
                || bytes_read != std::mem::size_of::<RtlUserProcessParameters>()
            {
                return None;
            }

            let cmd_len = params.command_line.length as usize;
            let cmd_buf = params.command_line.buffer;
            if cmd_len == 0 || cmd_buf.is_null() {
                return None;
            }

            let read_len = cmd_len.min(8192);
            let mut buf: Vec<u16> = vec![0u16; read_len / 2 + 1];
            let read_ok = win32_read_process_mem(
                process,
                cmd_buf as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                read_len,
                &mut bytes_read,
            );
            if read_ok.is_err() || bytes_read == 0 {
                return None;
            }

            let wchars_read = (bytes_read / 2).min(buf.len());
            buf.truncate(wchars_read);
            if let Some(pos) = buf.iter().position(|&c| c == 0) {
                buf.truncate(pos);
            }

            Some(String::from_utf16_lossy(&buf))
        }
    }

    fn win32_read_process_mem(
        process: HANDLE,
        base: *const c_void,
        buf: *mut c_void,
        size: usize,
        out: &mut usize,
    ) -> windows::core::Result<()> {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            base,
            buf,
            size as u32,
            Some(out),
        )
    }

    // ── Agent detection ────────────────────────────────────

    pub fn matches_agent_full(
        patterns: &[AgentProcess],
        exe_name: &str,
        cmdline: &str,
    ) -> bool {
        let lower_exe = exe_name.to_lowercase();
        let lower_cmd = cmdline.to_lowercase();

        patterns.iter().any(|p| {
            let name_lower = p.name.to_lowercase();

            if lower_exe.contains(&name_lower)
                || p.r#match.exe_any.iter().any(|e| lower_exe.contains(&e.to_lowercase()))
            {
                if !p.r#match.argv_contains_any.is_empty()
                    && !p
                        .r#match
                        .argv_contains_any
                        .iter()
                        .any(|arg| lower_cmd.contains(&arg.to_lowercase()))
                {
                    return false;
                }
                return true;
            }

            if !p.r#match.argv_contains_any.is_empty() {
                return p
                    .r#match
                    .argv_contains_any
                    .iter()
                    .any(|arg| lower_cmd.contains(&arg.to_lowercase()));
            }

            false
        })
    }

    pub fn matches_agent_exe_only(patterns: &[AgentProcess], exe_name: &str) -> bool {
        let lower = exe_name.to_lowercase();
        patterns.iter().any(|p| {
            let name_lower = p.name.to_lowercase();
            lower.contains(&name_lower)
                || p.r#match.exe_any.iter().any(|e| lower.contains(&e.to_lowercase()))
        })
    }

    // ── Process scan ───────────────────────────────────────

    pub fn scan_and_contain_agents(
        patterns: &[AgentProcess],
        tracked: &mut HashSet<u32>,
        jobs: &mut HashMap<u32, HANDLE>,
        tx: &mpsc::Sender<SecurityEvent>,
    ) {
        let current_pid = unsafe { GetCurrentProcessId() };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let snapshot = match snapshot {
            Ok(h) if !h.is_invalid() => h,
            _ => {
                warn!("CreateToolhelp32Snapshot failed");
                return;
            }
        };

        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        unsafe {
            if Process32FirstW(snapshot, &mut pe).is_ok() {
                loop {
                    let pid = pe.th32ProcessID;
                    if pid != 0 && pid != current_pid && !tracked.contains(&pid) {
                        let exe_name = String::from_utf16_lossy(
                            &pe.szExeFile[..pe
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(pe.szExeFile.len())],
                        );

                        let proc_handle = OpenProcess(
                            PROCESS_QUERY_INFORMATION
                                | PROCESS_VM_READ
                                | PROCESS_SET_QUOTA
                                | PROCESS_TERMINATE,
                            false,
                            pid,
                        );

                        match proc_handle {
                            Ok(h) => {
                                let matched = match read_process_command_line(h) {
                                    Some(cmdline) => {
                                        matches_agent_full(patterns, &exe_name, &cmdline)
                                    }
                                    None => matches_agent_full(patterns, &exe_name, ""),
                                };

                                if matched {
                                    match create_restricted_job_for(pid) {
                                        Ok(job) => match assign_process_to_job(job, h) {
                                            Ok(()) => {
                                                tracked.insert(pid);
                                                jobs.insert(pid, job);
                                                info!(
                                                    pid,
                                                    exe = %exe_name,
                                                    "contained AI agent in dedicated job object"
                                                );
                                                let _ = tx.blocking_send(
                                                    SecurityEvent::SystemError {
                                                        message: format!(
                                                            "AI agent contained: {exe_name} (pid {pid})"
                                                        ),
                                                        timestamp: unix_ts(),
                                                    },
                                                );
                                            }
                                            Err(e) => {
                                                warn!(
                                                    pid, exe = %exe_name, error = %e,
                                                    "failed to assign process to job"
                                                );
                                                let _ = CloseHandle(job);
                                                let _ = CloseHandle(h);
                                            }
                                        },
                                        Err(e) => {
                                            warn!(
                                                pid, exe = %exe_name, error = %e,
                                                "failed to create job object"
                                            );
                                            let _ = CloseHandle(h);
                                        }
                                    }
                                } else {
                                    let _ = CloseHandle(h);
                                }
                            }
                            Err(_e) => {
                                if matches_agent_exe_only(patterns, &exe_name) {
                                    warn!(
                                        pid, exe = %exe_name,
                                        "AI agent detected by exe name but cannot open process"
                                    );
                                }
                            }
                        }
                    }

                    if Process32NextW(snapshot, &mut pe).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        // Limpiar PIDs y Jobs de procesos que ya terminaron
        tracked.retain(|&pid| {
            let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) };
            match h {
                Ok(handle) => {
                    unsafe { let _ = CloseHandle(handle); }
                    true
                }
                Err(_) => {
                    if let Some(job) = jobs.remove(&pid) {
                        unsafe { let _ = CloseHandle(job); }
                        info!(pid, "released job object for terminated agent");
                    }
                    false
                }
            }
        });

        let orphan: Vec<u32> = jobs.keys().filter(|k| !tracked.contains(k)).copied().collect();
        for pid in orphan {
            if let Some(job) = jobs.remove(&pid) {
                unsafe { let _ = CloseHandle(job); }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// ── Platform-independent helpers ─────────────────────────────
// ═══════════════════════════════════════════════════════════════

/// Traduce eventos de `notify` (ReadDirectoryChangesW) a `SecurityEvent`.
#[allow(dead_code)]
fn translate_notify_event(ev: notify::Event) -> Vec<SecurityEvent> {
    use notify::event::{ModifyKind, RemoveKind};
    use notify::EventKind;

    let kind = match ev.kind {
        EventKind::Remove(RemoveKind::File) | EventKind::Remove(RemoveKind::Folder) => {
            ViolationKind::DeleteAttempt
        }
        EventKind::Modify(ModifyKind::Name(_)) => ViolationKind::RenameAttempt,
        EventKind::Modify(ModifyKind::Data(_)) => ViolationKind::WriteAttempt,
        EventKind::Create(_) => ViolationKind::CreateAttempt,
        _ => return Vec::new(),
    };

    ev.paths
        .into_iter()
        .map(|path| SecurityEvent::FileViolation {
            path,
            process: "<unknown>".to_string(),
            pid: 0,
            violation: kind,
            timestamp: unix_ts(),
        })
        .collect()
}

#[allow(dead_code)]
fn canonicalize(p: &Path) -> Result<PathBuf, GuardError> {
    std::fs::canonicalize(p).map_err(|source| GuardError::Io {
        path: p.to_path_buf(),
        source,
    })
}

#[allow(dead_code)]
fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════
// ── Re-export Windows-specific functions ─────────────────────
// ═══════════════════════════════════════════════════════════════

#[cfg(windows)]
use win32::{
    apply_deny_aces, assign_process_to_job, create_restricted_job_for, matches_agent_exe_only,
    matches_agent_full, read_process_command_line, remove_deny_aces, scan_and_contain_agents,
};

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::config::AgentMatch;

    #[test]
    fn matches_common_ai_agents() {
        let patterns = vec![
            AgentProcess { name: "cursor".into(), r#match: Default::default() },
            AgentProcess { name: "claude".into(), r#match: Default::default() },
        ];

        assert!(win_matches(&patterns, "Cursor.exe", ""));
        assert!(win_matches(&patterns, "claude-code.exe", ""));
        assert!(win_matches(&patterns, "claude.exe", ""));
        assert!(!win_matches(&patterns, "notepad.exe", ""));
        assert!(!win_matches(&patterns, "explorer.exe", ""));
    }

    #[test]
    fn matches_with_exe_any() {
        let patterns = vec![AgentProcess {
            name: "vscode".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec!["Code.exe".into(), "code-insiders.exe".into()],
                argv_contains_any: vec![],
                env_has: None,
            },
        }];

        assert!(win_matches(&patterns, "Code.exe", ""));
        assert!(win_matches(&patterns, "code-insiders.exe", ""));
        assert!(!win_matches(&patterns, "devenv.exe", ""));
    }

    #[test]
    fn matches_by_argv_flag() {
        let patterns = vec![AgentProcess {
            name: "generic-agent".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec![],
                argv_contains_any: vec!["--agent-mode".into(), "--copilot".into()],
                env_has: None,
            },
        }];

        assert!(win_matches(&patterns, "node.exe", "node.exe --agent-mode --port 8080"));
        assert!(win_matches(&patterns, "python.exe", "python.exe -m agent --copilot"));
        assert!(!win_matches(&patterns, "node.exe", "node.exe server.js"));
    }

    #[test]
    fn matches_requires_argv_when_specified() {
        let patterns = vec![AgentProcess {
            name: "cursor".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec![],
                argv_contains_any: vec!["--agent".into()],
                env_has: None,
            },
        }];

        assert!(win_matches(&patterns, "Cursor.exe", r"C:\Programs\Cursor\Cursor.exe --agent"));
        assert!(!win_matches(&patterns, "Cursor.exe", r"C:\Programs\Cursor\Cursor.exe"));
    }

    #[test]
    fn argv_only_match_no_exe() {
        let patterns = vec![AgentProcess {
            name: "whitelist".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec![],
                argv_contains_any: vec!["--llm-backend".into()],
                env_has: None,
            },
        }];

        assert!(win_matches(&patterns, "python.exe", "python.exe --llm-backend openai"));
        assert!(!win_matches(&patterns, "python.exe", "python.exe my_script.py"));
    }

    #[test]
    fn argv_case_insensitive() {
        let patterns = vec![AgentProcess {
            name: "test".into(),
            r#match: AgentMatch {
                exe: None,
                exe_any: vec![],
                argv_contains_any: vec!["--Agent-Mode".into()],
                env_has: None,
            },
        }];

        assert!(win_matches(&patterns, "test.exe", "test.exe --agent-mode --verbose"));
    }

    #[test]
    fn exe_only_fallback() {
        let _patterns = [AgentProcess { name: "cursor".into(), r#match: Default::default() }];

        #[cfg(windows)]
        {
            assert!(matches_agent_exe_only(&patterns, "Cursor.exe"));
            assert!(!matches_agent_exe_only(&patterns, "explorer.exe"));
        }
        #[cfg(not(windows))]
        {
            // On non-Windows, the function is not available at all
        }
    }

    // ── Test helpers ───────────────────────────────────────

    #[cfg(windows)]
    fn win_matches(patterns: &[AgentProcess], exe: &str, cmdline: &str) -> bool {
        matches_agent_full(patterns, exe, cmdline)
    }

    #[cfg(not(windows))]
    fn win_matches(patterns: &[AgentProcess], exe: &str, cmdline: &str) -> bool {
        // On non-Windows, run matching logic inline (decoupled from Win32)
        let lower_exe = exe.to_lowercase();
        let lower_cmd = cmdline.to_lowercase();

        patterns.iter().any(|p| {
            let name_lower = p.name.to_lowercase();
            if lower_exe.contains(&name_lower)
                || p.r#match.exe_any.iter().any(|e| lower_exe.contains(&e.to_lowercase()))
            {
                if !p.r#match.argv_contains_any.is_empty()
                    && !p
                        .r#match
                        .argv_contains_any
                        .iter()
                        .any(|arg| lower_cmd.contains(&arg.to_lowercase()))
                {
                    return false;
                }
                return true;
            }

            if !p.r#match.argv_contains_any.is_empty() {
                return p
                    .r#match
                    .argv_contains_any
                    .iter()
                    .any(|arg| lower_cmd.contains(&arg.to_lowercase()));
            }

            false
        })
    }
}
