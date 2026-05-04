//! Detección de agentes IA en Windows vía ETW (Event Tracing for Windows).
//!
//! Estrategias:
//! - `use_etw = true`:  usa ETW kernel provider `Microsoft-Windows-Kernel-Process`
//!   (EventID=1 para creación de procesos). Requiere permisos de administrador
//!   o pertenecer al grupo `Performance Log Users`.
//! - `use_etw = false`: polling vía `sysinfo` cada `polling_interval_ms`.
//!
//! En Linux, este módulo es un stub.

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};
    use windows::core::GUID;
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, WIN32_ERROR};
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
        CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
        EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
        PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, TRACE_LEVEL_INFORMATION,
        WNODE_FLAG_TRACED_GUID,
    };

    use agentguard_core::config::Config;
    use agentguard_core::SecurityEvent;

    /// GUID del proveedor del kernel para eventos de procesos.
    /// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
    const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716);

    const EVENT_ID_PROCESS_START: u16 = 1;

    pub struct ProcessWatcher {
        config: Arc<RwLock<Config>>,
        event_tx: mpsc::Sender<SecurityEvent>,
    }

    impl ProcessWatcher {
        pub fn new(config: Arc<RwLock<Config>>, event_tx: mpsc::Sender<SecurityEvent>) -> Self {
            Self { config, event_tx }
        }

        /// Inicia el consumidor ETW en un hilo dedicado.
        /// Retorna error si ETW no está disponible (fallback a polling).
        pub fn start_etw(self) -> Result<(), anyhow::Error> {
            std::thread::Builder::new()
                .name("agentguard-etw".into())
                .spawn(move || {
                    if let Err(e) = self.run_etw_session() {
                        tracing::error!("ETW session error: {}", e);
                    }
                })?;
            Ok(())
        }

        fn run_etw_session(&self) -> Result<(), anyhow::Error> {
            let session_name = "AgentGuard-ProcessWatcher\0"
                .encode_utf16()
                .collect::<Vec<u16>>();

            let buf_size = core::mem::size_of::<EVENT_TRACE_PROPERTIES>() + session_name.len() * 2;
            let mut buf = vec![0u8; buf_size];

            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            unsafe {
                (*props).Wnode.BufferSize = buf_size as u32;
                (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                (*props).Wnode.ClientContext = 1;
                (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                (*props).BufferSize = 64;
                (*props).MinimumBuffers = 4;
                (*props).MaximumBuffers = 8;
            }

            let mut session_handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE { Value: 0 };

            unsafe {
                let result = StartTraceW(
                    &mut session_handle,
                    windows::core::PCWSTR(session_name.as_ptr()),
                    props,
                );

                if result == ERROR_ALREADY_EXISTS {
                    tracing::debug!("ETW session already exists, reconnecting...");
                    ControlTraceW(
                        CONTROLTRACE_HANDLE { Value: 0 },
                        windows::core::PCWSTR(session_name.as_ptr()),
                        props,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                    StartTraceW(
                        &mut session_handle,
                        windows::core::PCWSTR(session_name.as_ptr()),
                        props,
                    )
                    .ok()?;
                } else if result != WIN32_ERROR(0) {
                    anyhow::bail!("StartTraceW failed: {:?}", result);
                }

                EnableTraceEx2(
                    session_handle,
                    &KERNEL_PROCESS_PROVIDER,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                    TRACE_LEVEL_INFORMATION as u8,
                    0x10, // WINEVENT_KEYWORD_PROCESS
                    0,
                    0,
                    None,
                )
                .ok()?;
            }

            tracing::info!("ETW session started, monitoring process creation events");

            let mut log_file = EVENT_TRACE_LOGFILEW::default();
            let session_name_w: Vec<u16> = "AgentGuard-ProcessWatcher\0".encode_utf16().collect();

            unsafe {
                log_file.LoggerName = windows::core::PWSTR(session_name_w.as_ptr() as *mut u16);
                log_file.Anonymous1.ProcessTraceMode =
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                log_file.Anonymous2.EventRecordCallback = Some(Self::event_callback);
                log_file.Context = self as *const Self as *mut std::ffi::c_void;

                let trace_handle = OpenTraceW(&mut log_file);
                if trace_handle.Value == u64::MAX {
                    anyhow::bail!("OpenTraceW failed");
                }

                ProcessTrace(&[trace_handle], None, None).ok()?;
                CloseTrace(trace_handle);
            }

            Ok(())
        }

        unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
            if record.is_null() {
                return;
            }
            let record = &*record;

            if record.EventHeader.EventDescriptor.Id != EVENT_ID_PROCESS_START {
                return;
            }

            let watcher = &*(record.UserContext as *const ProcessWatcher);

            if record.UserDataLength < 8 {
                return;
            }

            let data = std::slice::from_raw_parts(
                record.UserData as *const u8,
                record.UserDataLength as usize,
            );

            let process_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

            // ImageFileName: string UTF-16 a partir del offset 8
            let image_name = parse_wchar_string(&data[8..]);

            let is_agent = if let Ok(cfg) = watcher.config.try_read() {
                cfg.agent_detection.known_agents.iter().any(|agent| {
                    agent
                        .exe
                        .iter()
                        .any(|exe| image_name.to_lowercase().contains(&exe.to_lowercase()))
                })
            } else {
                false
            };

            if !is_agent {
                return;
            }

            let cwd = read_process_cwd(process_id);

            let tx = watcher.event_tx.clone();
            let agent_name = image_name;
            let cwd_path = std::path::PathBuf::from(&cwd);
            let _ = tx.try_send(SecurityEvent::AgentDetected {
                pid: process_id,
                agent_name,
                cwd: cwd_path,
                mode: "sandbox".into(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }
    }

    fn parse_wchar_string(data: &[u8]) -> String {
        let wchars: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&wchars)
    }

    fn read_process_cwd(_pid: u32) -> String {
        // TODO: implementar NtQueryInformationProcess + ReadProcessMemory
        // para leer RTL_USER_PROCESS_PARAMETERS.CurrentDirectory
        String::new()
    }

    // ── Polling fallback ──────────────────────────────────────────────────

    pub async fn start_polling(config: Arc<RwLock<Config>>, event_tx: mpsc::Sender<SecurityEvent>) {
        use sysinfo::Pid;
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

        let mut system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cmd(Default::default())),
        );
        let mut known_pids: HashSet<u32> = HashSet::new();

        tracing::info!("ProcessWatcher: using polling mode (500ms interval)");

        loop {
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                ProcessRefreshKind::new().with_cmd(Default::default()),
            );

            let agent_exes: Vec<String> = {
                let cfg = config.read().await;
                cfg.agent_detection
                    .known_agents
                    .iter()
                    .flat_map(|a| a.exe.iter().cloned())
                    .collect()
            };

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if known_pids.contains(&pid_u32) {
                    continue;
                }

                let exe_name = process.name().to_string_lossy().to_lowercase();
                let is_agent = agent_exes
                    .iter()
                    .any(|e| exe_name.contains(&e.to_lowercase()));

                if is_agent {
                    known_pids.insert(pid_u32);
                    let cwd = process.cwd().map(|p| p.to_path_buf()).unwrap_or_default();

                    tracing::info!(
                        agent = %exe_name,
                        pid = pid_u32,
                        "AI agent detected via polling"
                    );

                    let _ = event_tx
                        .send(SecurityEvent::AgentDetected {
                            pid: pid_u32,
                            agent_name: exe_name,
                            cwd,
                            mode: "sandbox".into(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        })
                        .await;
                }
            }

            known_pids.retain(|pid| system.process(Pid::from_u32(*pid)).is_some());

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
mod stub_impl {
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    use agentguard_core::config::Config;
    use agentguard_core::SecurityEvent;

    #[allow(dead_code)]
    pub struct ProcessWatcher;

    impl ProcessWatcher {
        pub fn new(_config: Arc<RwLock<Config>>, _event_tx: mpsc::Sender<SecurityEvent>) -> Self {
            tracing::info!("ProcessWatcher: not available on this platform (Windows only)");
            Self
        }

        pub fn start_etw(self) -> Result<(), anyhow::Error> {
            anyhow::bail!("ProcessWatcher ETW is only available on Windows")
        }

        pub async fn start_polling(
            _config: Arc<RwLock<Config>>,
            _event_tx: mpsc::Sender<SecurityEvent>,
        ) {
            tracing::info!("ProcessWatcher polling not available on this platform");
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
#[allow(unused_imports)]
pub use stub_impl::*;
