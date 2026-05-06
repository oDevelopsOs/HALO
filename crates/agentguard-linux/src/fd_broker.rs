//! FD Broker — dynamic path access from inside Landlock sandbox via SCM_RIGHTS.
//!
//! When an AI agent inside a Landlock-restricted sandbox needs access to a path
//! that wasn't pre-configured, it can request the daemon to open the path
//! on its behalf. The daemon sends back the file descriptor via Unix domain
//! socket using SCM_RIGHTS ancillary data.
//!
//! ## Protocol (JSON-line over Unix socket):
//!
//!   Client → {"op":"open","path":"/home/user/repo","flags":"rw"}
//!   Server → {"status":"ok"} followed by SCM_RIGHTS fd
//!         or {"status":"denied","error":"path not in allowlist"}
//!
//! ## Limitations:
//! - Only works for dynamically-linked binaries (Electron, Node, Python)
//!   via LD_PRELOAD. Statically-linked Go binaries cannot use this.
//! - The workspace pre-provisioned approach covers 95% of use cases.
//! - This broker handles the remaining 5%: agents that clone repos or
//!   need access to paths not known at sandbox-creation time.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A request from the sandboxed agent to open a path.
#[derive(Debug, Deserialize)]
struct BrokerRequest {
    op: String,
    path: String,
    #[serde(default = "default_flags")]
    flags: String,
}

fn default_flags() -> String {
    "rw".to_string()
}

/// Response sent back to the agent.
#[derive(Debug, Serialize)]
struct BrokerResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// FD Broker that runs as part of the daemon.
pub struct FdBroker {
    socket_path: PathBuf,
    allowed_prefixes: Vec<PathBuf>,
    /// Shared list of seccomp notifier fds from sandboxed agents.
    /// Populated when agents register their USER_NOTIF fds via the broker.
    notifier_fds: Arc<std::sync::Mutex<Vec<std::os::fd::OwnedFd>>>,
}

impl FdBroker {
    /// Create a new FD broker.
    ///
    /// `allowed_prefixes` are the paths the broker is allowed to open.
    /// Requests to paths outside these prefixes are denied.
    pub fn new(socket_path: PathBuf, allowed_prefixes: Vec<PathBuf>) -> Self {
        Self {
            socket_path,
            allowed_prefixes,
            notifier_fds: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get the shared notifier fds list for the SeccompNotifier.
    pub fn notifier_fds(&self) -> Arc<std::sync::Mutex<Vec<std::os::fd::OwnedFd>>> {
        self.notifier_fds.clone()
    }

    /// Run the broker loop — accepts connections and handles requests.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        // Remove stale socket if present
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| anyhow::anyhow!("FD broker bind {}: {}", self.socket_path.display(), e))?;

        // Set restrictive permissions on the socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600));
        }

        tracing::info!(
            path = %self.socket_path.display(),
            prefixes = self.allowed_prefixes.len(),
            "FD broker started"
        );

        let broker = Arc::new(self);
        let mut connection_id: u64 = 0;

        loop {
            let (stream, _addr) = listener
                .accept()
                .map_err(|e| anyhow::anyhow!("FD broker accept: {}", e))?;

            connection_id = connection_id.wrapping_add(1);
            let broker = broker.clone();

            tokio::task::spawn_blocking(move || {
                if let Err(e) = handle_connection(&broker, stream) {
                    tracing::warn!(
                        conn = connection_id,
                        error = %e,
                        "FD broker: connection error"
                    );
                }
            });
        }
    }

    /// Check if a path is within the allowed prefixes.
    fn is_path_allowed(&self, requested: &Path) -> bool {
        if self.allowed_prefixes.is_empty() {
            return true;
        }

        // Try to canonicalize the requested path for exact comparison
        let check_path = match std::fs::canonicalize(requested) {
            Ok(c) => c,
            Err(_) => {
                // Path doesn't exist — use the raw path and resolve parent
                // For non-existent paths, check against the parent directory
                if let Some(parent) = requested.parent() {
                    match std::fs::canonicalize(parent) {
                        Ok(canon_parent) => {
                            canon_parent.join(requested.file_name().unwrap_or_default())
                        }
                        Err(_) => requested.to_path_buf(),
                    }
                } else {
                    requested.to_path_buf()
                }
            }
        };

        self.allowed_prefixes
            .iter()
            .any(|prefix| check_path.starts_with(prefix))
    }
}

/// Handle a single broker connection.
fn handle_connection(broker: &FdBroker, mut stream: UnixStream) -> Result<(), anyhow::Error> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    reader.read_line(&mut line)?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let request: BrokerRequest = serde_json::from_str(line.trim())
        .map_err(|e| anyhow::anyhow!("invalid request JSON: {}", e))?;

    match request.op.as_str() {
        "open" => handle_open(broker, &mut stream, &request),
        "register_notifier" => handle_register_notifier(broker, &mut stream),
        "ping" => {
            let resp = BrokerResponse {
                status: "ok".into(),
                error: None,
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            stream.write_all(json.as_bytes())?;
            Ok(())
        }
        _ => {
            let resp = BrokerResponse {
                status: "error".into(),
                error: Some(format!("unknown operation: {}", request.op)),
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            stream.write_all(json.as_bytes())?;
            Ok(())
        }
    }
}

/// Handle a "register_notifier" request: receive the USER_NOTIF fd
/// from the sandboxed agent's shim and add it to the notifier fd list.
fn handle_register_notifier(
    broker: &FdBroker,
    stream: &mut UnixStream,
) -> Result<(), anyhow::Error> {
    // Receive the fd via SCM_RIGHTS
    match recv_fd(stream.as_raw_fd()) {
        Ok(fd) => {
            tracing::debug!(
                fd = fd.as_raw_fd(),
                "received seccomp notifier fd from agent"
            );
            if let Ok(mut fds) = broker.notifier_fds.lock() {
                fds.push(fd);
            }
            let resp = BrokerResponse {
                status: "ok".into(),
                error: None,
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            stream.write_all(json.as_bytes())?;
        }
        Err(e) => {
            let resp = BrokerResponse {
                status: "error".into(),
                error: Some(format!("failed to receive fd: {}", e)),
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            stream.write_all(json.as_bytes())?;
        }
    }
    Ok(())
}

/// Receive a file descriptor via SCM_RIGHTS over a Unix socket.
fn recv_fd(socket_fd: std::os::fd::RawFd) -> Result<std::os::fd::OwnedFd, anyhow::Error> {
    let mut buf = [0u8; 1];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_len];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let ret = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("recvmsg SCM_RIGHTS failed: {}", err);
    }

    // Extract the fd from cmsghdr
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        anyhow::bail!("no ancillary data in recvmsg");
    }

    let cmsg_len_actual = unsafe { (*cmsg).cmsg_len };
    let min_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    if cmsg_len_actual < min_len {
        anyhow::bail!("cmsg too short");
    }

    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::c_int;
    let fd = unsafe { *data_ptr };

    // SAFETY: we now own this file descriptor
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    Ok(owned)
}

/// Handle an "open" request: open the path and send the FD via SCM_RIGHTS.
fn handle_open(
    broker: &FdBroker,
    stream: &mut UnixStream,
    request: &BrokerRequest,
) -> Result<(), anyhow::Error> {
    let path = Path::new(&request.path);

    // Security check: is the path allowed?
    if !broker.is_path_allowed(path) {
        let resp = BrokerResponse {
            status: "denied".into(),
            error: Some(format!(
                "path '{}' is not in the allowed broker prefixes",
                request.path
            )),
        };
        let mut json = serde_json::to_string(&resp)?;
        json.push('\n');
        stream.write_all(json.as_bytes())?;
        return Ok(());
    }

    // Determine open flags
    let mut open_flags = libc::O_CLOEXEC;
    open_flags |= match request.flags.as_str() {
        "rw" => libc::O_RDWR,
        "ro" => libc::O_RDONLY,
        _ => libc::O_RDONLY,
    };

    // Open the path (the daemon has full permissions, outside the sandbox)
    let path_c = std::ffi::CString::new(path.to_str().unwrap_or(""))
        .map_err(|e| anyhow::anyhow!("invalid path encoding: {}", e))?;

    let fd = unsafe { libc::open(path_c.as_ptr(), open_flags) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let resp = BrokerResponse {
            status: "error".into(),
            error: Some(format!("open failed: {}", err)),
        };
        let mut json = serde_json::to_string(&resp)?;
        json.push('\n');
        stream.write_all(json.as_bytes())?;
        return Ok(());
    }

    // Send success response + FD via SCM_RIGHTS
    let resp = BrokerResponse {
        status: "ok".into(),
        error: None,
    };
    let mut json = serde_json::to_string(&resp)?;
    json.push('\n');

    // First write the JSON response, then send the FD
    stream.write_all(json.as_bytes())?;

    // Now send the FD via SCM_RIGHTS
    send_fd(stream.as_raw_fd(), fd)?;

    // Close our copy of the fd — the client now owns it
    unsafe {
        libc::close(fd);
    }

    tracing::debug!(
        path = %request.path,
        flags = %request.flags,
        "FD broker: sent fd for path"
    );

    Ok(())
}

/// Send a file descriptor over a Unix domain socket using SCM_RIGHTS.
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<(), anyhow::Error> {
    // Dummy data byte — required by sendmsg but we send JSON separately
    let dummy = [0u8; 1];
    let iov = libc::iovec {
        iov_base: dummy.as_ptr() as *mut libc::c_void,
        iov_len: dummy.len(),
    };

    // Allocate space for ancillary data: cmsghdr + 4 bytes for the fd
    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_len];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    // Build the cmsghdr
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        anyhow::bail!("CMSG_FIRSTHDR returned null");
    }

    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
    }

    // Copy the fd into the cmsg data area
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *mut libc::c_int;
    unsafe {
        *data_ptr = fd_to_send;
    }

    // Update msg_controllen to actual used space
    msg.msg_controllen = unsafe { (*cmsg).cmsg_len };

    let ret = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("sendmsg SCM_RIGHTS failed: {}", err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_broker_request_parse() {
        let json = r#"{"op":"open","path":"/tmp/test","flags":"rw"}"#;
        let req: BrokerRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.op, "open");
        assert_eq!(req.path, "/tmp/test");
        assert_eq!(req.flags, "rw");
    }

    #[test]
    fn test_broker_request_default_flags() {
        let json = r#"{"op":"open","path":"/tmp/test"}"#;
        let req: BrokerRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.flags, "rw");
    }

    #[test]
    fn test_broker_response_serialize() {
        let resp = BrokerResponse {
            status: "ok".into(),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\""));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_broker_response_denied() {
        let resp = BrokerResponse {
            status: "denied".into(),
            error: Some("path not allowed".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"denied\""));
        assert!(json.contains("path not allowed"));
    }

    #[test]
    fn test_is_path_allowed_with_empty_prefixes() {
        let broker = FdBroker::new(PathBuf::from("/tmp/sock"), vec![]);
        let tmp = std::env::temp_dir();
        assert!(broker.is_path_allowed(&tmp));
    }

    #[test]
    fn test_is_path_allowed_with_prefix() {
        let broker = FdBroker::new(PathBuf::from("/tmp/sock"), vec![PathBuf::from("/tmp")]);
        assert!(broker.is_path_allowed(Path::new("/tmp/test123")));
        assert!(!broker.is_path_allowed(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_is_path_allowed_nonexistent_checked_by_parent() {
        let broker = FdBroker::new(PathBuf::from("/tmp/sock"), vec![PathBuf::from("/tmp")]);
        // Non-existent path under allowed prefix → allowed
        assert!(broker.is_path_allowed(Path::new("/tmp/nonexistent_agentguard_test_xyz123")));
        // Path outside allowed prefix → denied
        assert!(!broker.is_path_allowed(Path::new("/etc/nonexistent")));
    }
}
