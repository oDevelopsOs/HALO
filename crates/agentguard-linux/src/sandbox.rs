//! Lanza agentes IA dentro de Bubblewrap (bwrap) con aislamiento completo.
//!
//! No requiere root. Compatible con cualquier usuario Linux con bwrap instalado.
//! El agente solo ve el directorio del proyecto + sistema readonly.
//!
//! Modos:
//! - `sandbox`: solo bwrap (namespaces + sistema de archivos aislado)
//! - `hybrid`:  bwrap + Landlock (bloquea acceso a todo excepto el proyecto)
//! - `monitor`:  sin sandbox, solo observación (para fallback)

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

use agentguard_core::config::Config;

pub struct SandboxLauncher {
    config: Config,
}

impl SandboxLauncher {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Lanza un agente IA dentro de bwrap con aislamiento completo.
    ///
    /// # Argumentos
    /// - `agent_exe`: nombre del ejecutable (se busca en PATH)
    /// - `project_dir`: directorio de trabajo del agente
    /// - `with_landlock`: si true, activa también Landlock (modo hybrid)
    ///
    /// # Retorna
    /// El PID del proceso sandboxeado.
    pub async fn launch(
        &self,
        agent_exe: &str,
        project_dir: &Path,
        with_landlock: bool,
    ) -> Result<u32, anyhow::Error> {
        // Verificar que bwrap está instalado
        let bwrap_path = which::which("bwrap").map_err(|_| {
            anyhow::anyhow!(
                "bwrap not found — install with: sudo apt install bubblewrap"
            )
        })?;

        // Resolver la ruta real del agente
        let agent_path = which::which(agent_exe).map_err(|_| {
            anyhow::anyhow!("executable '{}' not found in PATH", agent_exe)
        })?;

        let mut cmd = Command::new(&bwrap_path);

        // ── Sistema de archivos base (readonly) ─────────────────────────────
        for dir in &["/usr", "/lib", "/lib64"] {
            let p = PathBuf::from(dir);
            if p.exists() {
                cmd.args(["--ro-bind", dir, dir]);
            }
        }
        if Path::new("/etc/ssl").exists() {
            cmd.args(["--ro-bind", "/etc/ssl", "/etc/ssl"]);
        }
        if Path::new("/etc/resolv.conf").exists() {
            cmd.args(["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]);
        }

        // Directorios temporales aislados
        cmd.args(["--tmpfs", "/tmp"]);
        cmd.args(["--tmpfs", "/var/tmp"]);
        cmd.args(["--tmpfs", "/home"]);
        cmd.args(["--tmpfs", "/root"]);

        // proc y dev mínimos
        cmd.args(["--proc", "/proc"]);
        cmd.args(["--dev", "/dev"]);

        // ── Proyecto: lectura/escritura ──────────────────────────────────────
        let project_str = project_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid project path (non-UTF8)"))?;

        // Montar el proyecto en /workspace Y en su ruta original
        cmd.args(["--bind", project_str, "/workspace"]);
        cmd.args(["--bind", project_str, project_str]);

        // ── Binario del agente ───────────────────────────────────────────────
        let agent_str = agent_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid agent path (non-UTF8)"))?;
        cmd.args(["--ro-bind", agent_str, agent_str]);

        // ── Aislamiento de namespaces ────────────────────────────────────────
        // NOTA: NO usamos --unshare-net para que el DLP proxy funcione
        cmd.args([
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-user",
        ]);

        if self.config.sandbox.morir_con_padre {
            cmd.arg("--die-with-parent");
        }
        cmd.arg("--new-session");

        // ── Directorio de trabajo ────────────────────────────────────────────
        cmd.args(["--chdir", "/workspace"]);

        // ── Binds adicionales del config ─────────────────────────────────────
        for extra in &self.config.sandbox.bwrap_extra_args {
            cmd.arg(extra);
        }

        // ── Landlock (modo hybrid) ───────────────────────────────────────────
        // Pasamos variable de entorno que un wrapper interpreta
        if with_landlock {
            cmd.env("AGENTGUARD_LANDLOCK", "1");
            cmd.env("AGENTGUARD_LANDLOCK_RW", project_str);
        }

        // ── Variables de entorno ─────────────────────────────────────────────
        // Inyectar el proxy DLP
        let proxy_url = format!("http://127.0.0.1:{}", self.config.dlp.proxy_port);
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);

        // Marcar que el proceso fue lanzado por AgentGuard
        cmd.env("AGENTGUARD_SANDBOXED", "1");

        // ── El ejecutable a lanzar ───────────────────────────────────────────
        cmd.arg("--");
        cmd.arg(agent_str);

        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        cmd.stdin(Stdio::inherit());
        cmd.current_dir(project_dir);

        tracing::info!(
            agent = %agent_exe,
            project = %project_dir.display(),
            landlock = with_landlock,
            "launching agent in sandbox"
        );

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn bwrap: {}", e))?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("failed to get sandbox PID"))?;

        // Monitorizar el proceso en background
        tokio::spawn(async move {
            let _ = child.wait().await;
            tracing::info!(pid, "sandboxed agent exited");
        });

        Ok(pid)
    }

    /// Verifica si el sistema soporta bwrap, Landlock y eBPF LSM.
    /// Llamado en el arranque del daemon.
    pub fn check_capabilities() -> SandboxCapabilities {
        SandboxCapabilities {
            bwrap_available: which::which("bwrap").is_ok(),
            landlock_available: check_landlock_support(),
            ebpf_lsm_available: check_ebpf_lsm_support(),
        }
    }
}

// ── Capacidades del sistema ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SandboxCapabilities {
    pub bwrap_available: bool,
    pub landlock_available: bool,
    pub ebpf_lsm_available: bool,
}

impl SandboxCapabilities {
    /// Determina el modo efectivo según las capacidades reales del sistema.
    pub fn effective_mode(&self, requested: &str) -> &'static str {
        match requested {
            "hybrid" if self.bwrap_available && self.landlock_available => "hybrid",
            "hybrid" | "sandbox" if self.bwrap_available => "sandbox",
            _ => "monitor",
        }
    }

    /// Reporte legible para logs y CLI.
    pub fn report(&self) -> String {
        format!(
            "bwrap={} landlock={} eBPF_LSM={}",
            if self.bwrap_available {
                "yes"
            } else {
                "no (install bubblewrap)"
            },
            if self.landlock_available {
                "yes"
            } else {
                "no (kernel >= 5.13)"
            },
            if self.ebpf_lsm_available {
                "yes"
            } else {
                "no (kernel >= 5.7 + CONFIG_BPF_LSM)"
            },
        )
    }
}

fn check_landlock_support() -> bool {
    let output = std::process::Command::new("uname").arg("-r").output();
    if let Ok(out) = output {
        if let Ok(version) = std::str::from_utf8(&out.stdout) {
            let parts: Vec<u32> = version
                .trim()
                .split('.')
                .take(2)
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() >= 2 {
                return parts[0] > 5 || (parts[0] == 5 && parts[1] >= 13);
            }
        }
    }
    false
}

fn check_ebpf_lsm_support() -> bool {
    if let Ok(lsm_list) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        return lsm_list.contains("bpf");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_mode_degradation() {
        let caps = SandboxCapabilities {
            bwrap_available: true,
            landlock_available: false,
            ebpf_lsm_available: false,
        };
        assert_eq!(caps.effective_mode("hybrid"), "sandbox");
        assert_eq!(caps.effective_mode("sandbox"), "sandbox");
        assert_eq!(caps.effective_mode("monitor"), "monitor");
    }

    #[test]
    fn monitor_fallback_when_no_bwrap() {
        let caps = SandboxCapabilities {
            bwrap_available: false,
            landlock_available: false,
            ebpf_lsm_available: false,
        };
        assert_eq!(caps.effective_mode("sandbox"), "monitor");
        assert_eq!(caps.effective_mode("hybrid"), "monitor");
    }

    #[test]
    fn hybrid_available_when_all_present() {
        let caps = SandboxCapabilities {
            bwrap_available: true,
            landlock_available: true,
            ebpf_lsm_available: true,
        };
        assert_eq!(caps.effective_mode("hybrid"), "hybrid");
    }

    #[test]
    fn report_format() {
        let caps = SandboxCapabilities {
            bwrap_available: true,
            landlock_available: false,
            ebpf_lsm_available: true,
        };
        let report = caps.report();
        assert!(report.contains("bwrap=yes"));
        assert!(report.contains("eBPF_LSM=yes"));
    }
}
