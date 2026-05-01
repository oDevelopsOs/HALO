---
trigger: always_on
description: Filesystem paths, privilege separation, and capabilities
---

# Paths and Privileges

## Ubicaciones canónicas

| Recurso | Modo servicio (root) | Modo usuario |
|---|---|---|
| Config | `/etc/agentguard/config.toml` | `~/.agentguard/config.toml` |
| Vault (snapshots) | `/var/lib/agentguard/vault/` | `~/.agentguard/vault/` |
| Logs / incidentes | `/var/log/agentguard/incidents.jsonl` | `~/.agentguard/incidents.jsonl` |
| Socket IPC | `/run/agentguard/daemon.sock` | `~/.agentguard/daemon.sock` |
| CA root (MITM) | `/var/lib/agentguard/ca/` (perms 600) | `~/.agentguard/ca/` (perms 600) |

## Reglas

- **Detectar el modo** en `main()` leyendo `geteuid()` / `RUSTUID`:
  - EUID 0 → modo servicio.
  - EUID != 0 → modo usuario (funcionalidad reducida, sin eBPF LSM).
- **En modo servicio (root) nunca escribir a `/home`**. El systemd unit usa `ProtectHome=read-only`. Los snapshots se hacen leyendo de `/home/*` y escribiendo a `/var/lib/agentguard/vault/`.
- **Capabilities** (systemd `AmbientCapabilities`):
  - `CAP_BPF` — cargar programas BPF.
  - `CAP_SYS_ADMIN` — necesario para LSM hooks y algunas operaciones BPF.
  - `CAP_NET_ADMIN` — futuro, sockets raw si se necesitan.
  - `CAP_PERFMON` — métricas de rendimiento BPF.
  - `NoNewPrivileges=true`.
- **Nunca `chmod 777`** ni `0o666`. Archivos sensibles:
  - CA root privada: `0o600`.
  - Socket IPC modo servicio: `0o660` grupo `agentguard`.
  - Config: `0o644`.
  - Incidents log: `0o640`.
- **Expansión de `~`:** siempre vía `dirs::home_dir()`, nunca `std::env::var("HOME")` sin fallback.
- **Canonicalización:** todo path recibido de configuración o IPC pasa por `std::fs::canonicalize` antes de usarse (resuelve symlinks, previene path traversal).
- **Creación de directorios:** `std::fs::create_dir_all` + `set_permissions` inmediato si el directorio es sensible.
