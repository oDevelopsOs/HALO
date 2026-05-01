---
trigger: glob
globs: crates/agentguard-daemon/src/ipc_server.rs,crates/agentguard-cli/**/*.rs,crates/agentguard-common/**/*.rs
description: IPC protocol contract between daemon, CLI, and UI
---

# IPC Contract

- Los enums `IpcCommand` e `IpcResponse` viven en `agentguard-common` y son el **contrato estable** entre `agentguard-daemon`, `agentguard-cli` y `agentguard-ui`.
- **Versionado del protocolo:**
  - Constante `IPC_PROTOCOL_VERSION: u32` en `agentguard-common`.
  - El handshake inicial intercambia versión; si hay mismatch, el cliente imprime error claro y sale con código 2.
  - Bumps:
    - **Minor** (backward-compatible): añadir variantes nuevas con `#[serde(other)]` en el lado del receptor.
    - **Major** (breaking): renombrar/eliminar variantes, cambiar campos. Requiere entrada en `CHANGELOG.md` bajo `## Breaking`.
- **Serialización:** JSON con `serde_json`, newline-delimited sobre el socket (`\n` separa mensajes).
- **Transporte:**
  - Linux/macOS: socket Unix en `/run/agentguard/daemon.sock` (modo servicio) o `~/.agentguard/daemon.sock` (modo usuario).
  - Windows: Named Pipe `\\.\pipe\AgentGuard`.
  - Crate: `interprocess`.
- **Errores:** variante `IpcResponse::Error(String)` solo para errores no estructurados. Errores esperados (path not found, permission denied) tienen su propia variante tipada.
- **Autorización:** en modo servicio (daemon como root), el socket tiene permisos `0660` grupo `agentguard`. La CLI se añade al grupo durante la instalación.
- **No serializar secretos:** los `IpcResponse` nunca contienen valores de secretos DLP, solo metadata.
