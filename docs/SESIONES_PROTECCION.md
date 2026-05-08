# HALO — Diario de Implementación de Protección

> Mayo 2026. Registro completo de todo lo implementado, intentado y aprendido sobre la protección de archivos, red y sandbox en AgentGuard.

---

## 1. Arquitectura de Protección

AgentGuard protege en 3 capas independientes:

```
┌─────────────────────────────────────────────────────┐
│ CAPA 1: eBPF LSM (kernel)                          │
│ - Bloquea rm/rename/write/truncate en dirs protegidos│
│ - NO mata procesos, NO interfiere con el workflow   │
│ - Responde -EPERM a nivel syscall                   │
├─────────────────────────────────────────────────────┤
│ CAPA 2: DLP Proxy (userspace)                      │
│ - Inspecciona tráfico HTTP/HTTPS en 127.0.0.1:7771  │
│ - Detecta leaks de API keys, tokens, secretos       │
│ - Sanitiza/redacta (NO bloquea la conexión)         │
├─────────────────────────────────────────────────────┤
│ CAPA 3: Sandbox (bwrap) — solo bajo demanda         │
│ - agentguard launch <agente>                        │
│ - NO se activa automáticamente                      │
└─────────────────────────────────────────────────────┘
```

---

## 2. Capa 1: Protección de Archivos (eBPF LSM)

### 2.1 Historia de intentos

| Intento | Enfoque | Resultado |
|---------|---------|-----------|
| v1 | `bpf_d_path` para resolver paths | ❌ Verifier rechaza: "helper call not allowed in probe" |
| v2 | Inodo-based (`(dev << 32) \| ino`) | ✅ Funciona en 9 hooks LSM |

### 2.2 Implementación final: Protección por inodo

**Archivos clave:**
- `crates/agentguard-ebpf/src/file_guard.rs` — 13 hooks LSM
- `crates/agentguard-linux/src/guard/ebpf.rs` — userspace loader
- `crates/agentguard-core/src/config.rs` — expande `~` automáticamente

**Flujo:**
```
1. Daemon arranca (root vía sudo)
2. Lee config: protected_dirs = ["~/Documents", "~/Projects", ...]
3. expand_tilde("~/Documents") → /home/nini/Documents  (SUDO_USER=nini)
4. stat(/home/nini/Documents) → (dev=0x10302, ino=123456)
5. Sube key = (dev << 32) | ino al BPF map PROTECTED_DIR_INODES
6. En kernel: file_unlink(dir_inode, dentry)
   - Lee dir_inode->i_ino + dir_inode->i_sb->s_dev
   - Busca en PROTECTED_DIR_INODES
   - Si match → -EPERM
```

**Hooks LSM cargados (9 de 13):**

| Hook | Estado | Qué protege |
|------|--------|-------------|
| file_unlink | ✅ | Borrar archivos |
| inode_rmdir | ✅ | Borrar directorios |
| inode_rename | ✅ | Renombrar (src+dst) |
| file_rename | ❌ | Verifier BTF |
| file_open | ✅ | Abrir archivos protegidos |
| file_truncate | ❌ | Verifier ring buffer overflow |
| inode_symlink | ✅ | Crear symlinks |
| inode_create | ✅ | Crear archivos |
| inode_mkdir | ✅ | Crear directorios |
| inode_mknod | ✅ | Crear nodos |
| inode_link | ✅ | Hard links |
| inode_setattr | ❌ | Verifier BTF |
| bprm_check_security | ❌ | "last insn is not exit" |

### 2.3 Fix crítico: SUDO_USER

**Problema:** El daemon corre como root. `dirs::home_dir()` retorna `/root`. Los paths `~/Documents` expandían a `/root/Documents` (no existe). Solo se protegía `/root/.ssh`.

**Solución:** `user_home_dir()` en `config.rs`:
```rust
fn user_home_dir() -> Option<PathBuf> {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let home = PathBuf::from("/home").join(&sudo_user);
        if home.is_dir() { return Some(home); }
    }
    dirs::home_dir()
}
```

---

## 3. Capa 2: Protección de Red

### 3.1 Historia de intentos

| Intento | Enfoque | Resultado |
|---------|---------|-----------|
| v1 | NET_RESTRICT_MODE=1 por defecto | ❌ Bloqueaba TODO: navegador, APIs, agentes |
| v2 | NET_RESTRICT_MODE=0, solo DLP | ✅ DLP inspecciona, red funciona normal |

### 3.2 Decisión final

**NO bloquear la red.** El DLP proxy en `127.0.0.1:7771` inspecciona el tráfico HTTP/HTTPS y sanitiza/redacta datos sensibles sin bloquear la conexión.

**NET_RESTRICT_MODE** queda disponible bajo demanda explícita en config:
```toml
[sandbox]
network_isolation = true  # solo si se necesita explícitamente
```

**Cambios clave:**
- `guard.rs`: `set_network_restricted(false)` tanto en recovery como en fresh load
- `sandbox.rs`: Sin `--unshare-net` en sandbox transparente
- Los programas BPF pineados de ejecuciones anteriores DEBEN limpiarse:
  ```bash
  sudo rm -rf /sys/fs/bpf/agentguard/
  ```

---

## 4. Capa 3: Sandbox (bwrap)

### 4.1 Historia de intentos

| Intento | Enfoque | Resultado |
|---------|---------|-----------|
| v1 | `launch()` full isolation | ❌ /home tmpfs, terminal no funciona, binario no encontrado |
| v2 | `launch_transparent()` | ❌ `--chdir` antes de binds, `/home` de root no del usuario |
| v3 | Sin sandbox automático | ✅ Solo bajo demanda con `agentguard launch` |

### 4.2 Decisión final

El sandbox **NO se activa automáticamente**. El modo por defecto es `"ebpf"`:
```toml
[sandbox]
modo_por_defecto = "ebpf"
```

Solo se usa bwrap con `agentguard launch <agente>` (explícito).

### 4.3 Modos de sandbox

| Modo | Descripción | Automático |
|------|-------------|------------|
| `ebpf` | eBPF a nivel kernel, cero interrupción | ✅ Default |
| `monitor` | Solo observa, no bloquea | No |
| `transparent` | bwrap con /home compartido, solo lectura en dirs protegidos | No |
| `sandbox` | bwrap con aislamiento completo | No |
| `hybrid` | bwrap + Landlock | No |

---

## 5. Detección de Agentes

### 5.1 Scanner /proc

**Archivo:** `crates/agentguard-linux/src/guard/agents.rs`

- Escanea `/proc` cada 5 segundos
- Primer escaneo: todos los agentes → `mode=monitor` (preexistentes, no se tocan)
- Escaneos subsecuentes: agentes nuevos → `mode=ebpf` (eBPF protege, no se mata)

### 5.2 Flujo de eventos

```
Scanner detecta opencode (PID=12345)
  → SecurityEvent::AgentDetected { mode: "ebpf" }
  → event loop: mode != "sandbox/transparent/hybrid" → NO sandbox
  → handle_event: loguea, NO mata
  → eBPF ya protege los archivos a nivel kernel
```

---

## 6. Smart Protection (CLI)

### 6.1 Comandos implementados

```bash
agentguard setup --smart       # Detección inteligente + aplicar
agentguard setup --smart --yes # Non-interactivo
agentguard recommend           # Solo mostrar sugerencias
agentguard recommend --json    # Salida JSON
agentguard protect --all       # Aplicar perfil recomendado
agentguard protect --group <n> # Proteger grupo específico
agentguard groups              # Listar perfiles
agentguard groups enable <n>   # Activar grupo
```

### 6.2 Motor de sugerencias

**Archivo:** `crates/agentguard-core/src/smart_protect.rs`

3 pipelines:
1. **Perfiles estáticos** (Personal, Desarrollo, Secretos, AI Workspaces)
2. **Detección de agentes AI** vía `/proc`
3. **Escaneo heurístico de secretos** (.env, .pem, id_rsa, credentials, etc.)

---

## 7. Configuración Final Recomendada

```toml
# /etc/agentguard/config.toml

[agentguard]
version = "1"

protected_dirs = [
    "/home/nini/Documents",
    "/home/nini/Projects",
    "/home/nini/.ssh",
    "/home/nini/.gnupg",
    "/home/nini/.aws",
]

protected_files = [
    "/home/nini/.env",
    "/home/nini/.netrc",
    "/home/nini/.git-credentials",
]

[sandbox]
modo_por_defecto = "ebpf"
auto_detectar_agentes = true

[dlp]
enabled = true
proxy_port = 7771
action = "sanitize"

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 6
keep_days = 30

[updates]
auto_check = true
channel = "stable"
```

---

## 8. Problemas Conocidos y Pendientes

| Problema | Estado | Detalle |
|----------|--------|---------|
| 4 hooks eBPF sin cargar | Pendiente | file_truncate (ring buffer overflow), bprm (last insn), inode_setattr + file_rename (BTF) |
| net_guard ring buffer | Pendiente | "invalid access to memory, mem_size=288 off=288 size=1" |
| DLP proxy no verificado | Pendiente | No se ha probado que efectivamente redacte API keys |
| Paths en config manual | Mitigado | Usar paths absolutos o confiar en SUDO_USER |
| `/proc/PID/cwd` symlink roto | Mitigado | Algunos procesos muestran `/proc/X/fdinfo` |
| DBus notificaciones | Cosmético | Error "Name is not activatable" en entorno sin GUI |

---

## 9. Comandos de Verificación

```bash
# Compilar eBPF
./scripts/build-ebpf.sh

# Compilar todo
cargo build --workspace --exclude agentguard-ebpf

# Tests
cargo test --workspace --exclude agentguard-ebpf

# Clippy
cargo clippy --workspace --exclude agentguard-ebpf -- -D warnings

# Limpiar programas BPF pineados (IMPORTANTE tras cambios en red)
sudo rm -rf /sys/fs/bpf/agentguard/

# Lanzar daemon
sudo ./target/debug/agentguard-linux

# Verificar estado
cargo run --bin agentguard -- status

# Verificar capacidades
cargo run --bin agentguard -- check
```

---

## 10. Lecciones Aprendidas

1. **Nunca matar procesos del usuario** — eBPF bloquea syscalls sin tocar el proceso
2. **Nunca bloquear la red por defecto** — DLP inspecciona, net_guard es opt-in
3. **Nunca asumir que `~` = $HOME** — cuando eres root, `~` = `/root`. Usar `SUDO_USER`
4. **bwrap es frágil** — no sirve para sandbox automático. Solo bajo demanda
5. **Los programas BPF pineados persisten** — limpiar `/sys/fs/bpf/agentguard/` tras cambios
6. **`bpf_d_path` NO funciona en LSM hooks** — usar inodos (dev, ino)
7. **El verifier de BPF es exigente** — cada hook tiene restricciones diferentes
8. **259 tests, 0 warnings** — el build es estable
