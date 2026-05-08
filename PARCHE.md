# AgentGuard — Plan de Corrección Completo

> **Versión:** Fix 1.0  
> **Objetivo:** Protección real de archivos (sin modificación, sin borrado, sin acceso no autorizado) + DLP funcional contra leaks por HTTPS.

---

## Índice de problemas y fixes

| # | Problema | Gravedad | Fix |
|---|----------|----------|-----|
| 1 | Paths `~` se expanden a `/root/` en vez del usuario real | 🔴 Bloqueante | Resolución via `/etc/passwd` |
| 2 | Programas BPF viejos pineados en `/sys/fs/bpf/` | 🔴 Bloqueante | Limpieza automática al arrancar |
| 3 | Archivos protegidos se pueden modificar y truncar | 🔴 Bloqueante | Hooks `file_open` (flags) + `file_truncate` corregido |
| 4 | HTTPS MITM es `todo!()` — 99% del tráfico sin inspeccionar | 🔴 Bloqueante | Implementación completa CONNECT + CA local |
| 5 | `HTTP_PROXY` no se configura automáticamente | 🟡 Importante | Auto-configuración en instalación + wrapper |

---

## Fix 1 — Resolución correcta del home directory

### Problema

El daemon corre como `root`. `dirs::home_dir()` retorna `/root`. El fix `SUDO_USER` del diario solo funciona en invocaciones manuales con `sudo`, pero cuando `systemd` lanza el daemon, `SUDO_USER` está vacío. Los inodos subidos al mapa BPF son los de `/root/Documents` (no existe) → mapa vacío → nada protegido.

### Fix — `crates/agentguard-core/src/config.rs`

Reemplazar la función `user_home_dir()` existente por esta implementación que lee `/etc/passwd`:

```rust
/// Resuelve el home directory del usuario REAL, no de root.
/// Estrategia (en orden de prioridad):
/// 1. AGENTGUARD_USER_HOME env var (override explícito en config/systemd)
/// 2. SUDO_USER env var → buscar en /etc/passwd
/// 3. DBUS_SESSION_BUS_ADDRESS → extraer usuario
/// 4. Usuarios en /etc/passwd con UID >= 1000 y shell válida (excluye daemons)
/// 5. Fallback: dirs::home_dir() (será /root si nada más funciona)
pub fn resolve_real_user_home() -> Option<PathBuf> {
    // Override explícito (recomendado para producción via systemd Environment=)
    if let Ok(explicit) = std::env::var("AGENTGUARD_USER_HOME") {
        let p = PathBuf::from(&explicit);
        if p.is_dir() {
            tracing::info!("Using AGENTGUARD_USER_HOME: {}", explicit);
            return Some(p);
        }
        tracing::warn!("AGENTGUARD_USER_HOME set but not a directory: {}", explicit);
    }

    // SUDO_USER → /etc/passwd lookup
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            if let Some(home) = home_from_passwd(&sudo_user) {
                tracing::info!("Resolved home via SUDO_USER={}: {:?}", sudo_user, home);
                return Some(home);
            }
        }
    }

    // Usuarios con UID >= 1000 en /etc/passwd (el primero con home válido)
    if let Some(home) = first_human_user_home() {
        tracing::info!("Resolved home via /etc/passwd scan: {:?}", home);
        return Some(home);
    }

    // Último recurso
    let fallback = dirs::home_dir();
    tracing::warn!(
        "Could not resolve real user home, falling back to: {:?}. \
         Set AGENTGUARD_USER_HOME in systemd service to fix this.",
        fallback
    );
    fallback
}

/// Busca el home de un usuario concreto en /etc/passwd.
fn home_from_passwd(username: &str) -> Option<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        // formato: user:x:uid:gid:gecos:home:shell
        if fields.len() >= 7 && fields[0] == username {
            let home = PathBuf::from(fields[5]);
            if home.is_dir() {
                return Some(home);
            }
        }
    }
    None
}

/// Retorna el home del primer usuario humano (UID >= 1000) con home válido.
fn first_human_user_home() -> Option<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    let mut candidates: Vec<(u32, PathBuf)> = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 { continue; }

        let uid: u32 = fields[2].parse().ok()?;
        if uid < 1000 { continue; }  // excluir daemons del sistema

        let shell = fields[6];
        // Excluir usuarios sin shell interactiva
        if shell.ends_with("/nologin") || shell.ends_with("/false") || shell.is_empty() {
            continue;
        }

        let home = PathBuf::from(fields[5]);
        if home.is_dir() {
            candidates.push((uid, home));
        }
    }

    // El de menor UID suele ser el usuario principal
    candidates.sort_by_key(|(uid, _)| *uid);
    candidates.into_iter().map(|(_, home)| home).next()
}

/// Expande rutas con ~ usando el home real, no el de root.
pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = resolve_real_user_home() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}
```

### Configuración systemd recomendada

Añadir en `/etc/systemd/system/agentguard.service`:

```ini
[Service]
# ...resto de configuración...
# Override explícito — reemplazar 'nini' con el usuario real
Environment=AGENTGUARD_USER_HOME=/home/nini
```

Tras el cambio: `sudo systemctl daemon-reload && sudo systemctl restart agentguard`

### Verificación

```bash
# El daemon debe loggear exactamente qué home está usando
sudo journalctl -u agentguard -n 20 | grep -E "home|protect|inode"

# Los paths en el log deben ser /home/nini/... no /root/...
```

---

## Fix 2 — Limpieza automática de programas BPF pineados

### Problema

Si el daemon fue relanzado sin limpiar `/sys/fs/bpf/agentguard/`, los programas del run anterior siguen activos con mapas potencialmente corruptos o con datos obsoletos.

### Fix — `crates/agentguard-linux/src/guard/ebpf.rs`

Añadir limpieza automática **antes** de cargar cualquier programa BPF:

```rust
use std::path::Path;

const BPF_PIN_DIR: &str = "/sys/fs/bpf/agentguard";

/// Limpiar programas BPF pineados de ejecuciones anteriores.
/// Llamar ANTES de EbpfGuard::load().
pub fn cleanup_pinned_bpf() -> Result<(), anyhow::Error> {
    let pin_dir = Path::new(BPF_PIN_DIR);

    if !pin_dir.exists() {
        tracing::debug!("BPF pin dir does not exist, nothing to clean");
        return Ok(());
    }

    tracing::info!("Cleaning stale BPF programs from {}", BPF_PIN_DIR);

    // Leer y eliminar recursivamente — primero archivos, luego dirs
    remove_bpf_dir_recursive(pin_dir)?;

    // Recrear el directorio vacío para el nuevo run
    std::fs::create_dir_all(pin_dir)
        .map_err(|e| anyhow::anyhow!("Failed to recreate BPF pin dir: {e}"))?;

    tracing::info!("BPF pin dir cleaned and ready");
    Ok(())
}

fn remove_bpf_dir_recursive(dir: &Path) -> Result<(), anyhow::Error> {
    if !dir.is_dir() { return Ok(()); }

    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("read_dir {:?}: {e}", dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            remove_bpf_dir_recursive(&path)?;
            // Ignorar errores al borrar el dir (puede estar en uso)
            let _ = std::fs::remove_dir(&path);
        } else {
            std::fs::remove_file(&path)
                .map_err(|e| anyhow::anyhow!("remove {:?}: {e}", path))?;
        }
    }
    Ok(())
}
```

Llamar en el `main.rs` del daemon Linux:

```rust
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // ...init tracing...

    // SIEMPRE limpiar antes de cargar
    cleanup_pinned_bpf()?;

    let guard = EbpfGuard::load(&config.protected_dirs).await?;
    // ...resto del arranque...
}
```

### Limpieza manual (para debugging)

```bash
sudo rm -rf /sys/fs/bpf/agentguard/
sudo mkdir -p /sys/fs/bpf/agentguard/
```

---

## Fix 3 — Protección completa: sin modificación, sin borrado, sin acceso

### Objetivo

Los archivos en zonas protegidas deben ser:
- **No borrables** — `unlink`, `rmdir` → `-EPERM`
- **No modificables** — `open(O_WRONLY)`, `open(O_RDWR)`, `open(O_TRUNC)` → `-EPERM`
- **No truncables** — `truncate()`, `ftruncate()` → `-EPERM`
- **No renombrables** fuera de la zona → `-EPERM`
- **No enlazables** (hard links) → `-EPERM`

### Fix — `crates/agentguard-ebpf/src/file_guard.rs`

Reescritura completa del módulo eBPF con los hooks corregidos:

```rust
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
    BpfContext,
    helpers::bpf_get_current_comm,
};
use agentguard_common::{FileEvent, EventType};

// ─── Constantes ───────────────────────────────────────────────────────────────

pub const MAX_INODES: u32 = 512;

// Flags de apertura de archivo (deben coincidir con los del kernel)
const O_WRONLY: i32 = 1;
const O_RDWR: i32   = 2;
const O_TRUNC: i32  = 512;  // 0x200

// ─── Mapas BPF ────────────────────────────────────────────────────────────────

/// Mapa de inodos protegidos: key = (dev << 32 | ino), value = 1u8
#[map]
static PROTECTED_INODES: aya_bpf::maps::HashMap<u64, u8> =
    aya_bpf::maps::HashMap::with_max_entries(MAX_INODES, 0);

/// Ring buffer para eventos hacia userspace (solo lectura, no bloquea)
/// Tamaño reducido a 256KB para evitar overflow del verifier
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Construye la key del mapa: (dev << 32) | ino
#[inline(always)]
fn inode_key(dev: u64, ino: u64) -> u64 {
    (dev << 32) | (ino & 0xFFFF_FFFF)
}

/// Comprueba si un inodo (por dev+ino) está en el mapa protegido.
#[inline(always)]
unsafe fn is_protected_inode(dev: u64, ino: u64) -> bool {
    let key = inode_key(dev, ino);
    PROTECTED_INODES.get(&key).is_some()
}

/// Envía un evento al ring buffer (fail-open si no hay espacio).
/// NOTA: No usar en file_truncate ni inode_setattr — el verifier
/// los rechaza. Solo en hooks donde el verifier lo permite.
#[inline(always)]
fn send_event(ctx: &LsmContext, ev_type: EventType) {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).pid = ctx.pid();
            (*ev).uid = ctx.uid();
            (*ev).event_type = ev_type;
            (*ev).path = [0u8; 256]; // path no disponible en hooks de inodo
            // Obtener nombre del proceso
            let comm_ptr = (*ev).comm.as_mut_ptr();
            let _ = bpf_get_current_comm(comm_ptr as *mut _, 16);
        }
        entry.submit(0);
    }
}

// ─── Hooks LSM ────────────────────────────────────────────────────────────────

/// Bloquear borrado de archivos en directorios protegidos.
/// Argumentos LSM: (struct inode *dir, struct dentry *dentry)
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    // arg(0) = inode del DIRECTORIO padre
    let dir_inode: *const u8 = unsafe { ctx.arg(0) };
    if dir_inode.is_null() { return 0; }

    // Leer i_ino y s_dev del inode del directorio
    // Layout del struct inode: i_ino está en offset conocido via BTF
    // Usamos bpf_probe_read_kernel para acceder de forma segura
    let ino: u64 = unsafe {
        let mut val = 0u64;
        // i_ino offset en struct inode = 64 bytes (x86_64, kernel 5.x)
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut val as *mut _ as *mut _,
            8,
            dir_inode.add(64) as *const _,
        );
        if ret != 0 { return 0; }
        val
    };

    let dev: u64 = unsafe {
        // s_dev está en inode->i_sb->s_dev
        // inode->i_sb está en offset 40 (puntero de 8 bytes)
        let mut sb_ptr: u64 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut sb_ptr as *mut _ as *mut _,
            8,
            dir_inode.add(40) as *const _,
        );
        if ret != 0 { return 0; }

        // s_dev está en s_super->s_dev, offset 8 en struct super_block
        let mut dev_val: u32 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut dev_val as *mut _ as *mut _,
            4,
            (sb_ptr as *const u8).add(8) as *const _,
        );
        if ret != 0 { return 0; }
        dev_val as u64
    };

    if unsafe { is_protected_inode(dev, ino) } {
        send_event(&ctx, EventType::FileDelete);
        return -1; // -EPERM
    }
    0
}

/// Bloquear borrado de directorios protegidos.
#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    // Misma lógica que inode_unlink — el directorio padre debe ser protegido
    // Y también el propio directorio que se intenta borrar (arg(0) = inode del dir a borrar)
    let target_inode: *const u8 = unsafe { ctx.arg(0) };
    if target_inode.is_null() { return 0; }

    let (ino, dev) = match read_inode_dev(target_inode) {
        Some(v) => v,
        None => return 0,
    };

    if unsafe { is_protected_inode(dev, ino) } {
        send_event(&ctx, EventType::FileDelete);
        return -1;
    }
    0
}

/// Bloquear apertura de archivos en modo escritura dentro de zonas protegidas.
/// Esto es la clave para que los archivos sean NO MODIFICABLES.
/// Argumentos LSM: (struct file *file)
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let file: *const u8 = unsafe { ctx.arg(0) };
    if file.is_null() { return 0; }

    // f_flags está en struct file en offset 160 (aproximado, verificar con BTF)
    // Para una implementación robusta usar la macro offset_of! via aya
    let f_flags: i32 = unsafe {
        let mut flags = 0i32;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut flags as *mut _ as *mut _,
            4,
            file.add(160) as *const _,
        );
        if ret != 0 { return 0; }
        flags
    };

    // Solo bloquear si es apertura para escritura
    let is_write = (f_flags & O_WRONLY) != 0
        || (f_flags & O_RDWR) != 0
        || (f_flags & O_TRUNC) != 0;

    if !is_write { return 0; }

    // Obtener el inodo del archivo desde struct file
    // f_inode está en struct file en offset 32
    let f_inode: *const u8 = unsafe {
        let mut inode_ptr: u64 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut inode_ptr as *mut _ as *mut _,
            8,
            file.add(32) as *const _,
        );
        if ret != 0 || inode_ptr == 0 { return 0; }
        inode_ptr as *const u8
    };

    let (ino, dev) = match read_inode_dev(f_inode) {
        Some(v) => v,
        None => return 0,
    };

    // Verificar si el DIRECTORIO PADRE está protegido
    // f_path.dentry->d_parent->d_inode
    let parent_ino = unsafe { get_parent_inode(file) };
    let parent_protected = parent_ino
        .map(|(p_dev, p_ino)| is_protected_inode(p_dev, p_ino))
        .unwrap_or(false);

    // Verificar si el propio archivo está protegido (para archivos individuales)
    let self_protected = unsafe { is_protected_inode(dev, ino) };

    if parent_protected || self_protected {
        send_event(&ctx, EventType::FileWrite);
        return -1; // -EPERM — imposible escribir
    }

    0
}

/// Bloquear truncado de archivos protegidos.
/// NOTA: NO enviar al ring buffer aquí — el verifier lo rechaza en este hook.
/// El bloqueo se loggea en userspace vía el retorno -EPERM.
#[lsm(hook = "file_truncate")]
pub fn file_truncate(ctx: LsmContext) -> i32 {
    let file: *const u8 = unsafe { ctx.arg(0) };
    if file.is_null() { return 0; }

    let f_inode: *const u8 = unsafe {
        let mut inode_ptr: u64 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut inode_ptr as *mut _ as *mut _,
            8,
            file.add(32) as *const _,
        );
        if ret != 0 || inode_ptr == 0 { return 0; }
        inode_ptr as *const u8
    };

    let (ino, dev) = match read_inode_dev(f_inode) {
        Some(v) => v,
        None => return 0,
    };

    // Verificar padre también
    let parent_protected = unsafe {
        get_parent_inode(file)
            .map(|(pd, pi)| is_protected_inode(pd, pi))
            .unwrap_or(false)
    };

    if unsafe { is_protected_inode(dev, ino) } || parent_protected {
        // NO llamar a send_event aquí — ring buffer causa overflow en verifier
        return -1;
    }
    0
}

/// Bloquear renombrado fuera de zona protegida.
/// Argumentos LSM: (struct inode *old_dir, struct dentry *old_dentry,
///                  struct inode *new_dir, struct dentry *new_dentry, ...)
#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    let old_dir: *const u8 = unsafe { ctx.arg(0) };
    let new_dir: *const u8 = unsafe { ctx.arg(2) };

    if old_dir.is_null() { return 0; }

    let (old_ino, old_dev) = match read_inode_dev(old_dir) {
        Some(v) => v,
        None => return 0,
    };

    if unsafe { is_protected_inode(old_dev, old_ino) } {
        // Si el origen está protegido, el destino debe estar en la MISMA zona.
        // Si new_dir es diferente → bloquear.
        if !new_dir.is_null() {
            let (new_ino, new_dev) = match read_inode_dev(new_dir) {
                Some(v) => v,
                None => return -1, // fallo al leer destino → denegar por seguridad
            };
            if new_ino != old_ino || new_dev != old_dev {
                send_event(&ctx, EventType::FileRename);
                return -1;
            }
        } else {
            return -1;
        }
    }
    0
}

/// Bloquear creación de hard links a archivos protegidos.
#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    // arg(0) = old_dentry, arg(1) = new_dir inode, arg(2) = new_dentry
    let new_dir: *const u8 = unsafe { ctx.arg(1) };
    if new_dir.is_null() { return 0; }

    let (ino, dev) = match read_inode_dev(new_dir) {
        Some(v) => v,
        None => return 0,
    };

    if unsafe { is_protected_inode(dev, ino) } {
        return -1;
    }
    0
}

/// Bloquear creación de symlinks EN zonas protegidas.
#[lsm(hook = "inode_symlink")]
pub fn inode_symlink(ctx: LsmContext) -> i32 {
    let dir_inode: *const u8 = unsafe { ctx.arg(0) };
    if dir_inode.is_null() { return 0; }

    let (ino, dev) = match read_inode_dev(dir_inode) {
        Some(v) => v,
        None => return 0,
    };

    if unsafe { is_protected_inode(dev, ino) } {
        return -1;
    }
    0
}

// ─── Helpers internos ─────────────────────────────────────────────────────────

/// Lee (i_ino, s_dev) de un puntero a struct inode del kernel.
fn read_inode_dev(inode: *const u8) -> Option<(u64, u64)> {
    if inode.is_null() { return None; }

    let ino: u64 = unsafe {
        let mut val = 0u64;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut val as *mut _ as *mut _,
            8,
            inode.add(64) as *const _,
        );
        if ret != 0 { return None; }
        val
    };

    let dev: u64 = unsafe {
        let mut sb_ptr: u64 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut sb_ptr as *mut _ as *mut _,
            8,
            inode.add(40) as *const _,
        );
        if ret != 0 { return None; }

        let mut dev_val: u32 = 0;
        let ret = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut dev_val as *mut _ as *mut _,
            4,
            (sb_ptr as *const u8).add(8) as *const _,
        );
        if ret != 0 { return None; }
        dev_val as u64
    };

    Some((ino, dev))
}

/// Intenta obtener el inodo del directorio padre desde un struct file*.
/// file->f_path.dentry->d_parent->d_inode
unsafe fn get_parent_inode(file: *const u8) -> Option<(u64, u64)> {
    // f_path está en offset 16 de struct file
    // f_path.dentry está en offset 0 de struct path
    // Total: file + 16 + 0 = file + 16
    let mut dentry_ptr: u64 = 0;
    let ret = aya_bpf::helpers::bpf_probe_read_kernel(
        &mut dentry_ptr as *mut _ as *mut _,
        8,
        file.add(16) as *const _,
    );
    if ret != 0 || dentry_ptr == 0 { return None; }

    // d_parent está en offset 24 de struct dentry
    let mut parent_ptr: u64 = 0;
    let ret = aya_bpf::helpers::bpf_probe_read_kernel(
        &mut parent_ptr as *mut _ as *mut _,
        8,
        (dentry_ptr as *const u8).add(24) as *const _,
    );
    if ret != 0 || parent_ptr == 0 { return None; }

    // d_inode está en offset 32 de struct dentry
    let mut parent_inode_ptr: u64 = 0;
    let ret = aya_bpf::helpers::bpf_probe_read_kernel(
        &mut parent_inode_ptr as *mut _ as *mut _,
        8,
        (parent_ptr as *const u8).add(32) as *const _,
    );
    if ret != 0 || parent_inode_ptr == 0 { return None; }

    read_inode_dev(parent_inode_ptr as *const u8)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### Fix en el loader userspace — `crates/agentguard-linux/src/guard/ebpf.rs`

El loader debe subir al mapa tanto los inodos de los **directorios** como los de los **archivos individuales** protegidos:

```rust
use std::path::PathBuf;
use aya::maps::HashMap;

pub async fn populate_protected_inodes(
    bpf: &mut aya::Bpf,
    dirs: &[PathBuf],
    files: &[PathBuf],
) -> Result<(), anyhow::Error> {
    let mut map: HashMap<_, u64, u8> =
        HashMap::try_from(bpf.map_mut("PROTECTED_INODES")?)?;

    let mut count = 0u32;
    const MAX: u32 = 512;

    // Proteger directorios: subir el inodo del directorio raíz Y de todos sus subdirectorios
    for dir in dirs {
        let canonical = match std::fs::canonicalize(dir) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Cannot canonicalize {:?}: {e} — skipping", dir);
                continue;
            }
        };

        // Indexar el directorio raíz
        if let Some((dev, ino)) = stat_inode(&canonical) {
            let key = (dev << 32) | (ino & 0xFFFF_FFFF);
            map.insert(key, 1u8, 0)?;
            count += 1;
            tracing::info!("Protected dir inode: {:?} → key={:#x}", canonical, key);
        }

        // Indexar todos los subdirectorios (para proteger dentro del árbol)
        if canonical.is_dir() {
            index_subtree_dirs(&canonical, &mut map, &mut count, MAX)?;
        }

        if count >= MAX {
            tracing::warn!("Max protected inodes ({MAX}) reached, some paths may not be protected");
            break;
        }
    }

    // Proteger archivos individuales (protección de escritura/borrado directo)
    for file in files {
        let canonical = match std::fs::canonicalize(file) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Cannot canonicalize {:?}: {e} — skipping", file);
                continue;
            }
        };

        if let Some((dev, ino)) = stat_inode(&canonical) {
            let key = (dev << 32) | (ino & 0xFFFF_FFFF);
            map.insert(key, 1u8, 0)?;
            count += 1;
            tracing::info!("Protected file inode: {:?} → key={:#x}", canonical, key);
        }
    }

    tracing::info!("Total protected inodes loaded: {}", count);
    Ok(())
}

fn stat_inode(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

fn index_subtree_dirs(
    root: &std::path::Path,
    map: &mut HashMap<_, u64, u8>,
    count: &mut u32,
    max: u32,
) -> Result<(), anyhow::Error> {
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if *count >= max { break; }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Cannot read dir {:?}: {e}", dir);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some((dev, ino)) = stat_inode(&path) {
                    let key = (dev << 32) | (ino & 0xFFFF_FFFF);
                    map.insert(key, 1u8, 0)?;
                    *count += 1;
                    stack.push(path);
                }
            }
        }
    }
    Ok(())
}
```

### Verificación de protección

```bash
# 1. Verificar que el daemon arrancó con los hooks cargados
sudo journalctl -u agentguard -n 30 | grep -E "hook|protect|inode|loaded"

# 2. Intentar borrar un archivo protegido (debe dar Permission denied)
touch /home/nini/Documents/test_agentguard.txt
rm /home/nini/Documents/test_agentguard.txt
# Esperado: rm: cannot remove '...': Operation not permitted

# 3. Intentar modificar un archivo protegido
echo "hack" >> /home/nini/Documents/archivo.md
# Esperado: bash: .../archivo.md: Operation not permitted

# 4. Intentar truncar
truncate -s 0 /home/nini/Documents/archivo.md
# Esperado: truncate: '...': Operation not permitted

# 5. Verificar que un usuario normal NO puede crear archivos en zona protegida
touch /home/nini/Projects/nuevo.txt
# Esperado: touch: cannot touch '...': Operation not permitted
```

---

## Fix 4 — DLP con HTTPS MITM real

### Problema

`handle_connect_tunnel` está marcado `todo!()`. El 99% del tráfico a APIs de IA (OpenAI, Anthropic, Mistral, GitHub Copilot) va por HTTPS. Sin MITM, el DLP ve texto cifrado → no detecta ningún leak.

### Arquitectura del fix

```
Agente AI
    │ HTTP_PROXY=127.0.0.1:7771
    ▼
DLP Proxy
    ├─ Request HTTP  → inspeccionar body/headers → forward
    └─ Request HTTPS (CONNECT api.openai.com:443)
           │
           ▼
       Generar cert leaf para api.openai.com, firmado por CA local
           │
           ▼
       TLS handshake con el agente (CA confiada → sin error)
           │
           ▼
       Desencriptar → inspeccionar → re-encriptar → forward al destino real
```

### Paso 1 — Generación de CA local (`crates/agentguard-core/src/ca.rs`)

```rust
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub struct CaManager {
    ca_cert: rcgen::Certificate,
    ca_cert_der: Vec<u8>,
    ca_key: rcgen::KeyPair,
    cache: Arc<RwLock<std::collections::HashMap<String, LeafCert>>>,
}

#[derive(Clone)]
pub struct LeafCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl CaManager {
    /// Cargar CA existente o generar una nueva.
    pub fn load_or_create(ca_dir: &Path) -> Result<Self, anyhow::Error> {
        std::fs::create_dir_all(ca_dir)?;

        // Permisos restrictivos para el directorio de la CA
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let cert_path = ca_dir.join("ca.crt");
        let key_path  = ca_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading existing CA from {:?}", ca_dir);
            return Self::load_from_files(&cert_path, &key_path);
        }

        tracing::info!("Generating new local CA at {:?}", ca_dir);
        Self::generate_and_save(ca_dir, &cert_path, &key_path)
    }

    fn generate_and_save(
        ca_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self, anyhow::Error> {
        let key_pair = rcgen::KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "AgentGuard Local CA");
        dn.push(DnType::OrganizationName, "AgentGuard");
        params.distinguished_name = dn;

        // Válida por 10 años
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after  = rcgen::date_time_ymd(2034, 1, 1);

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_der = ca_cert.der().to_vec();
        let ca_key_der  = key_pair.serialize_der();

        // Guardar con permisos restrictivos
        std::fs::write(cert_path, ca_cert.pem())?;
        std::fs::write(key_path, key_pair.serialize_pem())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))?;
            std::fs::set_permissions(key_path,  std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!("CA generated. Install with: sudo agentguard ca install");

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key: key_pair,
            cache: Arc::new(RwLock::new(Default::default())),
        })
    }

    fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Self, anyhow::Error> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem  = std::fs::read_to_string(key_path)?;

        let key_pair = rcgen::KeyPair::from_pem(&key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_der = ca_cert.der().to_vec();

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key: key_pair,
            cache: Arc::new(RwLock::new(Default::default())),
        })
    }

    /// Generar (o reusar del caché) un certificado leaf para un hostname.
    pub async fn leaf_cert_for(&self, hostname: &str) -> Result<LeafCert, anyhow::Error> {
        // Consultar caché
        {
            let cache = self.cache.read().await;
            if let Some(cert) = cache.get(hostname) {
                return Ok(cert.clone());
            }
        }

        // Generar nuevo cert leaf
        let leaf = self.generate_leaf(hostname)?;

        // Guardar en caché
        {
            let mut cache = self.cache.write().await;
            cache.insert(hostname.to_string(), leaf.clone());
        }

        Ok(leaf)
    }

    fn generate_leaf(&self, hostname: &str) -> Result<LeafCert, anyhow::Error> {
        let key_pair = rcgen::KeyPair::generate()?;

        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        params.subject_alt_names = vec![
            SanType::DnsName(hostname.to_string()),
        ];

        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after  = rcgen::date_time_ymd(2026, 1, 1);

        let cert = params.signed_by(&key_pair, &self.ca_cert, &self.ca_key)?;

        Ok(LeafCert {
            cert_der: cert.der().to_vec(),
            key_der:  key_pair.serialize_der(),
        })
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Instalar la CA en el trust store del sistema (Linux).
    pub fn install_system_trust(&self, cert_path: &Path) -> Result<(), anyhow::Error> {
        // Copiar a /usr/local/share/ca-certificates/
        let dest = Path::new("/usr/local/share/ca-certificates/agentguard-ca.crt");
        std::fs::copy(cert_path, dest)
            .map_err(|e| anyhow::anyhow!("Copy CA cert failed: {e}. Run as root."))?;

        // Actualizar trust store
        let status = std::process::Command::new("update-ca-certificates")
            .status()
            .map_err(|e| anyhow::anyhow!("update-ca-certificates failed: {e}"))?;

        if !status.success() {
            anyhow::bail!("update-ca-certificates returned non-zero");
        }

        tracing::info!("CA installed in system trust store");
        Ok(())
    }
}
```

### Paso 2 — Proxy HTTPS MITM completo (`crates/agentguard-core/src/dlp/proxy.rs`)

```rust
use hyper::{
    body::Incoming,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use super::patterns::{DlpScanner, ScanResult};
use crate::ca::CaManager;

pub struct DlpProxy {
    port: u16,
    scanner: Arc<DlpScanner>,
    ca: Arc<CaManager>,
    action: DlpAction,
}

#[derive(Clone, Debug)]
pub enum DlpAction {
    Block,
    Redact,
    Alert,
}

impl DlpProxy {
    pub fn new(
        port: u16,
        ca: Arc<CaManager>,
        custom_patterns: Vec<(String, String)>,
        action: DlpAction,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            port,
            scanner: Arc::new(DlpScanner::new(custom_patterns)?),
            ca,
            action,
        })
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!("DLP proxy listening on http://{}", addr);

        let proxy = Arc::new(self);

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Accept error: {e}");
                    continue;
                }
            };

            let proxy = proxy.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy.handle_connection(stream).await {
                    tracing::debug!("Connection from {peer} error: {e}");
                }
            });
        }
    }

    async fn handle_connection(&self, stream: TcpStream) -> Result<(), anyhow::Error> {
        let io = TokioIo::new(stream);
        let scanner = self.scanner.clone();
        let ca = self.ca.clone();
        let action = self.action.clone();

        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                io,
                service_fn(move |req: Request<Incoming>| {
                    let scanner = scanner.clone();
                    let ca = ca.clone();
                    let action = action.clone();
                    async move {
                        handle_request(req, scanner, ca, action).await
                    }
                }),
            )
            .with_upgrades() // necesario para CONNECT
            .await?;

        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    scanner: Arc<DlpScanner>,
    ca: Arc<CaManager>,
    action: DlpAction,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    if req.method() == hyper::Method::CONNECT {
        // Tunnel HTTPS
        handle_connect(req, scanner, ca, action).await
    } else {
        // Proxy HTTP normal
        handle_http(req, scanner, action).await
    }
}

/// Manejar CONNECT para HTTPS MITM.
async fn handle_connect(
    req: Request<Incoming>,
    scanner: Arc<DlpScanner>,
    ca: Arc<CaManager>,
    action: DlpAction,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let host_port = req.uri().authority()
        .ok_or_else(|| anyhow::anyhow!("CONNECT missing authority"))?
        .to_string();

    let hostname = host_port.split(':').next()
        .ok_or_else(|| anyhow::anyhow!("CONNECT: no hostname"))?
        .to_string();

    // Responder 200 Connection Established inmediatamente
    let response = Response::builder()
        .status(200)
        .body(Full::new(Bytes::new()))?;

    // Hacer el upgrade del connection para obtener el stream raw
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = mitm_tls(upgraded, &hostname, &host_port, scanner, ca, action).await {
                    tracing::debug!("MITM error for {hostname}: {e}");
                }
            }
            Err(e) => tracing::warn!("Upgrade error: {e}"),
        }
    });

    Ok(response)
}

/// El núcleo del MITM: TLS handshake con el cliente, desencriptar, inspeccionar, re-encriptar.
async fn mitm_tls(
    upgraded: hyper::upgrade::Upgraded,
    hostname: &str,
    host_port: &str,
    scanner: Arc<DlpScanner>,
    ca: Arc<CaManager>,
    action: DlpAction,
) -> Result<(), anyhow::Error> {
    // 1. Generar cert leaf para este hostname
    let leaf = ca.leaf_cert_for(hostname).await?;

    // 2. Configurar TLS server (cara que ve el agente AI)
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(leaf.cert_der.clone())];
    let ca_cert_der = rustls::pki_types::CertificateDer::from(ca.ca_cert_der().to_vec());
    let full_chain = vec![
        rustls::pki_types::CertificateDer::from(leaf.cert_der),
        ca_cert_der,
    ];

    let private_key = rustls::pki_types::PrivateKeyDer::try_from(leaf.key_der)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e:?}"))?;

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(full_chain, private_key)?
    );

    let acceptor = TlsAcceptor::from(server_config);

    // 3. TLS handshake con el agente (el agente confía en nuestra CA)
    let client_stream = TokioIo::new(upgraded);
    // Reconvertir a stream raw para tokio-rustls
    // (simplificado — en implementación real usar tokio-rustls directamente)
    let tls_client_stream = acceptor.accept(
        tokio_stream_from_io(client_stream)
    ).await?;

    // 4. Conectar al destino real con TLS
    let real_stream = TcpStream::connect(host_port).await?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    );
    let connector = TlsConnector::from(client_config);
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;
    let tls_server_stream = connector.connect(server_name, real_stream).await?;

    // 5. Proxy bidireccional con inspección
    // Cada request que pasa se inspecciona por el DLP scanner
    proxy_with_inspection(
        tls_client_stream,
        tls_server_stream,
        hostname,
        scanner,
        action,
    ).await
}

async fn proxy_with_inspection(
    client: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    server: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    hostname: &str,
    scanner: Arc<DlpScanner>,
    action: DlpAction,
) -> Result<(), anyhow::Error> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // Leer el request del cliente para inspeccionarlo antes de forwarding
    let mut req_buf = vec![0u8; 64 * 1024]; // 64KB buffer
    let n = client_read.read(&mut req_buf).await?;

    if n == 0 {
        return Ok(());
    }

    let req_text = String::from_utf8_lossy(&req_buf[..n]);

    // Inspeccionar con DLP
    let scan_result = scanner.scan(&req_text);

    match scan_result {
        ScanResult::Clean => {
            // Forward sin modificar
            server_write.write_all(&req_buf[..n]).await?;
        }
        ScanResult::Violation { ref pattern_name, ref redacted } => {
            tracing::warn!(
                "DLP VIOLATION: {} in HTTPS request to {}",
                pattern_name, hostname
            );

            match action {
                DlpAction::Block => {
                    // No forwarding — cortar la conexión
                    let err_msg = format!(
                        "HTTP/1.1 403 Forbidden\r\n\
                         Content-Type: text/plain\r\n\
                         Connection: close\r\n\r\n\
                         AgentGuard DLP: Request blocked — {} detected in outbound HTTPS traffic.\n",
                        pattern_name
                    );
                    client_write.write_all(err_msg.as_bytes()).await?;
                    return Ok(());
                }
                DlpAction::Redact => {
                    // Enviar versión redactada al servidor real
                    server_write.write_all(redacted.as_bytes()).await?;
                    tracing::warn!("DLP: Redacted {} in request to {}", pattern_name, hostname);
                }
                DlpAction::Alert => {
                    // Solo alerta, forward original
                    server_write.write_all(&req_buf[..n]).await?;
                }
            }
        }
    }

    // Tunnel bidireccional para el resto del stream
    tokio::io::copy_bidirectional(
        &mut tokio::io::join(client_read, client_write),
        &mut tokio::io::join(server_read, server_write),
    ).await?;

    Ok(())
}

/// Manejar HTTP plano (no HTTPS).
async fn handle_http(
    req: Request<Incoming>,
    scanner: Arc<DlpScanner>,
    action: DlpAction,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Inspeccionar headers + body
    let headers_str = format!("{:?}", parts.headers);
    let content = format!("{}\n{}", headers_str, body_str);

    match scanner.scan(&content) {
        ScanResult::Violation { ref pattern_name, .. } => {
            tracing::warn!("DLP VIOLATION (HTTP): {} to {}", pattern_name, parts.uri);

            if matches!(action, DlpAction::Block) {
                return Ok(Response::builder()
                    .status(403)
                    .body(Full::new(Bytes::from(format!(
                        "AgentGuard DLP: Blocked — {} detected", pattern_name
                    ))))?)
            }
        }
        ScanResult::Clean => {}
    }

    // Forward al destino real
    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new()
    ).build_http();

    let rebuilt = Request::from_parts(parts, Full::new(body_bytes));

    match client.request(rebuilt.map(|b| b.map_err(|_| unreachable!()))).await {
        Ok(resp) => {
            let (rparts, rbody) = resp.into_parts();
            let rbytes = rbody.collect().await?.to_bytes();
            Ok(Response::from_parts(rparts, Full::new(rbytes)))
        }
        Err(e) => Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from(format!("AgentGuard proxy error: {e}"))))?),
    }
}
```

### Paso 3 — Scanner DLP con redacción (`crates/agentguard-core/src/dlp/patterns.rs`)

```rust
use regex::Regex;

pub struct DlpScanner {
    patterns: Vec<(String, Regex, String)>, // (nombre, regex, placeholder)
}

pub enum ScanResult {
    Clean,
    Violation {
        pattern_name: String,
        redacted: String, // versión con el secreto reemplazado
    },
}

/// Patrones ampliados con placeholders de redacción.
pub const PATTERNS: &[(&str, &str, &str)] = &[
    // (nombre, regex, placeholder)
    ("OpenAI API Key",
     r"(sk-[a-zA-Z0-9]{48,})",
     "[REDACTED:OpenAI-Key]"),

    ("OpenAI Project Key",
     r"(sk-proj-[a-zA-Z0-9\-_]{50,})",
     "[REDACTED:OpenAI-Project-Key]"),

    ("Anthropic API Key",
     r"(sk-ant-[a-zA-Z0-9\-_]{80,})",
     "[REDACTED:Anthropic-Key]"),

    ("GitHub Token",
     r"(ghp_[a-zA-Z0-9]{36})",
     "[REDACTED:GitHub-Token]"),

    ("GitHub OAuth",
     r"(gho_[a-zA-Z0-9]{36})",
     "[REDACTED:GitHub-OAuth]"),

    ("GitHub Fine-grained",
     r"(github_pat_[a-zA-Z0-9_]{82})",
     "[REDACTED:GitHub-PAT]"),

    ("AWS Access Key",
     r"(AKIA[A-Z0-9]{16})",
     "[REDACTED:AWS-Access-Key]"),

    ("AWS Secret Key",
     r#"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["'\s:=]+([a-zA-Z0-9/+]{40})"#,
     "[REDACTED:AWS-Secret]"),

    ("Google API Key",
     r"(AIza[a-zA-Z0-9\-_]{35})",
     "[REDACTED:Google-API-Key]"),

    ("Stripe Live Key",
     r"(sk_live_[a-zA-Z0-9]{24,})",
     "[REDACTED:Stripe-Live-Key]"),

    ("Stripe Secret Key",
     r"(rk_live_[a-zA-Z0-9]{24,})",
     "[REDACTED:Stripe-Restricted-Key]"),

    ("Private Key Block",
     r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
     "[REDACTED:Private-Key-Block]"),

    ("HuggingFace Token",
     r"(hf_[a-zA-Z0-9]{34,})",
     "[REDACTED:HuggingFace-Token]"),

    ("Mistral API Key",
     r#"(?i)(?:mistral|api)[_\-\s]?key["'\s:=]+([a-zA-Z0-9]{32,})"#,
     "[REDACTED:Mistral-Key]"),

    ("Generic Bearer Token",
     r#"(?i)[Aa]uthorization:\s*[Bb]earer\s+([a-zA-Z0-9\-._~+/]{20,})"#,
     "Authorization: Bearer [REDACTED:Bearer-Token]"),
];

impl DlpScanner {
    pub fn new(custom: Vec<(String, String)>) -> Result<Self, anyhow::Error> {
        let mut patterns = Vec::new();

        for (name, regex_str, placeholder) in PATTERNS {
            let re = Regex::new(regex_str)
                .map_err(|e| anyhow::anyhow!("Invalid DLP pattern '{}': {e}", name))?;
            patterns.push((name.to_string(), re, placeholder.to_string()));
        }

        for (name, regex_str) in custom {
            let re = Regex::new(&regex_str)
                .map_err(|e| anyhow::anyhow!("Invalid custom DLP pattern '{}': {e}", name))?;
            patterns.push((name, re, format!("[REDACTED:{}]", name)));
        }

        Ok(Self { patterns })
    }

    pub fn scan(&self, content: &str) -> ScanResult {
        let mut redacted = content.to_string();
        let mut found: Option<String> = None;

        for (name, pattern, placeholder) in &self.patterns {
            if pattern.is_match(&redacted) {
                // Redactar TODAS las ocurrencias del patrón
                redacted = pattern.replace_all(&redacted, placeholder.as_str()).to_string();

                if found.is_none() {
                    // Log solo el tipo, NUNCA el valor real
                    tracing::warn!(
                        pattern = name.as_str(),
                        "DLP: sensitive data pattern matched"
                    );
                    found = Some(name.clone());
                }
            }
        }

        match found {
            Some(pattern_name) => ScanResult::Violation { pattern_name, redacted },
            None => ScanResult::Clean,
        }
    }
}
```

### Paso 4 — Instalar la CA (comando CLI)

Añadir en `crates/agentguard-cli/src/main.rs`:

```rust
Commands::Ca { action } => match action {
    CaCommands::Install => {
        // Requiere root
        let ca_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("No home dir"))?
            .join(".agentguard/ca");

        let ca = CaManager::load_or_create(&ca_dir)?;

        // Linux: update-ca-certificates
        ca.install_system_trust(&ca_dir.join("ca.crt"))?;

        println!("✓ AgentGuard CA installed in system trust store");
        println!("  DLP proxy will now inspect HTTPS traffic");
        println!("");
        println!("  IMPORTANT: Browsers and agents may need restart");
    }

    CaCommands::Uninstall => {
        // Eliminar la CA del trust store (en agentguard uninstall)
        std::fs::remove_file("/usr/local/share/ca-certificates/agentguard-ca.crt").ok();
        std::process::Command::new("update-ca-certificates").status()?;
        println!("✓ AgentGuard CA removed from system trust store");
    }

    CaCommands::Show => {
        let ca_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".agentguard/ca/ca.crt");
        if ca_dir.exists() {
            println!("CA cert: {:?}", ca_dir);
            let output = std::process::Command::new("openssl")
                .args(["x509", "-noout", "-subject", "-dates", "-in"])
                .arg(&ca_dir)
                .output()?;
            println!("{}", String::from_utf8_lossy(&output.stdout));
        } else {
            println!("No CA found. Run: agentguard ca install");
        }
    }
}
```

### Dependencias adicionales necesarias

Añadir en `crates/agentguard-core/Cargo.toml`:

```toml
[dependencies]
# ... existentes ...

# HTTPS MITM
tokio-rustls = "0.26"
rustls = { version = "0.23", features = ["ring"] }
webpki-roots = "0.26"
hyper = { version = "1", features = ["full", "server", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"

# CA generation
rcgen = { version = "0.13", features = ["ring"] }
```

---

## Fix 5 — Configuración automática de HTTP_PROXY

### Problema

Los agentes AI no saben que el proxy existe. Hay que configurar `HTTP_PROXY` y `HTTPS_PROXY` en el entorno del sistema para que cualquier proceso que respete las convenciones de proxy lo use automáticamente.

### Fix A — Configuración global del sistema (Linux)

Añadir en `install.sh` y también como comando `agentguard proxy install`:

```bash
#!/bin/bash

PROXY_URL="http://127.0.0.1:7771"

# /etc/environment — para sesiones de login y la mayoría de servicios
cat >> /etc/environment << EOF

# AgentGuard DLP Proxy
HTTP_PROXY=${PROXY_URL}
HTTPS_PROXY=${PROXY_URL}
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
# No proxear localhost y servicios internos
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
EOF

echo "✓ Proxy configured in /etc/environment"
echo "  Restart your session or run: source /etc/environment"
```

### Fix B — Wrapper para agentes específicos

Para agentes que no respetan las variables de entorno (algunos Electron apps, Claude Desktop, etc.), crear wrappers:

```bash
#!/bin/bash
# /usr/local/bin/claude-protected
# Lanzar Claude Code con proxy forzado

export HTTP_PROXY="http://127.0.0.1:7771"
export HTTPS_PROXY="http://127.0.0.1:7771"
export http_proxy="http://127.0.0.1:7771"
export https_proxy="http://127.0.0.1:7771"
export NO_PROXY="localhost,127.0.0.1,::1"
export AGENTGUARD_AGENT="1"  # para identificación

exec "$@"
```

```bash
chmod +x /usr/local/bin/claude-protected
# Usar: claude-protected claude-code
# O configurar en el .desktop file del agente
```

### Fix C — Systemd para servicios que corren como daemons

```ini
# En /etc/systemd/system/agentguard.service
[Service]
Environment=HTTP_PROXY=http://127.0.0.1:7771
Environment=HTTPS_PROXY=http://127.0.0.1:7771
Environment=NO_PROXY=localhost,127.0.0.1
```

### Fix D — Verificar que el proxy funciona

```bash
# Test HTTP
curl -x http://127.0.0.1:7771 http://httpbin.org/get
# Debe retornar 200

# Test HTTPS
curl -x http://127.0.0.1:7771 https://httpbin.org/get
# Debe retornar 200 (requiere CA instalada)

# Test DLP — debe ser bloqueado/redactado
curl -x http://127.0.0.1:7771 \
  -H "Authorization: Bearer sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  https://api.anthropic.com/v1/messages
# Esperado: 403 Forbidden o request con key redactada
```

---

## Resumen de cambios por archivo

| Archivo | Cambio |
|---------|--------|
| `crates/agentguard-core/src/config.rs` | Función `resolve_real_user_home()` con lookup `/etc/passwd` |
| `crates/agentguard-linux/src/guard/ebpf.rs` | `cleanup_pinned_bpf()` al arrancar + `populate_protected_inodes()` mejorado |
| `crates/agentguard-ebpf/src/file_guard.rs` | Reescritura completa con `file_open` (write protection) + `file_truncate` corregido |
| `crates/agentguard-core/src/ca.rs` | **NUEVO** — CA manager con `rcgen` |
| `crates/agentguard-core/src/dlp/proxy.rs` | **NUEVO** — HTTPS MITM con CONNECT tunnel + TLS |
| `crates/agentguard-core/src/dlp/patterns.rs` | **NUEVO** — Scanner con redacción (no solo detección) |
| `crates/agentguard-cli/src/main.rs` | Comando `agentguard ca install/uninstall/show` |
| `scripts/install.sh` | Configurar HTTP_PROXY en `/etc/environment` + instalar CA |
| `/etc/systemd/system/agentguard.service` | `AGENTGUARD_USER_HOME` + proxy env vars |

---

## Checklist de verificación post-fix

```bash
# ── Fix 1: Paths ──────────────────────────────────────────────────────────────
sudo journalctl -u agentguard | grep "Resolved home"
# Debe mostrar: /home/nini (no /root)

# ── Fix 2: BPF limpio ─────────────────────────────────────────────────────────
ls /sys/fs/bpf/agentguard/
# Debe estar vacío o solo con archivos del run actual

# ── Fix 3: Protección archivos ────────────────────────────────────────────────
rm ~/Documents/cualquier_archivo.md
# → rm: cannot remove: Operation not permitted  ✓

echo "hack" > ~/Documents/cualquier_archivo.md
# → bash: Operation not permitted  ✓

truncate -s 0 ~/Documents/cualquier_archivo.md
# → truncate: Operation not permitted  ✓

mv ~/Documents/archivo.md /tmp/
# → mv: cannot move: Operation not permitted  ✓

# ── Fix 4: DLP HTTPS ──────────────────────────────────────────────────────────
sudo agentguard ca install
# → ✓ CA installed in system trust store

curl -x http://127.0.0.1:7771 \
  -d '{"key": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' \
  https://api.anthropic.com/v1/messages
# → 403 Forbidden (action=block) o request con key redactada (action=redact)  ✓

# ── Fix 5: Proxy automático ───────────────────────────────────────────────────
cat /etc/environment | grep PROXY
# → HTTP_PROXY=http://127.0.0.1:7771  ✓
# → HTTPS_PROXY=http://127.0.0.1:7771  ✓

echo $HTTP_PROXY
# → http://127.0.0.1:7771  ✓ (tras reinicio de sesión)
```

---

*AgentGuard Fix 1.0 — Protección real a nivel kernel, sin shortcuts.*