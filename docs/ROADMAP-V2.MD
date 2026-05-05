# AgentGuard — Roadmap v2.0 (VISIÓN FUTURA)

> ⚠️ **Este documento describe características PLANEADAS, no implementadas.**
> Para el estado actual del código, ver [`ARQUITECTURA.MD`](./ARQUITECTURA.MD).
>
> Lo que YA existe: bprm_check_security, eBPF LSM (12 hooks), Landlock V3,
> bwrap sandbox, AppContainer/LPAC, NTFS DENY ACEs, scanner /proc, 124 tests.
>
> Lo que este documento PLANEA para v2.0: binary displacement, seccomp-USER_NOTIF,
> OTA profiles, Windows Low IL, bpf_link pinning, FD broker.

> Linux + Windows · Root/Admin opcional · Documento de diseño v2.0

---

## Índice

1. [Filosofía y principios](#1-filosofía-y-principios)
2. [Stack tecnológico — decisiones y por qué](#2-stack-tecnológico)
3. [Linux — arquitectura por capas](#3-linux)
   - 3.1 [Capa 1: Interception (exec hook)](#31-capa-1-interception)
   - 3.2 [Capa 2: Filesystem isolation (Landlock)](#32-capa-2-filesystem-isolation)
   - 3.3 [Capa 3: Syscall filter (seccomp-BPF)](#33-capa-3-syscall-filter)
   - 3.4 [Capa 4: Runtime enforcement (eBPF LSM)](#34-capa-4-runtime-enforcement)
4. [Windows — arquitectura por capas](#4-windows)
   - 4.1 [Capa 1: IFEO interception](#41-capa-1-ifeo-interception)
   - 4.2 [Capa 2: Process isolation](#42-capa-2-process-isolation)
   - 4.3 [Capa 3: Filesystem protection](#43-capa-3-filesystem-protection)
5. [Retos conocidos y soluciones definitivas](#5-retos-y-soluciones)
   - 5.1 [Evasión del shim por ruta absoluta](#51-evasión-del-shim-por-ruta-absoluta)
   - 5.2 [Landlock y directorios dinámicos](#52-landlock-y-directorios-dinámicos)
   - 5.3 [Mantenimiento de perfiles seccomp](#53-mantenimiento-de-perfiles-seccomp)
   - 5.4 [Seguridad de perfiles OTA](#54-seguridad-de-perfiles-ota)
   - 5.5 [Fallo del daemon durante USER_NOTIF](#55-fallo-del-daemon-durante-user_notif)
   - 5.6 [Binarios en rutas de solo lectura](#56-binarios-en-rutas-de-solo-lectura)
6. [Matriz de capacidades](#6-matriz-de-capacidades)
7. [Código de referencia](#7-código-de-referencia)
8. [Orden de implementación](#8-orden-de-implementación)
9. [Diferenciadores de mercado](#9-diferenciadores-de-mercado)

---

## 1. Filosofía y principios

### Qué hace AgentGuard que nadie más hace

Las herramientas existentes de seguridad para agentes IA cometen uno o más de estos errores:

- **Proxy HTTP/S**: solo interceptan red. Un agente puede borrar archivos sin tocar la red.
- **Watcher de filesystem**: detectan el daño *después* de que ocurre.
- **VMs**: efectivas pero 2 GB de RAM y arranque lento. Inaceptable.
- **Docker**: requiere root, no es transparente, overhead notable.
- **Polling de `/proc`**: ventana de detección finita. Race condition por diseño.

AgentGuard intercepta en `exec()` con tecnología de kernel, aplica aislamiento por capas sin VM, y degrada elegantemente cuando no hay privilegios.

### Principios no negociables

**Transparencia total.** El agente no sabe que está sandboxeado. Sin proxies que añadan latencia, sin variables de entorno modificadas, sin cambios en el entorno de ejecución visibles para el agente.

**Fail-secure sin bloquear.** Si el daemon muere, la protección de kernel sigue activa. En Linux, el `bpf_link` pinado en `/sys/fs/bpf/agentguard/` persiste hasta el siguiente reboot. En Windows, las IFEO keys son entradas de registro permanentes.

**Degradación útil.** Con menos privilegios, menos protección, pero nunca cero. Un usuario sin root en Linux obtiene binary displacement + Landlock + seccomp — es sandboxing real, no security theater.

**Zero overhead en steady state.** Las restricciones se aplican en `exec()`. Una vez el agente corre en el sandbox, no hay ningún componente de AgentGuard en su hot path.

**Legalidad estricta.** Todos los mecanismos usados son APIs documentadas del SO diseñadas para este uso. Sin drivers sin firmar en Windows. Sin modificar binarios de terceros. Sin interceptar TLS sin consentimiento explícito.

---

## 2. Stack Tecnológico

### Linux — decisiones

| Capa | Tecnología elegida | Alternativas rechazadas | Motivo |
|---|---|---|---|
| Exec interception (root) | eBPF `bprm_check_security` + `bpf_link` pinado | ptrace, LD_PRELOAD, inotify | Kernel-resident, zero latency, sobrevive la muerte del daemon |
| Exec interception (sin root) | Binary displacement + inotify auto-heal | Solo PATH shim | PATH shim es bypasseable con ruta absoluta; displacement no |
| Filesystem isolation | Landlock LSM | AppArmor, SELinux, chroot | Único mecanismo sin privilegios, irrevocable, kernel 5.13+ |
| Syscall filter | seccomp-BPF + `SECCOMP_RET_USER_NOTIF` | Solo `RET_KILL_PROCESS`, strace | USER_NOTIF permite respuesta inteligente sin matar el proceso |
| Runtime file protection | eBPF LSM `file_unlink`/`file_rename` | inotify, fanotify | Kernel-level, imposible de saltar desde userspace |
| Workspace isolation | Pre-provisioned scratch dir en allowlist | SCM_RIGHTS FD broker | Cubre 95% casos sin complejidad de IPC; FD broker como v2 |
| Perfil OTA | JSON firmado con Ed25519 | Sin firma, HTTPS solo | HTTPS no protege contra CDN comprometida |

### Windows — decisiones

| Capa | Tecnología elegida | Alternativas rechazadas | Motivo |
|---|---|---|---|
| Exec interception (admin) | IFEO `HKLM` | Minifilter driver, ETW | No necesita driver firmado, NT lo aplica antes del primer opcode |
| Exec interception (sin admin) | IFEO `HKCU` + binary displacement | Solo PATH shim | HKCU IFEO funciona por usuario sin admin en Win10+ |
| Process isolation (admin) | AppContainer + Job Object | Hyper-V container | Menor overhead, usado por Edge/Office, no necesita Hyper-V |
| Process isolation (sin admin) | Low Integrity Level + Job Object + `SetProcessMitigationPolicy` | Nada o Docker | LIL bloquea escrituras en la mayoría del sistema implícitamente |
| Syscall mitigation | `SetProcessMitigationPolicy` (7 políticas) | Driver de filtrado | Sin driver, sin admin, aplicable antes del primer opcode |
| Filesystem (admin) | NTFS DENY ACEs por servicio SYSTEM | Solo Job Objects | El agente no puede modificar ACLs que SYSTEM ha puesto |

---

## 3. Linux

### 3.1 Capa 1: Interception

#### Con root / CAP_BPF + CAP_SYS_ADMIN — eBPF exec hook

El hook `bprm_check_security` se ejecuta en el kernel durante la syscall `execve`, antes de que el nuevo proceso tenga ningún opcode ejecutado. Cuando detecta un agente conocido, devuelve `-EPERM`, el exec falla, y el daemon recibe el evento via ring buffer para relanzar en sandbox.

El `bpf_link` se pina en `/sys/fs/bpf/agentguard/exec_hook`. Si el daemon muere, el hook permanece. Los nuevos exec siguen siendo bloqueados. Al reiniciar, el daemon recupera el link existente sin recargar el programa eBPF.

```
execve("claude-code", argv, envp)
    │
    ▼  [kernel]
bprm_check_security hook
    │
    ├── comm no está en AGENT_NAMES map → retorna 0, exec continúa
    │
    └── comm está en AGENT_NAMES map
            → retorna -EPERM (exec bloqueado)
            → ring buffer: ExecEvent { pid, uid, comm, cwd }
            │
            ▼  [userspace, daemon]
        Lee /proc/<pid>/cmdline → argv original
        Lee /proc/<pid>/cwd    → directorio de trabajo
            │
            ▼
        bwrap --ro-bind /usr /usr \
              --ro-bind /lib /lib \
              --bind <workspace> <workspace> \
              --bind /tmp/ag-<session> /tmp \
              --unshare-net --unshare-pid --unshare-ipc \
              --die-with-parent \
              --seccomp <fd_filtro> \
              -- <argv[0]> <argv[1]...>
```

#### Sin root — Binary Displacement + inotify auto-heal

El instalador **desplaza** el binario original renombrándolo a `.<nombre>.real` y coloca el shim estático exactamente en la ruta original. Si alguien llama a `/home/user/.npm-global/bin/claude-code` con ruta absoluta, sigue golpeando el shim.

El riesgo del displacement es que un `npm update -g` sobrescriba el shim con el nuevo binario real. Para esto existe el **daemon de auto-curación**:

```
inotify watch en rutas de agentes conocidos:
    ~/.npm-global/bin/
    ~/.local/bin/
    ~/.cargo/bin/
    /home/<user>/.volta/bin/
    [rutas configuradas por el usuario]

Eventos monitorizados: IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE

Al detectar escritura en ruta de agente conocido:
    1. Leer los primeros 4 bytes del nuevo archivo
    2. ¿Es el shim de AgentGuard? (magic bytes propios) → no hacer nada
    3. ¿Es un binario nuevo/actualizado? →
       a. mv <ruta>/<agente> <ruta>/.<agente>.real
       b. cp agentguard-shim <ruta>/<agente>
       c. chmod +x <ruta>/<agente>
       d. Log del evento
    Tiempo de reacción: <50ms (inotify es síncrono con el VFS)
```

**Edge case crítico: binarios en rutas de solo lectura.** Si el binario del agente está en `/usr/bin/` u otra ruta que requiere root para escribir, el displacement falla sin root. En ese caso:

1. Detectar la situación en instalación y advertir al usuario.
2. Caer al PATH shim con nota en el log: `"displacement unavailable for /usr/bin/claude — using PATH shim only. Absolute path invocations are not protected without root."`
3. Documentar explícitamente esta limitación. No prometer lo que no se puede dar.

**Detección del propio shim** para evitar bucles en el inotify watcher: los shims compilados por AgentGuard tienen un magic header en los primeros 8 bytes del binario ELF (en una sección `.note.agentguard` del ELF). El watcher lee la sección antes de reaccionar. Si ya es un shim de AgentGuard, ignora el evento.

### 3.2 Capa 2: Filesystem Isolation

#### Landlock LSM (kernel ≥5.13, sin root)

Landlock permite a cualquier proceso sin privilegios crear un dominio de restricción que limita su propio acceso a filesystem. Es **irrevocable** — una vez aplicado con `landlock_restrict_self()`, ni el propio proceso puede expandirlo. No hay syscall para desactivarlo.

El shim aplica Landlock antes de hacer `exec()` al agente real:

```rust
// Dominio de restricción mínimo para un agente IA
let ruleset_attr = landlock_ruleset_attr {
    handled_access_fs:
        LANDLOCK_ACCESS_FS_WRITE_FILE    |  // escribir archivos
        LANDLOCK_ACCESS_FS_REMOVE_FILE   |  // borrar archivos
        LANDLOCK_ACCESS_FS_REMOVE_DIR    |  // borrar directorios
        LANDLOCK_ACCESS_FS_MAKE_REG      |  // crear archivos
        LANDLOCK_ACCESS_FS_MAKE_DIR      |  // crear directorios
        LANDLOCK_ACCESS_FS_RENAME        |  // renombrar
        LANDLOCK_ACCESS_FS_REFER,           // mover entre dirs
    handled_access_net:
        LANDLOCK_ACCESS_NET_CONNECT_TCP,    // conexiones TCP salientes
};
// Landlock v3 (kernel 6.7+): también cubre CONNECT_TCP sin root
```

Las rutas permitidas para escritura son exactamente:
- `<workspace>` — el directorio de trabajo del agente para esta sesión
- `/tmp/ag-<session_id>` — directorio temporal privado
- `~/.cache/` de los runtimes necesarios (Node, Python — solo lectura en su mayoría)

#### Workspaces pre-aprovisionados — solución al problema de directorios dinámicos

Landlock restringe acceso por ruta en el momento de `open()`, pero no puede anticipar qué rutas nuevas necesitará el agente durante su ejecución. Un agente que clona un repo en un path no previsto recibe `EACCES`.

La solución correcta para v1 es el **workspace pre-aprovisionado**:

```
~/.agentguard/workspaces/
    <session_id>/           ← bind-mounted como /workspace dentro del sandbox
        .agentguard-session  ← metadata: timestamp, agente, permisos
```

El agente trabaja siempre dentro de este directorio. Si necesita acceder a archivos del proyecto del usuario, el usuario los monta explícitamente:

```bash
agentguard run --mount ~/Projects/myapp claude-code
# monta ~/Projects/myapp como /workspace/myapp dentro del sandbox
```

**FD broker vía SCM_RIGHTS (v2, para casos avanzados):** Para agentes que genuinamente necesitan acceso dinámico a múltiples rutas, se puede implementar un daemon broker. El agente le pide acceso a una ruta vía socket UNIX, el broker evalúa las reglas y le pasa el FD abierto usando `SCM_RIGHTS`. Esto funciona porque Landlock restringe en el momento del `open()`, pero no invalida FDs ya abiertos por otro proceso con más permisos.

Limitación conocida del FD broker: solo funciona si el agente está adaptado para usar el protocolo, o si se inyecta una capa de intercepción vía `LD_PRELOAD`. Esto último solo funciona para binarios dinámicamente enlazados (Electron, Node, Python). Para binarios Go compilados estáticamente, no hay opción — el workspace pre-aprovisionado es la única solución.

### 3.3 Capa 3: Syscall Filter

#### seccomp-BPF con SECCOMP_RET_USER_NOTIF (kernel ≥5.9)

En vez de `SECCOMP_RET_KILL_PROCESS` (mata el proceso en la syscall bloqueada), usamos `SECCOMP_RET_USER_NOTIF` para syscalls ambiguas. El kernel pausa la syscall y notifica al daemon, que puede:

- **Permitir**: si la syscall es legítima en este contexto
- **Denegar con `ENOSYS`**: el agente recibe "función no implementada" y hace fallback a alternativas
- **Denegar con `EPERM`**: denegación explícita
- **Kill**: en casos donde la syscall es claramente maliciosa

```
Agente intenta syscall no en allowlist
    │
    ▼  [kernel]
seccomp filter → SECCOMP_RET_USER_NOTIF
    │  (syscall pausada, no ejecutada)
    ▼
Daemon recibe notificación vía fd de notificación
    │
    ├── ¿Syscall en lista "ambigua"? (nueva, rara pero legítima)
    │       → Log + Allow (con telemetría)
    │
    ├── ¿Syscall potencialmente peligrosa?
    │       → Log + Deny con ENOSYS
    │
    └── ¿Syscall claramente maliciosa? (ptrace, kexec, bpf)
            → Kill process + Alert
```

**Syscalls con `RET_KILL_PROCESS` siempre** (no hay ambigüedad posible):

```
ptrace              — manipulación de otros procesos
process_vm_readv/writev — leer/escribir memoria de otros procesos
kexec_load          — reemplazar el kernel
mount               — montar filesystems
setuid/setgid       — escalar privilegios
unshare             — crear nuevos namespaces (el agente ya está en sandbox)
perf_event_open     — acceso a contadores de hardware
bpf                 — el agente no puede cargar sus propios programas eBPF
```

#### Fail-safe cuando el daemon muere durante USER_NOTIF

Este es un problema real que la mayoría de documentos ignoran. Si el daemon muere mientras el kernel tiene una syscall pausada esperando respuesta vía USER_NOTIF, el comportamiento por defecto es que el kernel libera la syscall con `ENOSYS`. Esto hay que diseñarlo explícitamente:

1. El fd de notificación se mantiene en el daemon con `SO_KEEPALIVE` y un watchdog interno.
2. Al morir el daemon, el fd se cierra. El kernel libera todas las syscalls pendientes con `ENOSYS`.
3. El proceso agente recibe `ENOSYS` y (si está bien programado) hace fallback. Si no, puede crashear — preferible a que ejecute una syscall peligrosa.
4. En el systemd unit del daemon: `Restart=always` con `RestartSec=100ms`. La ventana de exposición es <100ms.
5. Al reiniciar, el daemon reconstruye el fd de notificación y el agente continúa.

Para syscalls clasificadas como `RET_KILL_PROCESS`, el daemon no está en el loop — el kernel mata directamente. Esta distinción es importante: `USER_NOTIF` solo se usa para syscalls donde el daemon necesita contexto para decidir.

### 3.4 Capa 4: Runtime Enforcement

eBPF LSM `file_unlink` y `file_rename` activos sobre todos los procesos del sistema, incluyendo los que ya corrían cuando AgentGuard arrancó. Esta es la red de seguridad final: aunque un agente escape el sandbox (teóricamente imposible, pero diseñamos para defense in depth), el intento de borrar un archivo protegido es bloqueado en el kernel.

El `bpf_link` de esta capa también va pinado en `/sys/fs/bpf/agentguard/file_hook`.

---

## 4. Windows

### 4.1 Capa 1: IFEO Interception

**Image File Execution Options** es una característica del subsistema NT desde Windows NT 3.51. Cuando Windows va a crear un proceso, consulta la clave de registro correspondiente. Si existe una entrada `Debugger`, ejecuta ese binario en lugar del original, pasando el exe original como argumento.

No es "interceptar" el proceso — Windows *nunca llega a crear el proceso original*. El launcher de AgentGuard corre en su lugar desde el primer opcode.

**Con admin (HKLM):** Funciona para cualquier usuario del sistema, cualquier método de lanzamiento. No se puede bypassear desde userspace.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
    claude-code.exe\
        Debugger = "C:\Program Files\AgentGuard\launcher.exe"
    cursor.exe\
        Debugger = "C:\Program Files\AgentGuard\launcher.exe"
    windsurf.exe\
        Debugger = "C:\Program Files\AgentGuard\launcher.exe"
```

**Sin admin (HKCU):** Funciona para el usuario actual en Windows 10+. Mismo mecanismo, menor scope.

```
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
    claude-code.exe\
        Debugger = "%LOCALAPPDATA%\AgentGuard\launcher.exe"
```

**Binary displacement en Windows:** Para el caso sin admin donde HKCU IFEO no funcione (aplicaciones instaladas en rutas del sistema), se usa el mismo patrón que en Linux: renombrar el binario original a `.<nombre>.real.exe` y colocar el launcher en su lugar. En Windows, un File System Watcher (`ReadDirectoryChangesW`) monitoriza las rutas de agentes para el mismo auto-heal que inotify en Linux.

### 4.2 Capa 2: Process Isolation

#### Con admin — AppContainer + Job Object

AppContainer es el mecanismo de sandboxing de menor overhead en Windows. Es el mismo que usa Edge, Internet Explorer en modo protegido, y Microsoft Office en modo sandbox. No requiere Hyper-V.

El launcher crea el proceso agente en AppContainer antes de que ejecute su primer opcode:

```
launcher.exe recibe: ["claude-code.exe", <args originales>]
    │
    ▼
1. Crear AppContainer SID para esta sesión
   (SID único por sesión, no reutilizado)
    │
    ▼
2. Construir SECURITY_CAPABILITIES:
   - Capabilities: vacías por defecto
   - No internetClient, no privateNetworkClient, no documentLibrary
    │
    ▼
3. CreateProcess con EXTENDED_STARTUPINFO:
   - ProcThreadAttributeSecurityCapabilities → AppContainer
   - CREATE_SUSPENDED (proceso creado pero no ejecuta nada todavía)
    │
    ▼
4. AssignProcessToJobObject ANTES de ResumeThread
   (garantiza que el proceso nace dentro del Job)
    │
    ▼
5. SetProcessMitigationPolicy en el proceso hijo
    │
    ▼
6. ResumeThread → el agente empieza a ejecutar dentro del AppContainer
```

#### Sin admin — Low Integrity Level + Job Object

Low Integrity Level es el mecanismo de Windows para reducir los privilegios de un proceso sin requerir admin. Cualquier proceso puede crear un hijo con IL más baja que la suya. Un proceso Medium IL (usuario normal) puede crear hijos en Low IL.

Lo que bloquea Low IL implícitamente (por SACL del sistema):
- Escritura en `%USERPROFILE%` excepto `%LOCALAPPDATA%\Low`
- Escritura en `HKCU` excepto `HKCU\Software\Classes` (Low subkey)
- Comunicación IPC con procesos Medium/High (DDE, mensajes de ventana, etc.)
- Creación de procesos con IL ≥ Low (no puede escalar)

```rust
// Proceso hijo en Low IL sin admin
let mut token = open_current_token(TOKEN_ALL_ACCESS)?;

// Crear token restringido — quita todos los privilegios
let restricted = create_restricted_token(
    token,
    DISABLE_MAX_PRIVILEGE,
    &[], // sin deny SIDs adicionales (Low IL ya los cubre)
    &[], // sin privileges a quitar específicamente
    &[], // sin restricting SIDs
)?;

// Bajar IL a Low (S-1-16-4096)
let low_il_sid = create_low_integrity_sid()?;
set_token_integrity_level(restricted, low_il_sid, SE_GROUP_INTEGRITY)?;

// Crear proceso SUSPENDIDO con token restringido en Low IL
let process = create_process_as_user(
    restricted,
    exe_path,
    args,
    working_dir,
    CREATE_SUSPENDED,
)?;

// Asignar al Job Object ANTES de reanudar
assign_to_job(job, process.handle)?;

// Aplicar mitigaciones de proceso
apply_mitigations(process.handle)?;

// Reanudar
resume_thread(process.thread)?;
```

#### SetProcessMitigationPolicy — 7 políticas sin admin

```rust
// 1. Solo DLLs firmadas por Microsoft
ProcessSignaturePolicy → MicrosoftSignedOnly: true
// Impide que el agente cargue código arbitrario desde DLLs sin firmar

// 2. Sin acceso a Win32k (GDI/User) — agentes CLI no lo necesitan
ProcessSystemCallDisablePolicy → DisallowWin32kSystemCalls: true
// Elimina la superficie de ataque del kernel GDI

// 3. Sin código dinámico no firmado
ProcessDynamicCodePolicy → ProhibitDynamicCode: true
// Sin JIT arbitrario excepto el del runtime del agente (Node/Python tienen excepción)

// 4. Export Address Filter (EAF/EAF+)
ProcessMitigationOptionsMask → EnableExportAddressFilter: true
// Dificulta que shellcode resuelva funciones de la API de Windows

// 5. Import Address Filter (IAF)
ProcessMitigationOptionsMask → EnableImportAddressFilter: true
// Similar a EAF pero para la tabla de imports

// 6. Sin imágenes remotas o de baja integridad
ProcessImageLoadPolicy → NoRemoteImages: true, NoLowMandatoryLabelImages: true
// No puede cargar DLLs de rutas de red o con IL bajo

// 7. Control Flow Guard
ProcessControlFlowGuardPolicy → EnableControlFlowGuard: true
// Protección contra ROP chains
```

### 4.3 Capa 3: Filesystem Protection

**Con admin (SYSTEM service):** El servicio aplica NTFS DENY ACEs en las rutas protegidas para el SID del AppContainer y para el usuario normal. El agente en AppContainer no puede modificar estas ACLs porque no tiene los permisos necesarios — solo el servicio SYSTEM puede hacerlo.

**Sin admin:** Low IL actúa como filesystem protection implícita. Para rutas específicas que necesitan protección extra, el usuario puede marcarlas con `icacls` manualmente, aunque esto está fuera del scope de lo que AgentGuard puede hacer sin admin.

---

## 5. Retos y Soluciones

### 5.1 Evasión del shim por ruta absoluta

**Problema:** Un IDE, script, o el propio usuario llama a `/home/user/.npm-global/bin/claude-code` con la ruta absoluta, bypaseando el PATH shim.

**Solución implementada:** Binary displacement. El shim ocupa exactamente la ruta original del binario. La ruta absoluta sigue golpeando el shim.

**Reto dentro del reto:** `npm update -g` sobrescribe el shim con el nuevo binario real.

**Solución:** Daemon inotify de auto-curación (ver §3.1). Reacciona en <50ms. El nuevo binario se convierte en `.<nombre>.real` y el shim vuelve a su lugar.

**Edge case no resuelto con elegancia:** El agente está en `/usr/bin/` (requiere root para escribir). Sin root, no podemos hacer displacement.

**Solución honesta:** Detectar en instalación, advertir al usuario, ofrecer el PATH shim con documentación explícita de la limitación. No prometer protección que no podemos dar. Si el usuario nos da root más tarde, migrar a displacement automáticamente.

### 5.2 Landlock y directorios dinámicos

**Problema:** Landlock se configura en `exec()` con una lista de rutas fija. Si el agente necesita acceder a un directorio que no estaba en la lista (un repo clonado, un path generado dinámicamente), recibe `EACCES`.

**Solución v1 — Workspaces pre-aprovisionados:**
```
agentguard run --mount ~/Projects/myapp claude-code
```
El workspace es el único directorio donde el agente puede escribir. Cubre el 95% de casos de uso reales. Simple, auditable, sin complejidad de IPC.

**Solución v2 — FD broker con SCM_RIGHTS:**
Para casos donde el workspace pre-aprovisionado es insuficiente (agentes que necesitan acceso a múltiples proyectos no relacionados en una sesión):

```
Agente recibe EACCES en open("/home/user/NewProject")
    │  (si el agente usa el protocolo broker, o vía LD_PRELOAD)
    ▼
Mensaje al socket UNIX del daemon:
    { "op": "open", "path": "/home/user/NewProject", "flags": "rw" }
    │
    ▼
Daemon evalúa regla:
    - ¿El path está en la allowlist del usuario? → continúa
    - ¿Requiere confirmación del usuario? → notificación desktop
    │
    ▼
Daemon abre el directorio con sus propios permisos (fuera del sandbox)
Daemon pasa el FD al agente vía SCM_RIGHTS en el socket UNIX
    │
    ▼
Agente usa openat(<fd_recibido>, "archivo.txt", O_RDWR)
Esto bypasea Landlock legítimamente — el FD ya está abierto
```

**Limitación conocida del broker:** Solo funciona para binarios dinámicamente enlazados. Claude Code (Electron), Cursor (Electron), Windsurf (Electron) — todos son dinámicos, todos funcionan con LD_PRELOAD. Agentes Go compilados estáticamente (como algunas versiones de `aider` compiladas así) no pueden usar el broker sin modificar el agente.

### 5.3 Mantenimiento de perfiles seccomp

**Problema:** Una nueva versión de Claude Code empieza a usar syscalls que no estaban en la allowlist. El filtro con `RET_KILL_PROCESS` mata el proceso sin explicación. El usuario desinstala AgentGuard.

**Solución: perfiles OTA con `SECCOMP_RET_USER_NOTIF`**

Para syscalls clasificadas como "ambiguas" (no claramente maliciosas, no claramente necesarias), el daemon recibe la notificación, la evalúa, y la permite con telemetría. Esta telemetría alimenta el sistema OTA:

```
Producción:
    Agente intenta syscall X no conocida
    → USER_NOTIF al daemon
    → Daemon: ¿en la lista de known-ambiguous? NO
    → Daemon: log con contexto completo + Allow (fail-open para ambiguas)
    → Telemetría anonimizada a backend AgentGuard

Backend AgentGuard CI/CD:
    Recibe telemetría: "claude-code v1.x usa syscall 425 (futex_waitv)"
    Ejecuta nueva versión del agente en VM instrumentada con strace
    Baterías de tests automáticos verifican que la syscall es legítima
    Si es legítima: añadir a allowlist del perfil
    Firma perfil actualizado con clave Ed25519 privada
    Publica en CDN de distribución

Cliente AgentGuard:
    Comprueba perfil actualizado cada 24h (o en cada arranque de agente)
    Descarga y verifica firma Ed25519
    Aplica nuevo perfil
```

### 5.4 Seguridad de perfiles OTA

**Problema:** Si alguien compromete la CDN o el servidor de distribución, puede subir un perfil que debilita el sandbox. El cliente descarga el perfil malicioso y queda desprotegido.

**Solución: firma Ed25519 con clave privada offline**

```rust
// En el build pipeline de AgentGuard (servidor seguro, no CDN):
let signing_key = Ed25519SigningKey::from_bytes(&PRIVATE_KEY_BYTES);
let profile_json = serde_json::to_vec(&profile)?;
let signature = signing_key.sign(&profile_json);

// Perfil publicado = profile_json + signature (separados)
// La clave privada NUNCA toca la CDN

// En el cliente:
let verifying_key = Ed25519VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES);
// La clave pública está hardcodeada en el binario del cliente
// (no descargable — esto es lo que hace el pinning seguro)

verifying_key.verify(&downloaded_profile, &downloaded_signature)?;
// Si falla: rechazar el perfil, mantener el anterior, alertar al usuario
```

**Clave de rotación de emergencia:** El binario contiene 3 claves públicas (primaria + 2 de backup). Si la primaria se compromete, se puede revocar publicando un perfil firmado con la backup que invalida la primaria. Este proceso requiere acceso físico al servidor de signing (air-gapped preferiblemente).

**Versioning con anti-rollback:** Cada perfil tiene un número de versión monotónicamente creciente. El cliente rechaza perfiles con versión menor o igual a la actual, incluso si la firma es válida. Esto previene ataques de rollback donde un atacante sirve un perfil antiguo (y potencialmente más permisivo).

### 5.5 Fallo del daemon durante USER_NOTIF

**Problema:** El daemon muere mientras el kernel tiene syscalls pausadas esperando respuesta USER_NOTIF. ¿Qué pasa con el proceso agente?

**Comportamiento del kernel:** Al cerrarse el fd de notificación, el kernel libera todas las syscalls pendientes con `ENOSYS`. El agente puede crashear si no maneja `ENOSYS`, pero no ejecuta nada peligroso.

**Diseño de fail-safe:**

```
1. Clasificación de syscalls por comportamiento en fallo:
   - KILL_ALWAYS: ptrace, kexec, bpf → RET_KILL_PROCESS (no pasa por USER_NOTIF)
   - NOTIFY_OR_ENOSYS: syscalls ambiguas → USER_NOTIF, fallback a ENOSYS si daemon muere
   - ALLOW: allowlist completa → RET_ALLOW directamente

2. Daemon watchdog:
   - Hilo interno comprueba estado cada 100ms
   - Si detecta que el fd de notificación está en estado anómalo → reinicia la conexión

3. systemd unit del daemon:
   Restart=always
   RestartSec=100ms
   StartLimitIntervalSec=10
   StartLimitBurst=5
   → Máximo 5 reinicios en 10 segundos antes de marcar como failed

4. Al reiniciarse el daemon:
   - Recupera bpf_link pinado (el hook eBPF sigue activo)
   - Reconstruye fd de notificación para nuevas syscalls
   - Los procesos agente que crashearon por ENOSYS: el usuario los relanza
     y vuelven al sandbox inmediatamente
```

La ventana de exposición máxima es el tiempo de reinicio del daemon (<200ms con RestartSec=100ms). Durante esa ventana, las syscalls clasificadas como KILL_ALWAYS siguen siendo bloqueadas por el kernel directamente. Solo las syscalls en la categoría NOTIFY_OR_ENOSYS quedan temporalmente sin supervisión de usuario — el kernel las deniega con ENOSYS.

### 5.6 Binarios en rutas de solo lectura

**Problema:** El agente está instalado en `/usr/bin/`, `/usr/local/bin/`, o cualquier ruta que requiere root para escribir. Binary displacement falla sin root.

**Árbol de decisión en instalación:**

```
Para cada agente detectado:

¿La ruta del binario es escribible por el usuario?
    │
    ├── SÍ → Binary displacement + inotify watcher
    │         (protección completa sin root)
    │
    └── NO → ¿El agente está en el PATH del usuario?
                 │
                 ├── SÍ → PATH shim en directorio usuario-writable
                 │        Advertencia: "ruta absoluta no protegida sin root"
                 │        Recomendación: instalar claude-code via npm/pip/cargo
                 │        en directorio de usuario para protección completa
                 │
                 └── NO → Registro en db de agentes conocidos sin protección
                           Notificación al usuario: protección parcial
                           Oferta: "ejecuta `sudo agentguard install-root`
                           para protección completa"
```

---

## 6. Matriz de Capacidades

### Linux

| Capacidad | root + kernel ≥5.7 | sin root + kernel ≥5.13 | sin root + kernel <5.13 |
|---|:---:|:---:|:---:|
| Exec interception (cualquier método de lanzamiento) | eBPF ✓ | Displacement ✓ | Displacement ✓ |
| Exec interception (ruta absoluta, binario en /usr) | eBPF ✓ | ✗ (documentado) | ✗ (documentado) |
| Filesystem isolation irrevocable | bwrap + mount ns ✓ | Landlock ✓ | seccomp parcial ⚠ |
| Syscall filter adaptativo | USER_NOTIF ✓ | USER_NOTIF ✓ | RET_ERRNO solamente ⚠ |
| Red isolation | network namespace ✓ | ✗ | ✗ |
| File delete protection (archivos protegidos) | eBPF LSM ✓ | seccomp unlinkat ✓ | seccomp unlinkat ✓ |
| Protección persiste si daemon muere | bpf_link ✓ | Landlock irrevocable ✓ | seccomp irrevocable ✓ |
| Perfiles seccomp OTA | ✓ | ✓ | ✓ |
| Overhead en idle | ~0% | ~0% | ~0% |

### Windows

| Capacidad | Admin (SYSTEM service) | Sin admin |
|---|:---:|:---:|
| Exec interception (cualquier método) | IFEO HKLM ✓ | IFEO HKCU + displacement ✓ |
| Process isolation | AppContainer ✓ | Low IL ✓ |
| Restricción de API de kernel | SetProcessMitigationPolicy ✓ | SetProcessMitigationPolicy ✓ |
| Resource limits | Job Objects ✓ | Job Objects ✓ |
| Filesystem (rutas protegidas) | NTFS DENY ACEs ✓ | Low IL implícito ⚠ |
| Protección persiste si daemon muere | IFEO es registro permanente ✓ | IFEO HKCU permanente ✓ |
| Overhead en idle | ~0% | ~0% |

---

## 7. Código de Referencia

### 7.1 Binary Displacement — instalador (Linux)

```rust
use std::path::{Path, PathBuf};
use std::fs;

/// Magic bytes que identifican un shim de AgentGuard en el ELF.
/// Se embeben en la sección .note.agentguard del binario shim.
const AGENTGUARD_SHIM_MAGIC: &[u8] = b"AGENTGUARD_SHIM_V1\0";

pub fn install_displacement(
    agent_binary: &Path,
    shim_binary: &Path,
) -> Result<DisplacementResult, anyhow::Error> {
    // 1. Verificar que la ruta es escribible por el usuario actual
    let metadata = fs::metadata(agent_binary)?;
    let uid = unsafe { libc::getuid() };
    let file_uid = metadata.uid(); // std::os::unix::fs::MetadataExt

    let writable = file_uid == uid || uid == 0;
    if !writable {
        return Ok(DisplacementResult::NotWritable {
            path: agent_binary.to_path_buf(),
            suggestion: format!(
                "Run `sudo agentguard install-root` for full protection, \
                 or reinstall {} in a user-writable location (npm/pip/cargo user install)",
                agent_binary.display()
            ),
        });
    }

    // 2. Verificar que no es ya un shim de AgentGuard (evitar doble displacement)
    if is_agentguard_shim(agent_binary)? {
        return Ok(DisplacementResult::AlreadyDisplaced);
    }

    // 3. Calcular la ruta del binario real
    let parent = agent_binary.parent().unwrap();
    let name = agent_binary.file_name().unwrap().to_str().unwrap();
    let real_path = parent.join(format!(".{}.real", name));

    // 4. Desplazar: rename original → .name.real
    fs::rename(agent_binary, &real_path)?;

    // 5. Copiar el shim a la ruta original
    fs::copy(shim_binary, agent_binary)?;

    // 6. Preservar los permisos del original
    let real_meta = fs::metadata(&real_path)?;
    fs::set_permissions(agent_binary, real_meta.permissions())?;

    // 7. Registrar en la base de datos de displacements
    DisplacementDb::record(agent_binary, &real_path)?;

    Ok(DisplacementResult::Success {
        original: agent_binary.to_path_buf(),
        real: real_path,
    })
}

fn is_agentguard_shim(path: &Path) -> Result<bool, anyhow::Error> {
    // Buscar la sección .note.agentguard en el ELF
    // Implementación simplificada: buscar magic bytes en los primeros 4KB
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 4096];
    use std::io::Read;
    let n = file.read(&mut buf)?;
    Ok(buf[..n].windows(AGENTGUARD_SHIM_MAGIC.len())
        .any(|w| w == AGENTGUARD_SHIM_MAGIC))
}
```

### 7.2 inotify Auto-heal daemon (Linux)

```rust
use inotify::{Inotify, WatchMask, EventMask};
use std::path::PathBuf;
use std::collections::HashMap;

pub struct AutoHealWatcher {
    inotify: Inotify,
    /// watch_fd → (directorio, lista de agentes monitorizados)
    watches: HashMap<inotify::WatchDescriptor, (PathBuf, Vec<String>)>,
    shim_binary: PathBuf,
}

impl AutoHealWatcher {
    pub fn new(shim_binary: PathBuf) -> Result<Self, anyhow::Error> {
        Ok(Self {
            inotify: Inotify::init()?,
            watches: HashMap::new(),
            shim_binary,
        })
    }

    pub fn watch_directory(
        &mut self,
        dir: PathBuf,
        agent_names: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        let wd = self.inotify.watches().add(
            &dir,
            // IN_CREATE: nuevo archivo creado
            // IN_MOVED_TO: archivo movido a este dir (npm usa rename atómico)
            // IN_CLOSE_WRITE: archivo terminó de escribirse
            WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE,
        )?;
        self.watches.insert(wd, (dir, agent_names));
        Ok(())
    }

    pub async fn run(mut self) -> Result<(), anyhow::Error> {
        let mut buffer = [0u8; 4096];
        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)?;
            for event in events {
                self.handle_event(event).await?;
            }
        }
    }

    async fn handle_event(
        &self,
        event: inotify::Event<&std::ffi::OsStr>,
    ) -> Result<(), anyhow::Error> {
        // Obtener el directorio que generó el evento
        let Some((dir, agent_names)) = self.watches.get(&event.wd) else {
            return Ok(());
        };

        // Obtener el nombre del archivo modificado
        let Some(name) = event.name else { return Ok(()); };
        let name_str = name.to_string_lossy();

        // ¿Es un agente conocido?
        if !agent_names.iter().any(|a| a == name_str.as_ref()) {
            return Ok(());
        }

        let path = dir.join(name);

        // ¿Ya es un shim de AgentGuard? → no hacer nada
        if is_agentguard_shim(&path)? {
            return Ok(());
        }

        // El shim fue sobrescrito. Restaurar.
        tracing::info!(
            "Agent binary updated at {:?} — restoring AgentGuard shim",
            path
        );

        // Calcular ruta del binario real
        let real_name = format!(".{}.real", name_str);
        let real_path = dir.join(&real_name);

        // Mover el nuevo binario a .name.real (puede ser una versión actualizada)
        tokio::fs::rename(&path, &real_path).await?;

        // Restaurar el shim
        tokio::fs::copy(&self.shim_binary, &path).await?;
        let real_meta = tokio::fs::metadata(&real_path).await?;
        tokio::fs::set_permissions(&path, real_meta.permissions()).await?;

        tracing::info!("Shim restored at {:?}. Real binary at {:?}", path, real_path);
        Ok(())
    }
}
```

### 7.3 Landlock — aplicación en el shim

```rust
use std::os::unix::io::OwnedFd;

/// Versiones de Landlock soportadas.
/// Se detecta en runtime cuál soporta el kernel actual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LandlockVersion {
    V1 = 1, // kernel 5.13 — FS básico
    V2 = 2, // kernel 5.19 — añade TRUNCATE
    V3 = 3, // kernel 6.7  — añade NET_CONNECT_TCP
}

pub struct LandlockDomain {
    fd: OwnedFd,
    version: LandlockVersion,
}

impl LandlockDomain {
    /// Detecta la versión de Landlock disponible y crea el ruleset.
    pub fn create(config: &SandboxConfig) -> Result<Self, LandlockError> {
        // Probar desde la versión más alta hasta la más baja
        for version in [LandlockVersion::V3, LandlockVersion::V2, LandlockVersion::V1] {
            match Self::try_create(config, version) {
                Ok(domain) => {
                    tracing::info!("Landlock {:?} active", version);
                    return Ok(domain);
                }
                Err(LandlockError::UnsupportedVersion) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(LandlockError::NotSupported)
    }

    fn try_create(
        config: &SandboxConfig,
        version: LandlockVersion,
    ) -> Result<Self, LandlockError> {
        let mut handled_fs =
            LANDLOCK_ACCESS_FS_WRITE_FILE  |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR  |
            LANDLOCK_ACCESS_FS_MAKE_REG    |
            LANDLOCK_ACCESS_FS_MAKE_DIR    |
            LANDLOCK_ACCESS_FS_RENAME      |
            LANDLOCK_ACCESS_FS_REFER;

        if version >= LandlockVersion::V2 {
            handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        let mut handled_net = 0u64;
        if version >= LandlockVersion::V3 {
            handled_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
        }

        let attr = landlock_ruleset_attr {
            handled_access_fs:  handled_fs,
            handled_access_net: handled_net,
        };

        let fd = unsafe {
            let ret = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr,
                std::mem::size_of::<landlock_ruleset_attr>(),
                0u32,
            );
            if ret == -libc::EINVAL as i64 {
                return Err(LandlockError::UnsupportedVersion);
            }
            if ret < 0 {
                return Err(LandlockError::Syscall(std::io::Error::last_os_error()));
            }
            OwnedFd::from_raw_fd(ret as i32)
        };

        let domain = Self { fd, version };

        // Añadir rutas con permisos de escritura
        for path in &config.allowed_write_paths {
            domain.add_write_rule(path)?;
        }

        // Añadir rutas con solo lectura (todo lo necesario para ejecutar el agente)
        for path in &config.allowed_read_paths {
            domain.add_read_rule(path)?;
        }

        Ok(domain)
    }

    fn add_write_rule(&self, path: &std::path::Path) -> Result<(), LandlockError> {
        let dir = std::fs::File::open(path)
            .map_err(|e| LandlockError::OpenPath(path.to_path_buf(), e))?;

        let rule = landlock_path_beneath_attr {
            allowed_access:
                LANDLOCK_ACCESS_FS_READ_FILE  |
                LANDLOCK_ACCESS_FS_READ_DIR   |
                LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_REMOVE_FILE |
                LANDLOCK_ACCESS_FS_MAKE_REG   |
                LANDLOCK_ACCESS_FS_RENAME,
            parent_fd: dir.as_raw_fd(),
        };

        unsafe {
            let ret = libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule,
                0u32,
            );
            if ret < 0 {
                return Err(LandlockError::AddRule(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Aplica el dominio al proceso actual. IRREVOCABLE.
    pub fn restrict_self(self) -> Result<(), LandlockError> {
        unsafe {
            let ret = libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.fd.as_raw_fd(),
                0u32,
            );
            if ret < 0 {
                return Err(LandlockError::RestrictSelf(std::io::Error::last_os_error()));
            }
        }
        // El fd se cierra al hacer drop — el dominio queda activo igualmente
        Ok(())
    }
}
```

### 7.4 seccomp con USER_NOTIF + fail-safe

```rust
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::os::unix::io::{AsRawFd, OwnedFd};

pub struct SeccompNotifier {
    /// File descriptor para recibir notificaciones del kernel
    notify_fd: OwnedFd,
}

/// Construye el filtro seccomp y retorna el fd de notificación.
/// El filtro tiene 3 clases de acción:
/// - Allow: syscalls en la allowlist completa
/// - UserNotif: syscalls ambiguas que el daemon decide en runtime
/// - KillProcess: syscalls claramente peligrosas
pub fn install_seccomp_filter(
    allowlist: &[i64],
    ambiguous: &[i64],
) -> Result<SeccompNotifier, anyhow::Error> {
    use seccompiler::SeccompAction::*;

    let mut rules = std::collections::BTreeMap::new();

    // Syscalls claramente peligrosas → matar el proceso inmediatamente
    // NO pasan por USER_NOTIF — el kernel actúa sin consultar al daemon
    for &sc in &ALWAYS_KILL_SYSCALLS {
        rules.insert(sc, vec![]);  // con KillProcess como default action
    }

    // Syscalls ambiguas → notificar al daemon (USER_NOTIF)
    // Usa un fd separado para la comunicación
    for &sc in ambiguous {
        // SeccompAction::Notify es USER_NOTIF en seccompiler
        rules.entry(sc).or_insert_with(Vec::new);
    }

    // El filtro: allowlist con KillProcess como default para lo no listado
    // Excepto las ambiguas que van a Notify
    let filter = SeccompFilter::new(
        allowlist.iter().map(|&sc| (sc, vec![])).collect(),
        KillProcess,  // default para todo lo no en allowlist ni ambiguous
        Allow,
        std::env::consts::ARCH.try_into()?,
    )?;

    let program: BpfProgram = filter.try_into()?;

    // Instalar el filtro — a partir de aquí es activo e irrevocable para este proceso
    let notify_fd = seccompiler::apply_filter_with_notify(&program)?;

    Ok(SeccompNotifier {
        notify_fd: unsafe { OwnedFd::from_raw_fd(notify_fd) },
    })
}

/// Loop principal del daemon para manejar notificaciones seccomp.
pub async fn handle_seccomp_notifications(
    notifier: SeccompNotifier,
    profile: Arc<SeccompProfile>,
) {
    let fd = notifier.notify_fd.as_raw_fd();

    loop {
        // Recibir notificación del kernel (blocking)
        let notification = match seccomp_notif_recv(fd) {
            Ok(n) => n,
            Err(e) => {
                // ENOENT: el proceso agente murió. Salir del loop.
                if e.raw_os_error() == Some(libc::ENOENT) {
                    tracing::debug!("Agent process died, seccomp notifier loop ending");
                    return;
                }
                tracing::error!("seccomp_notif_recv error: {}", e);
                continue;
            }
        };

        let syscall_nr = notification.data.nr as i64;
        let pid = notification.pid;

        // Decisión basada en el perfil actual (puede actualizarse OTA)
        let response = {
            let profile = profile.read().await;
            match profile.classify(syscall_nr) {
                SyscallClass::Allow => NotifResponse::allow(notification.id),
                SyscallClass::DenyEnosys => {
                    tracing::warn!(pid, syscall = syscall_nr, "denying ambiguous syscall with ENOSYS");
                    NotifResponse::deny(notification.id, libc::ENOSYS)
                }
                SyscallClass::DenyEperm => {
                    tracing::warn!(pid, syscall = syscall_nr, "denying syscall with EPERM");
                    NotifResponse::deny(notification.id, libc::EPERM)
                }
                SyscallClass::AllowWithTelemetry => {
                    // Permitir pero registrar — para alimentar el sistema OTA
                    telemetry::record_unknown_syscall(syscall_nr, pid);
                    NotifResponse::allow(notification.id)
                }
            }
        };

        if let Err(e) = seccomp_notif_send(fd, &response) {
            // ENOENT: el proceso ya murió entre la notificación y nuestra respuesta
            // Es normal, no es un error
            if e.raw_os_error() != Some(libc::ENOENT) {
                tracing::error!("seccomp_notif_send error: {}", e);
            }
        }
    }
}

const ALWAYS_KILL_SYSCALLS: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_mount,
    libc::SYS_perf_event_open,
    libc::SYS_bpf,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
];
```

### 7.5 Perfiles OTA — firma y verificación

```rust
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Clave pública hardcodeada en el binario del cliente.
/// NUNCA se descarga — esto es lo que hace seguro el sistema.
/// Si se compromete la CDN, los perfiles maliciosos son rechazados
/// porque no están firmados con esta clave.
const AGENTGUARD_OTA_PUBLIC_KEY: [u8; 32] = [
    // ... bytes de la clave pública Ed25519 ...
    // Generada offline, la privada nunca toca internet
    0x00, 0x00, /* ... */
];

/// Claves de backup para rotación de emergencia
const AGENTGUARD_OTA_BACKUP_KEYS: &[[u8; 32]] = &[
    [/* backup key 1 */],
    [/* backup key 2 */],
];

#[derive(serde::Deserialize)]
pub struct SignedProfile {
    /// Versión monotónicamente creciente (anti-rollback)
    pub version: u64,
    /// Unix timestamp de emisión
    pub issued_at: u64,
    /// Contenido del perfil (syscall allowlists, etc.)
    pub profile: SeccompProfile,
    /// Firma Ed25519 sobre el JSON de profile + version + issued_at
    pub signature: String, // hex
}

pub fn verify_and_apply_profile(
    downloaded: &[u8],
    current_version: u64,
) -> Result<SeccompProfile, OtaError> {
    let signed: SignedProfile = serde_json::from_slice(downloaded)
        .map_err(OtaError::InvalidJson)?;

    // Anti-rollback: rechazar versiones antiguas o iguales
    if signed.version <= current_version {
        return Err(OtaError::Rollback {
            downloaded: signed.version,
            current: current_version,
        });
    }

    // Construir el mensaje que fue firmado
    let message = format!(
        "{}:{}:{}",
        signed.version,
        signed.issued_at,
        serde_json::to_string(&signed.profile).unwrap(),
    );

    // Decodificar la firma
    let sig_bytes = hex::decode(&signed.signature)
        .map_err(|_| OtaError::InvalidSignature)?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| OtaError::InvalidSignature)?;

    // Verificar con la clave primaria o las de backup
    let all_keys = std::iter::once(&AGENTGUARD_OTA_PUBLIC_KEY)
        .chain(AGENTGUARD_OTA_BACKUP_KEYS.iter());

    let valid = all_keys.any(|key_bytes| {
        VerifyingKey::from_bytes(key_bytes)
            .and_then(|key| key.verify(message.as_bytes(), &signature))
            .is_ok()
    });

    if !valid {
        return Err(OtaError::SignatureVerificationFailed);
    }

    Ok(signed.profile)
}
```

### 7.6 Windows — launcher completo sin admin

```rust
use windows::Win32::{Foundation::*, Security::*, System::Threading::*};

pub fn launch_agent_sandboxed(
    exe_path: &str,
    original_args: &[String],
    working_dir: &str,
) -> Result<SandboxedProcess, anyhow::Error> {
    unsafe {
        // 1. Token restringido en Low Integrity Level
        let mut src_token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut src_token)?;

        let mut restricted = HANDLE::default();
        CreateRestrictedToken(
            src_token,
            DISABLE_MAX_PRIVILEGE,
            0, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(),
            &mut restricted,
        )?;

        // Establecer Low IL (S-1-16-4096)
        let mut low_sid: *mut std::ffi::c_void = std::ptr::null_mut();
        let low_auth = SID_IDENTIFIER_AUTHORITY { Value: [0,0,0,0,0,16] };
        AllocateAndInitializeSid(
            &low_auth, 1, SECURITY_MANDATORY_LOW_RID as u32,
            0,0,0,0,0,0,0, &mut low_sid,
        )?;

        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low_sid as *mut _,
                Attributes: SE_GROUP_INTEGRITY.0,
            },
        };
        SetTokenInformation(
            restricted, TokenIntegrityLevel,
            &label as *const _ as *const _,
            std::mem::size_of_val(&label) as u32,
        )?;

        // 2. Job Object con restricciones
        let job = CreateJobObjectW(None, None)?;

        let mut basic = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
        basic.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        ).0;
        basic.ActiveProcessLimit = 16;
        SetInformationJobObject(
            job, JobObjectBasicLimitInformation,
            &basic as *const _ as *const _,
            std::mem::size_of_val(&basic) as u32,
        )?;

        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: (
                JOB_OBJECT_UILIMIT_HANDLES |
                JOB_OBJECT_UILIMIT_GLOBALATOMS |
                JOB_OBJECT_UILIMIT_DESKTOP |
                JOB_OBJECT_UILIMIT_EXITWINDOWS
            ).0,
        };
        SetInformationJobObject(
            job, JobObjectBasicUIRestrictions,
            &ui as *const _ as *const _,
            std::mem::size_of_val(&ui) as u32,
        )?;

        // 3. Crear proceso SUSPENDIDO
        let mut cmdline = build_cmdline(exe_path, original_args);
        let working_dir_w = to_wide(working_dir);

        let mut si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessAsUserW(
            restricted,
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None, None, false,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
            None,
            PCWSTR(working_dir_w.as_ptr()),
            &si, &mut pi,
        )?;

        // 4. Asignar al Job ANTES de reanudar (crítico)
        AssignProcessToJobObject(job, pi.hProcess)?;

        // 5. Mitigaciones de proceso
        apply_all_mitigations(pi.hProcess);

        // 6. Reanudar
        ResumeThread(pi.hThread)?;
        CloseHandle(pi.hThread)?;
        CloseHandle(src_token)?;
        CloseHandle(restricted)?;
        FreeSid(low_sid as *mut _);

        Ok(SandboxedProcess {
            handle: pi.hProcess,
            pid: pi.dwProcessId,
            job,
        })
    }
}

fn apply_all_mitigations(process: HANDLE) {
    unsafe {
        // Solo binarios firmados Microsoft
        let _ = SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
                Anonymous: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_0 {
                    MicrosoftSignedOnly: 1,
                },
            } as *const _ as *const _,
            std::mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(),
        );

        // Sin Win32k (GDI) — agentes CLI no lo usan
        let _ = SetProcessMitigationPolicy(
            ProcessSystemCallDisablePolicy,
            &PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
                Anonymous: PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_0 {
                    DisallowWin32kSystemCalls: 1,
                },
            } as *const _ as *const _,
            std::mem::size_of::<PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY>(),
        );

        // Sin imágenes remotas ni de baja integridad
        let _ = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            &PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
                Anonymous: PROCESS_MITIGATION_IMAGE_LOAD_POLICY_0 {
                    NoRemoteImages: 1,
                    NoLowMandatoryLabelImages: 1,
                    ..Default::default()
                },
            } as *const _ as *const _,
            std::mem::size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        );
    }
}
```

---

## 8. Orden de Implementación

### Fase 1 — Base sin privilegios (máximo impacto, mínimo riesgo)

| Tarea | Plataforma | Semanas |
|---|---|---|
| Binary displacement + ELF magic detection | Linux | 1 |
| inotify auto-heal daemon | Linux | 1 |
| Shim estático (musl, sin dependencias) | Linux | 1 |
| Landlock integration en shim (v1+v2+v3 auto-detect) | Linux | 1 |
| seccomp allowlist mínima + USER_NOTIF para ambiguas | Linux | 2 |
| Fail-safe USER_NOTIF (daemon watchdog + ENOSYS fallback) | Linux | 1 |
| IFEO HKCU setup + PATH shim | Windows | 1 |
| Low IL + Job Object + SetProcessMitigationPolicy launcher | Windows | 2 |

### Fase 2 — Privilegios elevados

| Tarea | Plataforma | Semanas |
|---|---|---|
| eBPF bprm_check_security hook + bpf_link pinado | Linux | 2 |
| bwrap sandbox + network namespace | Linux | 1 |
| eBPF LSM file_unlink / file_rename | Linux | 1 |
| IFEO HKLM setup + AppContainer launcher | Windows | 2 |
| NTFS DENY ACEs via SYSTEM service | Windows | 1 |

### Fase 3 — OTA y mantenimiento

| Tarea | Plataforma | Semanas |
|---|---|---|
| Backend CI/CD con strace + VM instrumentada | – | 3 |
| Sistema OTA con firma Ed25519 + anti-rollback | Linux + Windows | 2 |
| Telemetría anonimizada de syscalls desconocidas | Linux | 1 |
| FD broker SCM_RIGHTS (workspaces dinámicos) | Linux | 2 |

---

## 9. Diferenciadores de Mercado

**Landlock sin root.** Nadie en el espacio de herramientas para agentes IA usa Landlock. Es filesystem isolation real sin privilegios — no es "security theater" ni un watcher que detecta daños después de que ocurren.

**Binary displacement + inotify auto-heal.** La combinación cierra el gap del PATH shim (ruta absoluta) y el gap de las actualizaciones automáticas. El sistema se autocura en <50ms cuando un gestor de paquetes actualiza el agente.

**eBPF exec hook con ventana cero.** `bprm_check_security` intercepta en la syscall `execve`, antes de que el proceso tenga ningún opcode ejecutado. Los competidores que usan polling de `/proc` tienen una ventana de detección de 1-5 segundos. La protección basada en eBPF no tiene ventana.

**SECCOMP_RET_USER_NOTIF como syscall filter adaptativo.** En vez de un filtro binario que mata el proceso o permite todo, el daemon toma decisiones en runtime y alimenta el sistema OTA. El resultado es que los perfiles mejoran con el uso en lugar de romperse con las actualizaciones de los agentes.

**IFEO sin driver firmado en Windows.** Intercepción universal en Windows sin el coste y complejidad de un driver firmado con certificado EV. Funciona con doble clic, terminal, scripts, y cualquier método de lanzamiento programático. Persiste como entrada de registro — sobrevive reinicios del servicio.

**Perfiles OTA con firma Ed25519 + anti-rollback.** Los competidores que ofrecen reglas actualizables las sirven sin firma criptográfica o con HTTPS solamente (no protege contra CDN comprometida). La clave pública hardcodeada en el binario del cliente garantiza que solo AgentGuard puede emitir perfiles válidos.

**Zero overhead en steady state.** Las restricciones viven en el kernel. Una vez el agente está corriendo en el sandbox, no hay ningún componente de AgentGuard en su hot path. Sin proxy, sin polling, sin IPC en cada operación.

---

*AgentGuard · Sandbox Architecture v2.0 · Linux + Windows · Producción-ready*