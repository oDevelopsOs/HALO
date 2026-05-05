# WARDEN
## Windows Agent Runtime Defense & Enforcement Node
### Arquitectura de Seguridad Anti-Agente IA — Especificación Técnica v1.0

```
Stack: Rust · windows-drivers-rs · WFP · ETW · Minifilter · ratatui
Target: Windows 10/11 x64 · Secure Boot compatible
```

---

## ⚠️ Modelo de Amenaza

Los agentes de IA operan con acceso completo al filesystem, red y procesos del usuario. Los vectores de ataque documentados son:

| Vector | Mecanismo | Impacto |
|---|---|---|
| **Data exfiltration** | Lectura de `.env`, config, secrets → HTTP POST | Leak de API keys, tokens OAuth |
| **Filesystem destruction** | `DeleteFile` / `rmdir` recursivo por alucinación | Pérdida irreversible de proyectos |
| **Silent modification** | Escritura en archivos críticos sin confirmación | Corrupción de código, configs |
| **Registry harvesting** | Lectura de `HKCU\Software` buscando tokens guardados | Credenciales de IDEs, git, cloud |
| **Process hijacking** | Spawn de subprocesos no declarados | Ejecución arbitraria de código |
| **Clipboard siphon** | Lectura del portapapeles del usuario | Captura de passwords copiados |
| **Network bypass** | Conexión directa a C2 / exfiltración DNS | Exfiltración silenciosa |

---

## 🏗️ Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (TUI)                          │
│              ratatui · tokio · crossbeam-channel                    │
│         Políticas · Alertas en tiempo real · Audit log              │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ IPC (Named Pipe / shared memory)
          ┌───────────────┼───────────────────┐
          ▼               ▼                   ▼
┌──────────────┐  ┌──────────────┐   ┌──────────────────┐
│  LAYER 0     │  │  LAYER 1     │   │  LAYER 2         │
│  KERNEL CORE │  │  NET SHIELD  │   │  SHADOW HOOKS    │
│  Minifilter  │  │  WFP Engine  │   │  User-mode API   │
│  + Registry  │  │  + DPI       │   │  Hooking Layer   │
│  + Process   │  │  + TLS tap   │   │  (DLL injection) │
└──────┬───────┘  └──────┬───────┘   └────────┬─────────┘
       │                 │                     │
       └─────────────────┼─────────────────────┘
                         ▼
              ┌──────────────────────┐
              │      LAYER 3         │
              │  SEMANTIC ENGINE     │
              │  Entropy · Regex     │
              │  Behavioral scoring  │
              └──────────┬───────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
┌──────────────┐ ┌─────────────┐ ┌───────────────┐
│  LAYER 4     │ │  LAYER 5    │ │  LAYER 6      │
│  ETW SENSOR  │ │  ISOLATION  │ │  AUDIT VAULT  │
│  Kernel feed │ │  Job Objects│ │  Tamper-proof │
│  + audit     │ │  + Tokens   │ │  event store  │
└──────────────┘ └─────────────┘ └───────────────┘
```

---

## LAYER 0 — KERNEL CORE
### Minifilter Driver + Registry + Process Callbacks
**Rust crate:** `windows-drivers-rs` · **Signing:** EV cert requerido en producción

El núcleo duro. Opera en Ring 0. Nada pasa por el filesystem sin su aprobación.

### 0.1 — Minifilter Driver (IRP Interception)

Registra callbacks **pre-operación** sobre cada IRP del filesystem. El agente ni se entera.

```rust
// Callbacks registrados en FLT_OPERATION_REGISTRATION
IRP_MJ_CREATE          → PreCreate()      // Apertura de ficheros
IRP_MJ_WRITE           → PreWrite()       // Escritura
IRP_MJ_SET_INFORMATION → PreSetInfo()     // Delete / Rename / Move
IRP_MJ_READ            → PreRead()        // Lectura de ficheros sensibles
IRP_MJ_CREATE          → PostCreate()     // Auditoría post-acceso
```

**Lógica de decisión en `PreCreate()`:**
```
1. ¿El proceso requestor está en el registro de agentes vigilados?
   NO → PASS (sin overhead)
   SÍ → continuar evaluación

2. ¿El path está en zona protegida? (.env / *.key / id_rsa / secrets.*)
   SÍ + acceso de lectura → ALERT al Control Plane → esperar decisión usuario
   SÍ + acceso de escritura → BLOCK inmediato (FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED)

3. ¿El path está en zona de cuarentena? (/AppData del agente)
   → LOG sin bloquear (modo auditoría)
```

**Lógica de decisión en `PreSetInfo()` (el más crítico):**
```
FileDispositionInformation  → DeleteFile = TRUE  → BLOCK + ALERT CRÍTICO
FileDispositionInformationEx → POSIX delete       → BLOCK + ALERT CRÍTICO
FileRenameInformation       → rename fuera de zona → requiere confirmación
FileLinkInformation         → hard link a zona protegida → BLOCK
```

**Lógica de decisión en `PreRead()`:**
```
Path matches secret_patterns[] → ALERT al usuario
  → Si usuario deniega: FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED
  → Si permite: LOG + continuar
```

### 0.2 — Registry Callback (CmRegisterCallbackEx)

Los agentes buscan tokens en el registro. Esta capa los corta.

```rust
// Operaciones interceptadas
RegNtPreOpenKey         → apertura de hives sensibles
RegNtPreQueryValueKey   → lectura de valores específicos
RegNtPreSetValueKey     → escritura no autorizada en registro
```

**Hives protegidos por defecto:**
```
HKCU\Software\GitHub\*              → GitHub tokens
HKCU\Software\OpenAI\*              → API keys OpenAI
HKCU\Software\Anthropic\*           → API keys Anthropic
HKCU\Environment → OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS_*
HKLM\SYSTEM\CurrentControlSet\Services\* → servicios del sistema
```

### 0.3 — Process Notification (PsSetCreateProcessNotifyRoutineEx)

Intercepta la creación de cualquier proceso hijo lanzado por agentes vigilados.

```rust
// Callback ejecutado ANTES de que el proceso empiece a correr
fn on_process_create(info: &PS_CREATE_NOTIFY_INFO) {
    if parent_is_watched_agent(info.parent_pid) {
        if !is_whitelisted_binary(info.image_name) {
            // Opción A: Deny creation
            info.creation_status = STATUS_ACCESS_DENIED;
            // Opción B: Allow con token restringido (ver Layer 5)
            inject_restricted_token(info.process);
        }
    }
}
```

### 0.4 — Object Callbacks (ObRegisterCallbacks)

Protege el propio proceso guardián de ser terminado por el agente.

```rust
// Stripa permisos PROCESS_TERMINATE y PROCESS_VM_WRITE
// sobre el proceso warden cuando cualquier agente intenta obtener un handle
OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS
  con access_state.remaining_desired_access &= ~PROCESS_TERMINATE
```

---

## LAYER 1 — NET SHIELD
### Windows Filtering Platform (WFP) + Deep Packet Inspection
**Rust crate:** `windows-sys` (fwpuclnt.dll) · **Sin kernel signing** para modo user-mode

Control total sobre la red de cada agente. Opera en la pila TCP/IP, antes de que el dato salga de la máquina.

### 1.1 — WFP User-Mode Engine

WFP tiene una API accesible desde user-mode sin necesidad de driver. Se registra un **shim de filtrado** por proceso.

```rust
// Capas WFP utilizadas
FWPM_LAYER_ALE_AUTH_CONNECT_V4    // Control de conexiones salientes (por proceso)
FWPM_LAYER_ALE_AUTH_CONNECT_V6    // IPv6
FWPM_LAYER_STREAM_V4              // Inspección de contenido del stream
FWPM_LAYER_DATAGRAM_DATA_V4       // UDP (exfiltración DNS)
```

**Política por proceso:**
```
Agent process → solo puede conectar a:
  - dominios en whitelist (api.openai.com, api.anthropic.com, etc.)
  - puertos 80/443 únicamente

Cualquier otro destino → BLOCK + LOG con dst IP, port, bytes intentados
```

### 1.2 — Deep Packet Inspection (DPI) Pre-TLS

El truco: se intercepta en **WinHTTP/WinINet** (user-mode, antes del cifrado TLS), no en el paquete cifrado.

Via hook de `WinHttpSendRequest` y `HttpSendRequestW`:

```rust
fn hook_winhttp_send(request: HINTERNET, headers: &[u8], body: &[u8]) {
    // 1. Pasar body al Semantic Engine
    let verdict = semantic_engine::scan(body);
    
    match verdict {
        Verdict::Clean => call_original(request, headers, body),
        
        Verdict::SecretDetected { pattern, excerpt } => {
            alert_user(format!("AGENTE INTENTÓ ENVIAR: {pattern} → {excerpt}"));
            // Bloquear o sanitizar antes de enviar
            let sanitized = redact_secrets(body);
            call_original(request, headers, &sanitized);
        }
        
        Verdict::HighEntropy { entropy_score } => {
            alert_user(format!("PAYLOAD SOSPECHOSO entropy={entropy_score:.2}"));
            // Requiere confirmación usuario
        }
    }
}
```

### 1.3 — DNS Exfiltration Guard

Los agentes avanzados pueden exfiltrar datos codificados en queries DNS. WARDEN monitorea via WFP UDP layer:

```
- Query length > 63 chars en un subdominio → SUSPICIOUS
- Alta entropía en subdomain label → SUSPICIOUS  
- Frecuencia > N queries/seg al mismo dominio → RATE LIMIT + ALERT
- Destinos DNS no estándar (no 8.8.8.8, 1.1.1.1, DNS local) → BLOCK
```

---

## LAYER 2 — SHADOW HOOKS
### User-Mode API Interception (Sin kernel signing)
**Rust crates:** `retour` · `dll-syringe` · **Sin EV cert necesario**

La capa de intercepción en espacio de usuario. Se inyecta en el proceso del agente y engancha sus llamadas Win32 antes de que lleguen al kernel. Compatible con agentes que ya están corriendo.

### 2.1 — DLL de Intercepción

Una DLL de Rust ultra-ligera (<200KB) inyectada en el proceso del agente vía `CreateRemoteThread` + `LoadLibrary`.

```rust
// Hooks instalados al cargar la DLL (DLL_PROCESS_ATTACH)
static HOOKS: &[(&str, &str, *const ())] = &[
    // Filesystem
    ("kernel32", "CreateFileW",      hook_create_file      as _),
    ("kernel32", "WriteFile",        hook_write_file       as _),
    ("kernel32", "DeleteFileW",      hook_delete_file      as _),
    ("kernel32", "MoveFileExW",      hook_move_file        as _),
    ("kernel32", "RemoveDirectoryW", hook_remove_dir       as _),
    // Registry
    ("advapi32", "RegOpenKeyExW",    hook_reg_open         as _),
    ("advapi32", "RegQueryValueExW", hook_reg_query        as _),
    // Network (pre-TLS)
    ("winhttp",  "WinHttpSendRequest",   hook_winhttp      as _),
    ("wininet",  "HttpSendRequestW",     hook_wininet      as _),
    ("ws2_32",   "WSASend",              hook_wsa_send     as _),
    // Process
    ("kernel32", "CreateProcessW",   hook_create_proc      as _),
    // Clipboard
    ("user32",   "GetClipboardData", hook_clipboard        as _),
];
```

### 2.2 — Hook de DeleteFile (Ejemplo concreto)

```rust
#[hook]
unsafe fn hook_delete_file(lp_file_name: LPCWSTR) -> BOOL {
    let path = wide_to_string(lp_file_name);
    
    // Enviar al Control Plane vía Named Pipe
    let event = AgentEvent {
        kind: EventKind::FileDelete,
        path: path.clone(),
        process: current_process_name(),
        timestamp: now(),
    };
    
    let verdict = ipc::send_and_wait(event);
    
    match verdict {
        Verdict::Allow  => original_delete_file(lp_file_name),
        Verdict::Block  => {
            SetLastError(ERROR_ACCESS_DENIED);
            FALSE
        }
        Verdict::Prompt => {
            // El usuario tiene 10 segundos para responder
            // Si no responde → BLOCK por defecto (fail-safe)
            if user_confirmed_within(Duration::from_secs(10)) {
                original_delete_file(lp_file_name)
            } else {
                SetLastError(ERROR_ACCESS_DENIED);
                FALSE
            }
        }
    }
}
```

### 2.3 — Hook de GetClipboardData

```rust
#[hook]
unsafe fn hook_clipboard(u_format: UINT) -> HANDLE {
    let event = AgentEvent {
        kind: EventKind::ClipboardRead,
        process: current_process_name(),
        ..
    };
    
    // Limpia el portapapeles si contiene datos sensibles (password managers, etc.)
    // antes de devolvérselo al agente
    let content = peek_clipboard_content(u_format);
    if semantic_engine::is_sensitive(&content) {
        alert_user("AGENTE INTENTÓ LEER EL PORTAPAPELES");
        return NULL; // Devuelve vacío
    }
    
    original_get_clipboard_data(u_format)
}
```

---

## LAYER 3 — SEMANTIC ENGINE
### Motor de Detección de Secretos e Intención Maliciosa
**Rust crates:** `regex` · `shannon-entropy` · operación en memoria pura

El cerebro de WARDEN. Recibe datos raw (paths, payloads de red, contenido de ficheros) y determina si contienen información sensible o patrones de comportamiento peligroso.

### 3.1 — Biblioteca de Patrones de Secretos

```rust
pub static SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern { name: "Anthropic API Key",  regex: r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{93}" },
    SecretPattern { name: "OpenAI API Key",     regex: r"sk-[a-zA-Z0-9]{48}" },
    SecretPattern { name: "OpenAI Proj Key",    regex: r"sk-proj-[a-zA-Z0-9_-]{82}" },
    SecretPattern { name: "AWS Access Key",     regex: r"AKIA[0-9A-Z]{16}" },
    SecretPattern { name: "AWS Secret Key",     regex: r"[0-9a-zA-Z/+]{40}" },  // con contexto
    SecretPattern { name: "GitHub Token",       regex: r"gh[pousr]_[A-Za-z0-9_]{36,255}" },
    SecretPattern { name: "Google API Key",     regex: r"AIza[0-9A-Za-z\-_]{35}" },
    SecretPattern { name: "Stripe Secret",      regex: r"sk_live_[0-9a-zA-Z]{24,}" },
    SecretPattern { name: "Slack Bot Token",    regex: r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}" },
    SecretPattern { name: "Azure Storage Key",  regex: r"[a-zA-Z0-9+/]{86}==" },
    SecretPattern { name: "Private Key (PEM)",  regex: r"-----BEGIN (RSA |EC )?PRIVATE KEY-----" },
    SecretPattern { name: "JWT Token",          regex: r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\." },
    SecretPattern { name: "Generic Bearer",     regex: r"Bearer\s+[a-zA-Z0-9\-._~+/]{20,}" },
    SecretPattern { name: "Connection String",  regex: r"(mongodb|postgresql|mysql|redis)://[^\s]+" },
];
```

### 3.2 — Análisis de Entropía (Shannon)

Strings de alta entropía = probablemente un secreto, aunque no matchee ningún patrón conocido.

```rust
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

// Clasificación
// entropy > 4.5 + longitud > 20 chars → SUSPICIOUS
// entropy > 5.5 + longitud > 32 chars → LIKELY SECRET
// entropy > 6.5                       → HIGH CONFIDENCE SECRET
```

### 3.3 — Motor de Scoring Comportamental

No solo detecta un evento aislado. Evalúa **secuencias de comportamiento**:

```rust
// Scoring acumulado por sesión de agente
struct BehaviorScore {
    read_env_files: u8,         // +30 pts por .env leído
    read_config_files: u8,      // +20 pts por config.* leído
    read_key_files: u8,         // +40 pts por *.key / id_rsa leído
    outbound_connections: u8,   // +10 pts por conexión a nuevo host
    subprocess_spawned: u8,     // +25 pts por proceso hijo no whitelisted
    high_entropy_writes: u8,    // +35 pts por escritura de datos alta entropía
    registry_reads: u8,         // +20 pts por lectura de hives sensibles
    files_deleted: u8,          // +50 pts por cada fichero borrado
    clipboard_access: u8,       // +30 pts por lectura de portapapeles
}

// Umbrales de alerta
score >= 50  → YELLOW: notificación silenciosa al usuario
score >= 80  → ORANGE: popup de alerta, bloqueo preventivo
score >= 120 → RED:    suspensión del agente + dump forense completo
```

### 3.4 — Clasificador de Ficheros Sensibles

```rust
pub fn classify_path(path: &Path) -> Sensitivity {
    match path {
        p if matches_any(p, &["*.env", ".env.*", "*.pem", "*.key", "id_rsa*"])
            => Sensitivity::Critical,   // Bloqueo inmediato
        
        p if matches_any(p, &["*secret*", "*token*", "*credential*", "*password*"])
            => Sensitivity::High,       // Alerta + confirmación
        
        p if matches_any(p, &["*.config", "*.cfg", "*.toml", "*.yaml", "*.json"])
          && is_in_project_root(p)
            => Sensitivity::Medium,     // Log + notificación suave
        
        _   => Sensitivity::Normal,     // Pass-through
    }
}
```

---

## LAYER 4 — ETW SENSOR
### Event Tracing for Windows — Feed de Kernel en Tiempo Real
**Rust crate:** `ferrisetw` · **Sin signing** necesario · Lectura pura

ETW da acceso a los eventos del kernel sin modificarlos. Es la capa de observabilidad y correlación.

```rust
// Providers subscritos
let providers = vec![
    // Actividad de filesystem a nivel kernel
    "Microsoft-Windows-Kernel-File",
    // Creación/terminación de procesos
    "Microsoft-Windows-Kernel-Process",  
    // Actividad de red (conexiones, DNS)
    "Microsoft-Windows-Kernel-Network",
    // Actividad de registro
    "Microsoft-Windows-Kernel-Registry",
    // Carga de imágenes (DLLs, drivers)
    "Microsoft-Windows-Kernel-Audit-API-Calls",
];
```

**Uso práctico:** ETW actúa como sistema de auditoría independiente. Incluso si un agente bypasea los hooks de Layer 2 (llamando syscalls directamente), ETW lo verá y lo registrará para correlación post-incidente.

```
Flow:
  Kernel ETW event
    → ferrisetw consumer (Rust async)
      → filtrado por PID de agentes vigilados
        → correlación con behavioral scorer (Layer 3)
          → almacenamiento en Audit Vault (Layer 6)
```

---

## LAYER 5 — ISOLATION ENGINE
### Process Token Hardening + Job Objects
**Rust crate:** `windows-sys` · **Sin signing** · Aplica en el momento de spawn

Si WARDEN lanza el agente (o lo detecta al inicio), puede aplicar restricciones a nivel de token de proceso.

### 5.1 — Restricted Token

```rust
fn spawn_agent_sandboxed(cmd: &str) -> Result<HANDLE> {
    // 1. Crear token restringido del proceso actual
    let restricted = CreateRestrictedToken(
        current_token,
        DISABLE_MAX_PRIVILEGE,   // elimina todos los privilegios no esenciales
        sids_to_disable,         // deshabilita grupos de admin
        privileges_to_delete,    // elimina SeDebugPrivilege, SeBackupPrivilege, etc.
        restricted_sids,         // SIDs de solo-deny (nunca allow)
    )?;
    
    // 2. Lanzar el agente con ese token
    CreateProcessWithTokenW(restricted, cmd, ...)
}
```

### 5.2 — Job Object Limits

```rust
fn apply_job_limits(job: HANDLE) {
    SetInformationJobObject(job, JobObjectBasicLimitInformation, &BasicLimits {
        active_process_limit: 8,        // máx subprocesos
        per_job_user_time_limit: ...,   // CPU limit
    });
    
    SetInformationJobObject(job, JobObjectBasicUIRestrictions, &UILimits {
        ui_restrictions_class:
            JOB_OBJECT_UILIMIT_READCLIPBOARD    |  // sin lectura de portapapeles
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD   |  // sin escritura al portapapeles
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |  // sin cambiar config del sistema
            JOB_OBJECT_UILIMIT_DESKTOP          |  // sin crear escritorios
            JOB_OBJECT_UILIMIT_EXITWINDOWS,        // sin apagar/reiniciar
    });
}
```

---

## LAYER 6 — AUDIT VAULT
### Almacenamiento Forense Tamper-Proof
**Rust crates:** `sled` / `sqlite` · HMAC-SHA256 chaining

Cada evento genera un registro inmutable. Si el agente intenta modificar o borrar el log, el minifilter (Layer 0) lo bloquea.

```rust
struct AuditEntry {
    id:         u64,
    timestamp:  i64,           // UNIX nanoseconds
    pid:        u32,
    process:    String,
    event_kind: EventKind,
    path:       Option<String>,
    verdict:    Verdict,
    score:      u8,            // behavioral score en ese momento
    prev_hash:  [u8; 32],      // hash del entry anterior (blockchain-style)
    hash:       [u8; 32],      // HMAC-SHA256(entry content || prev_hash, key)
}
```

El vault es una cadena de hashes. Cualquier manipulación retroactiva rompe la cadena → detectable.

---

## CONTROL PLANE — TUI
### Terminal UI en tiempo real
**Rust crates:** `ratatui` · `tokio` · `crossterm` · `toml`

```
┌─────────────────────────────────────────────────────────────────┐
│  WARDEN v1.0  │  Agent: claude-desktop (PID 4821)  │  🔴 ALERT │
├─────────────────────────────────────────────────────────────────┤
│ LIVE EVENTS                              │ BEHAVIORAL SCORE     │
│                                          │                      │
│ 14:23:01 🔴 DELETE  /projects/api.env   │  ████████░░  82/120  │
│ 14:23:00 🟡 READ    .env (blocked)      │                      │
│ 14:22:58 🟡 NET     POST api.third.com  │ RISK: ██████ HIGH    │
│ 14:22:55 🟢 WRITE   /tmp/output.txt     │                      │
│ 14:22:50 🟢 READ    /src/main.rs        │ [A]llow [B]lock [?]  │
├─────────────────────────────────────────┴──────────────────────┤
│ PROTECTED ZONES                          ACTIVE AGENTS         │
│  ✓ /home/user/.env files                 • claude-desktop ⚠️   │
│  ✓ /home/user/.ssh/*                     • cursor (idle)       │
│  ✓ Registry HKCU\Software\*              • codex (monitoring)  │
│  ✓ /projects/**/*.key                                          │
└─────────────────────────────────────────────────────────────────┘
```

**Comandos disponibles:**
```
[a] allow         Permitir acción pendiente
[b] block         Bloquear acción pendiente
[s] suspend       Suspender agente activo
[p] policy        Editar política (abre config.toml)
[l] log           Ver audit log completo
[q] quit
```

---

## Stack de Dependencias

```toml
[dependencies]
# Core Windows APIs
windows-sys = { version = "0.52", features = ["Win32_*"] }

# Kernel driver (minifilter, WFP callout)
windows-drivers-rs = { git = "https://github.com/microsoft/windows-drivers-rs" }

# API Hooking (Layer 2)
retour = "0.3"           # Detour-style inline hooking, pure Rust
dll-syringe = "0.15"    # DLL injection en procesos target

# ETW Consumer (Layer 4)
ferrisetw = "0.6"        # Windows ETW consumer en Rust

# Terminal UI (Control Plane)
ratatui = "0.27"
crossterm = "0.27"

# Async runtime
tokio = { version = "1", features = ["full"] }

# IPC entre componentes
crossbeam-channel = "0.5"

# Semantic Engine
regex = "1.10"           # Pattern matching para secrets

# Serialización / Config
serde = { version = "1", features = ["derive"] }
toml = "0.8"

# Audit Vault
sled = "0.34"            # Embedded DB tamper-proof
hmac = "0.12"
sha2 = "0.10"
```

---

## Deployment Matrix

| Modo | Capas activas | Signing requerido | Cobertura |
|---|---|---|---|
| **Free / Dev** | 2 + 3 + 4 + 5 + 6 | ❌ Ninguno | ~80% |
| **Standard** | 1 + 2 + 3 + 4 + 5 + 6 | ❌ Ninguno | ~90% |
| **Full** | 0 + 1 + 2 + 3 + 4 + 5 + 6 | ✅ EV cert (~300€/año) | ~99% |

> **Recomendación de lanzamiento:** publicar en modo Standard (sin EV cert). Cubre el 90% de los ataques de los agentes actuales. La capa kernel (Layer 0) se puede añadir en una versión Pro.

---

## Por Qué Esto Es Inbypaseable Para Los Agentes Actuales

Los agentes actuales (Claude Desktop, Cursor, Codex, Windsurf) operan todos a través de:

1. **Win32 APIs estándar** → cubiertos por Layer 2 (hooks)
2. **WinHTTP/WinINet para red** → cubiertos por Layer 1 (WFP + hooks pre-TLS)
3. **CreateFile/WriteFile/DeleteFile** → cubiertos por Layer 0 (minifilter) y Layer 2 (hooks)

Un bypass requeriría que el agente hiciera **syscalls directas al kernel** saltándose Win32 completamente (técnica conocida como *Direct Syscalls* o *Syscall Unhooking*). Esto es:
- Imposible desde Python/Node/los runtimes que usan estos agentes
- Detectable via ETW incluso si ocurriera (Layer 4)
- Bloqueado completamente si Layer 0 está activo

**Conclusión:** ningún agente de IA comercial actual puede bypassear esta arquitectura en modo Standard, y ninguno puede bypassear Layer 0 bajo ninguna circunstancia sin comprometer el kernel del sistema operativo completo — lo que activaría Windows Defender y PatchGuard antes de que el agente llegue a intentarlo.

---

*WARDEN — Built in Rust. Zero garbage collection. Zero mercy.*