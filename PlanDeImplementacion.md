# Plan de implementación AgentGuard (HALO)

Implementación incremental de AgentGuard en Rust siguiendo el spec del `README.md`, con MVP Linux-first (eBPF LSM + vault + DLP + CLI), reglas Windsurf para enforcement de calidad, y un entorno de pruebas aislado en VM/contenedor para validar sin riesgo al host.

---

## 0. Decisiones tomadas

- **Alcance MVP:** Linux (Ubuntu 22.04+). Windows/macOS/UI se posponen a fases 3-4.
- **Nombre:** `agentguard` en crates y binarios. Rebrand opcional a HALO al final de Fase 1 (branch `rebrand/halo`).
- **Lenguaje:** Rust edition 2021, toolchain `stable` + `nightly` (solo crate `agentguard-ebpf`).
- **Políticas no negociables** (de §2 README): cero `.unwrap()` en prod, `clippy -D warnings`, RAM<10MB, latencia<50ms.

---

## 1. Reglas Windsurf a crear (`.windsurf/rules/`)

Antes de escribir una sola línea de código productivo, crear estas reglas que aplicarán a todas las sesiones futuras en el workspace:

| Archivo | Contenido |
|---|---|
| `01-rust-style.md` | `cargo fmt` obligatorio; `clippy -D warnings`; edition 2021; usar `thiserror` para errores de librería, `anyhow` para binarios; docstrings en todos los `pub fn`. |
| `02-no-unwrap.md` | Prohibido `.unwrap()`, `.expect()`, `panic!()` fuera de tests y `build.rs`. Usar `?` + tipos de error propios. Excepción: `main()` puede usar `anyhow::Result`. |
| `03-ebpf-safety.md` | Código eBPF siempre `#![no_std]`, bucles con bound estático, fail-open en caso de error interno del hook, nunca hacer `bpf_probe_read` sin validar el puntero. Documentar cada uso de `unsafe`. |
| `04-security-logging.md` | **Nunca** loggear el valor de un secreto detectado — solo nombre del patrón + destino + proceso. Logs en formato JSON estructurado (`tracing` + `tracing-subscriber`). |
| `05-testing.md` | Todo módulo nuevo requiere tests unitarios. Cambios en `vault.rs`, `dlp_proxy.rs`, `kernel_loader.rs` requieren test de integración. No debilitar ni eliminar tests sin justificación explícita. |
| `06-ipc-contract.md` | `IpcCommand`/`IpcResponse` son el contrato daemon↔CLI↔UI. Cambios breaking requieren bump de versión de protocolo y nota en `CHANGELOG.md`. |
| `07-paths-and-privileges.md` | Vault/logs cuando corre como root → `/var/lib/agentguard/`. Modo usuario → `~/.agentguard/`. Nunca escribir a `/home` desde el daemon en modo root (solo leer). CA root para MITM en `ca/` con permisos 600. |

---

## 2. Entorno de pruebas seguro

**Requisito crítico:** nunca probar eBPF LSM o DENY ACEs en el host de desarrollo. El daemon puede bloquear `rm` en tu `~/Documents` real.

### Opción A — VM dedicada (recomendada para eBPF)

```bash
# Multipass o libvirt con Ubuntu 24.04 (kernel 6.8, BPF LSM activo)
multipass launch 24.04 --name agentguard-dev --cpus 2 --memory 4G --disk 20G
multipass exec agentguard-dev -- sudo apt install -y build-essential clang llvm \
    libelf-dev linux-headers-$(uname -r) pkg-config libssl-dev
# Habilitar BPF LSM (si no está ya):
multipass exec agentguard-dev -- sudo sed -i \
    's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf"/' \
    /etc/default/grub
multipass exec agentguard-dev -- sudo update-grub && multipass restart agentguard-dev
# Verificar: cat /sys/kernel/security/lsm  → debe incluir "bpf"
```

Montar el workspace: `multipass mount ~/Escritorio/Projects/HALO agentguard-dev:/home/ubuntu/agentguard`.

### Opción B — Contenedor privilegiado (más rápido para iterar userspace)

Útil para vault, DLP proxy, CLI, tests. **No** sirve para cargar eBPF LSM (necesita kernel del host — si el host no tiene BPF LSM, usar Opción A).

```dockerfile
# .devcontainer/Dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    curl build-essential clang llvm libelf-dev pkg-config libssl-dev git
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# ... etc
```

```bash
docker run --rm -it --privileged --cap-add=SYS_ADMIN --cap-add=BPF \
    -v $(pwd):/work -w /work agentguard-dev bash
```

### Datos de prueba aislados

Crear `tests/fixtures/sandbox/` con árbol sintético:

```
tests/fixtures/sandbox/
├── docs/          ← "protegido" en tests
├── secrets/       ← archivos con API keys falsos para DLP
│   └── .env       ← sk-test1234567890abcdef1234567890abcdef12345678
└── trash/         ← "no protegido" para verificar que sí se puede borrar
```

**Nunca** apuntar `protected_dirs` del config de test a `$HOME`. Siempre `$TMPDIR` o `tests/fixtures/sandbox/`.

### Script `./scripts/dev-reset.sh`

Reinstala el daemon en la VM, recarga systemd, limpia vault de pruebas — idempotente.

---

## 3. Fases de implementación

> Cada casilla `[ ]` = PR atómica + tests + review antes de pasar a la siguiente.

### Fase 0 — Bootstrap (día 1)

```
[ ] 0.1  Crear .windsurf/rules/*.md (sección 1)
[ ] 0.2  cargo new --workspace; Cargo.toml raíz con members y resolver = "2"
[ ] 0.3  Crear crates vacíos: agentguard-common, agentguard-daemon, agentguard-cli,
         agentguard-ebpf, agentguard-ui (stub), tests/integration
[ ] 0.4  .github/workflows/ci.yml (fmt + clippy + test)
[ ] 0.5  rust-toolchain.toml (stable) + configuración nightly solo para ebpf
[ ] 0.6  LICENSE-GPL, LICENSE-BSL, CHANGELOG.md
[ ] 0.7  .gitignore, rustfmt.toml, .editorconfig
[ ] 0.8  Provisionar VM de pruebas (sección 2) y documentar en docs/DEV_ENV.md
```

**Gate:** `cargo build --workspace` verde en host y en VM.

### Fase 1 — Core de protección Linux (semanas 1-3)

```
[ ] 1.1  agentguard-common: FileEvent, NetworkEvent, EventType, PathPrefix.
         no_std compatible, #[repr(C)]. Tests de layout con std::mem::size_of.
[ ] 1.2  agentguard-daemon/config.rs: deserialización de config.toml,
         validación (paths existen, regex válidos), expansión de "~".
[ ] 1.3  agentguard-daemon/vault.rs: create_snapshot, restore, list, cleanup.
         BLAKE3 para hashing, deduplicación por hash-as-filename.
[ ] 1.4  Tests: test_vault_create_and_restore, test_vault_cleanup,
         test_vault_deduplication, permisos Unix preservados.
[ ] 1.5  agentguard-ebpf/file_guard.rs: hook file_unlink + file_rename,
         array map PROTECTED_PREFIXES, ring buffer FILE_EVENTS.
         build.rs en daemon que compile los .bpf.o y los embeba con include_bytes_aligned!.
[ ] 1.6  agentguard-daemon/kernel_loader.rs: check_ebpf_lsm_support,
         load, populate prefixes, listen_events, add/remove_protected_path.
[ ] 1.7  Test manual en VM: `agentguard protect /tmp/sandbox/docs` →
         `rm /tmp/sandbox/docs/file.md` retorna EPERM. Evento llega al daemon.
[ ] 1.8  Fallback userspace con `notify` crate: misma API que EbpfGuard
         detrás de un trait `KernelGuard`. Seleccionar en runtime según kernel.
[ ] 1.9  Benchmark: RAM idle < 10 MB, CPU idle < 0.1% (documentar resultado).
```

**Gate:** test E2E en VM bloquea `unlink` real; fallback userspace funciona en contenedor sin BPF LSM.

### Fase 2 — DLP, IPC y daemon completo (semanas 4-5)

```
[ ] 2.1  dlp_proxy.rs: HTTP (hyper 1.x). Cargar DEFAULT_DLP_PATTERNS + custom.
         Test: request con sk-... → 403; request limpio → 200.
[ ] 2.2  CA root local con rcgen, persistencia en ~/.agentguard/ca/ (permisos 600).
         Instalación al trust store via install.sh (o skip en modo dev).
[ ] 2.3  HTTPS MITM: handle_connect_tunnel con tokio-rustls. Generar leaf certs
         on-the-fly por hostname, firmados por la CA local.
[ ] 2.4  Tests DLP: matriz patrón × acción (block/alert/log) × HTTP/HTTPS.
[ ] 2.5  daemon.rs: loop principal tokio::select!, handle_event, kill_process,
         send_desktop_notification (notify-rust), log_incident (JSONL append).
[ ] 2.6  ipc_server.rs: socket Unix con interprocess crate, serde JSON sobre newline-delimited.
         IpcCommand/IpcResponse completos. Versión del protocolo en el handshake.
[ ] 2.7  Detección de agent processes: leer /proc, match por exe/argv/env
         según config.agent_processes. Test con procesos sintéticos.
[ ] 2.8  Integración DLP→daemon: violación en proxy envía SecurityEvent al canal mpsc.
```

**Gate:** Daemon arranca, proxy DLP en :7771 bloquea API keys, IPC responde a `Status`, notificación desktop visible en VM.

### Fase 3 — CLI + packaging Linux (semana 6)

```
[ ] 3.1  agentguard-cli: clap derive, todos los subcomandos conectados al IPC.
[ ] 3.2  Output formateado: crossterm + tablas, colores (verde/rojo/amarillo).
[ ] 3.3  `agentguard init --defaults`: genera config.toml inicial.
[ ] 3.4  packaging/linux/install.sh: descarga release, verifica sha256,
         instala binarios, systemd unit, CA trust store, crea config.
[ ] 3.5  packaging/linux/agentguard.service: unit con capabilities restringidas.
[ ] 3.6  .github/workflows/release.yml: build x86_64 + aarch64, tar.gz + checksums.txt.
[ ] 3.7  Dogfooding: ejecutar `install.sh` en la VM limpia desde release de GitHub.
```

**Gate:** En VM limpia, `curl … | bash` deja el daemon corriendo, `agentguard status` funciona.

### Fase 4 — Windows + macOS + UI + auto-update (semanas 7-10)

```
[ ] 4.1  windows_guard: DENY ACEs con SetNamedSecurityInfoW, Job Objects,
         Windows Service via windows-service crate.
[ ] 4.2  Windows installer Inno Setup + firma (si hay cert disponible).
[ ] 4.3  macOS: System Extension en Swift con EndpointSecurity (requiere entitlement).
         XPC bridge al daemon Rust. Fallback chflags uchg en modo degraded.
[ ] 4.4  Tauri v2 + Svelte: Dashboard, Protected Zones, Incidents (§13 README).
[ ] 4.5  System tray + ventana principal. Tauri commands → IPC client.
[ ] 4.6  updater.rs: check GitHub releases, sha256 verify, atomic rename, reload.
[ ] 4.7  E2E en las 3 plataformas: checklist §20 del README.
```

**Gate:** Checklist pre-release (§20) verde en Linux + Windows + macOS.

---

## 4. Checklist de verificación continua

Ejecutar antes de cada merge a `main`:

- `cargo fmt --check && cargo clippy --workspace -- -D warnings`
- `cargo test --workspace --exclude agentguard-ebpf`
- Build eBPF: `cargo +nightly build -p agentguard-ebpf --target bpfel-unknown-none -Z build-std=core`
- `grep -rn "\.unwrap\(\)\|\.expect\(" crates/*/src` debe devolver 0 hits (excluyendo `#[cfg(test)]`).
- Benchmark RAM/CPU del daemon idle ≤ umbrales del README §2.

---

## 5. Entregables por fase

| Fase | Artefactos |
|---|---|
| 0 | Workspace + CI + VM funcionando |
| 1 | Binario daemon que bloquea unlink real en Linux + vault operativo |
| 2 | Proxy DLP HTTPS + daemon completo + IPC |
| 3 | Release v0.1.0 instalable vía `curl \| bash` en Ubuntu 22.04+ |
| 4 | v1.0: 3 OSes + UI + auto-update + checklist pre-release verde |

---

## 6. Riesgos y mitigaciones

- **eBPF LSM no disponible en host:** usar VM Ubuntu 24.04 (sección 2). Fallback userspace (1.8) cubre el resto.
- **`bpf_d_path` semantics en LSM hooks:** validado en kernel ≥5.10. Documentar versión mínima probada y fallback.
- **HTTPS MITM rompe pinning:** agentes con cert pinning rechazarán la CA. Mantener whitelist de hosts a no-MITM, configurable.
- **Rendimiento del verifier eBPF:** el bucle sobre `MAX_PREFIXES=64` puede fallar verify si se añaden hooks. Bound estático + `#[inline(always)]` para ayudar.
- **Root en el daemon:** usar `AmbientCapabilities` mínimo (§16 README), `ProtectHome=read-only`, `ProtectSystem=strict`.
