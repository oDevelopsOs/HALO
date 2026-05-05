# AGENTS.md — Protocolo de trabajo seguro para AgentGuard (HALO)

> **Objetivo:** que cualquier agente de IA (incluido tú mismo en sesiones futuras)
> siga este protocolo al modificar este proyecto. Evita errores catastróficos,
> mantiene la integridad del código y garantiza que cada cambio es verificable.

---

## 1. Seguridad ante todo — Reglas no negociables

### 1.1 Backup antes de cualquier cambio estructural

Antes de modificar la estructura de crates, renombrar archivos, mover módulos o
refactorizar:

```bash
# Crear branch de respaldo con timestamp
git branch backup/$(date +%Y%m%d-%H%M%S)
git log --oneline -3  # confirmar que el último commit es el correcto
```

Si el cambio es pequeño (un solo archivo, un fix puntual), hacer backup del archivo:

```bash
cp ruta/archivo.rs ruta/archivo.rs.bak
```

### 1.2 Nunca borrar sin red

- **Nunca** usar `rm -rf` sobre código fuente sin tener backup en git
- **Mover** archivos con `git mv` (o copy + delete solo cuando el build nuevo funciona)
- **No eliminar** el código viejo hasta que el código nuevo compila y pasa tests
- Si un crate queda obsoleto, renombrarlo a `crates/.archived/NOMBRE` en vez de borrarlo

### 1.3 Commits atómicos y verificables

- Un commit = un cambio lógico (un módulo migrado, un fix)
- El mensaje sigue el formato: `feat(scope): descripción` o `fix(scope): descripción`
- Después de cada commit, verificar que build + tests pasan
- **Nunca** commitear código que no compila

### 1.4 Ramas de trabajo

```
main                ← solo código probado y estable
backup/pre-faseX    ← snapshot antes de empezar cada fase
feat/NOMBRE         ← ramas de feature
fix/NOMBRE          ← ramas de bugfix
```

---

## 2. Estructura de trabajo por sesión

### 2.1 Checklist de inicio de sesión

```markdown
[ ] Leer AGENTS.md (este archivo)
[ ] Leer PlanDeImplementacion.md para saber en qué fase estamos
[ ] Verificar `git status` — no debe haber cambios sin commitear
[ ] Verificar `cargo build --workspace --exclude agentguard-ebpf` — debe compilar
[ ] Verificar `cargo test --workspace --exclude agentguard-ebpf` — deben pasar
[ ] Anotar en qué archivos voy a trabajar
```

### 2.2 Flujo de trabajo por cada módulo/archivo

```
1. Leer el archivo actual (Read tool)
2. Entender sus dependencias (imports, crate::, super::)
3. Planificar el cambio (anotar qué imports hay que actualizar)
4. Escribir el nuevo archivo (Write tool) o editar (Edit tool)
5. Build: cargo build --workspace --exclude agentguard-ebpf
6. Si falla → corregir → volver a paso 5
7. Si compila → Tests: cargo test -p NOMBRE_CRATE
8. Si pasan → siguiente módulo
```

### 2.3 Verificación post-sesión

```markdown
[ ] cargo build --workspace --exclude agentguard-ebpf (0 errores)
[ ] cargo test --workspace --exclude agentguard-ebpf (todos pasan)
[ ] cargo clippy --workspace --exclude agentguard-ebpf -- -D warnings (0 warnings)
[ ] git status (solo cambios intencionados)
[ ] Actualizar CHANGELOG.md si es un cambio visible
[ ] Actualizar PlanDeImplementacion.md si cambia el roadmap
```

---

## 3. Reglas específicas del proyecto

### 3.1 Estructura de crates

```
crates/
├── agentguard-common/       Tipos compartidos (no_std + std), IPC protocol
├── agentguard-core/         Lógica compartida del daemon (todas las plataformas)
│   └── NO contiene implementaciones de guard específicas de SO
├── agentguard-linux/        Binario Linux (eBPF + userspace fallback)
├── agentguard-windows/      Binario Windows (Fase 4)
├── agentguard-ebpf/         Programas eBPF kernel (compilación separada, nightly)
├── agentguard-tui/         TUI terminal (ratatui + crossterm)
├── agentguard-cli/          CLI cross-platform (único binario para todos)
```

### 3.2 Dónde va cada cosa

| Tipo de código | Crate destino |
|---|---|---|
| Tipos FFI (no_std) | `agentguard-common` |
| Config, Vault, DLP, CA, IPC, eventos, guard trait | `agentguard-core` |
| eBPF loader (aya), userspace notify | `agentguard-linux` |
| NTFS ACLs, Job Objects, Win Service | `agentguard-windows` |
| Comandos CLI, output formateado | `agentguard-cli` |
| Scripts de instalación | `agentguard-installer` |
| Dashboard, Zones, Incidents UI | `agentguard-tui` |

### 3.3 Imports correctos

```rust
// Dentro de agentguard-core:
use crate::config::Config;        // crate:: → el propio crate
use crate::events::SecurityEvent;

// Desde agentguard-linux hacia core:
use agentguard_core::{KernelGuard, GuardError};
use agentguard_core::config::Config;

// Tipos comunes desde cualquier crate:
use agentguard_common::{IpcCommand, IpcResponse, PathPrefix};
```

### 3.4 Features condicionales

- `agentguard-linux` usa `#[cfg(feature = "ebpf")]` para aya
- Sin `--features ebpf`, el daemon Linux compila con solo userspace fallback
- `agentguard-windows` está en el workspace (Fase 4+8 completadas)

---

## 4. Políticas de código (Windsurf rules existentes)

Las reglas en `.windsurf/rules/` siguen vigentes:

| Archivo | Regla |
|---|---|
| `01-rust-style.md` | fmt, clippy, edition 2021, thiserror/anyhow, docstrings |
| `02-no-unwrap.md` | Prohibido `.unwrap()` en prod. Usar `?` + tipos de error |
| `03-ebpf-safety.md` | eBPF `#![no_std]`, fail-open, bounds check |
| `04-security-logging.md` | Nunca loggear valores de secretos |
| `05-testing.md` | Tests unitarios obligatorios en cada módulo nuevo |
| `06-ipc-contract.md` | `IpcCommand`/`IpcResponse` inmutable sin bump de versión |
| `07-paths-and-privileges.md` | Permisos 600/700, paths root vs usuario |

---

## 5. Testing

### 5.1 Comando de tests

```bash
cargo test --workspace --exclude agentguard-ebpf
```

### 5.2 Mínimo requerido

- Cada `pub fn` en `agentguard-core` debe tener al menos 1 test
- Cambios en vault, DLP, o guard requieren test de integración
- Nunca debilitar tests existentes
- Si un test se ignora (`#[ignore]`), documentar por qué

### 5.3 Tests por crate (estado actual, Mayo 2026 — post-Fase 8)

| Crate | Tests | Estado |
|---|---|---|
| `agentguard-common` | 3 | OK |
| `agentguard-core` | 62 (60 unit + 2 E2E ignorados) | OK |
| `agentguard-linux` | 18 (15 unit + 3 integración) | OK |
| `agentguard-tui` | 0 | OK |
| `agentguard-cli` | 11 | OK |
| `agentguard-windows` | 7 unit + 15 E2E (solo Windows) | OK |
| **Total** | **99 passed + 2 ignored + 15 Windows-only** | **0 fallos** |

---

## 6. CI/CD

### 6.1 Checks pre-commit (local)

```bash
cargo fmt --check
cargo clippy --workspace --exclude agentguard-ebpf -- -D warnings
cargo test --workspace --exclude agentguard-ebpf
grep -rn "\.unwrap()\|\.expect(" crates/*/src  # debe ser 0 en prod
```

### 6.2 Build eBPF (solo cuando se modifica agentguard-ebpf)

```bash
./scripts/build-ebpf.sh
cargo build -p agentguard-linux --features ebpf
```

---

## 7. Glosario rápido

| Término | Significado |
|---|---|
| **HALO** | Nombre clave del proyecto |
| **AgentGuard** | Nombre público del producto |
| **Guard** | Backend de protección (eBPF, userspace, Windows) |
| **Vault** | Sistema de snapshots con deduplicación BLAKE3 |
| **DLP** | Data Loss Prevention — proxy HTTP/HTTPS que detecta secretos |
| **MITM** | Man-in-the-Middle — interceptación HTTPS con CA local |
| **IPC** | Inter-Process Communication — socket Unix entre daemon y CLI |
| **LSM** | Linux Security Modules — hooks del kernel donde corre eBPF |
| **Terminal-first** | La CLI es la interfaz primaria; la UI es secundaria/opcional |

---

## 8. Plan de fases (resumen actualizado)

| Fase | Estado | Descripción |
|---|---|---|
| **0** | ✓ Completada | Reorganización de crates (core + linux + stubs) |
| **1** | ✓ Completada | Core funcional — 60 tests, 0 unwrap en prod, 0 warnings |
| **2** | ✓ Completada | Linux daemon funcional (eBPF + userspace, systemd, VM tests, SIGTERM, incidentes disk) |
| **3** | ✓ Completada | CLI cross-platform + installer con detección de SO |
| **4** | ✓ Completada | Windows daemon (NTFS DENY ACEs + Job Objects) |
| **5** | — Eliminada | macOS daemon — fuera de scope MVP |
| **6** | ✓ Completada | TUI Terminal (ratatui + crossterm, 4 tabs) |
| **7** | ✓ Completada | Auto-updater (ureq 3, GitHub Releases, SHA256) |
| **8** | ✓ Completada | Windows hardening (AppContainer, PEB, Named Pipes, tests E2E) |

---

> **Última actualización:** 2026-05-05 — Fase 8: hardening Windows completo. AppContainer, PEB, Named Pipes, 15 tests E2E. 99 tests, 0 warnings.
> **Backup más reciente:** `backup/pre-fase0`
