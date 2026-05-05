# Entorno de desarrollo — AgentGuard

Guía para levantar el entorno de desarrollo y pruebas en una máquina limpia.
Para el **entorno de pruebas aislado** (donde lanzar simuladores de agentes
maliciosos contra el daemon) ver `test-env/README.md`.

---

## 1. Requisitos

### Host

- Linux (preferente: Ubuntu 22.04+ o Fedora 38+). Windows es secundario hasta Fase 4.
- Rust stable + nightly (se gestiona vía `rust-toolchain.toml`).
- `clang`, `llvm`, `libelf-dev`, `pkg-config`, `libssl-dev` para compilar bpf-linker y dependencias nativas.
- Docker 24+ **o** Multipass **o** libvirt si quieres levantar la VM de pruebas.

### Kernel

Para que el daemon cargue los hooks eBPF LSM reales necesitas:

- Kernel ≥ 5.7 (recomendado 6.x).
- `CONFIG_BPF_LSM=y` en la configuración del kernel.
- BPF listado en los LSM activos (`cat /sys/kernel/security/lsm` debe incluir `bpf`).

Si tu host no los tiene, el daemon cae al fallback userspace (crate `notify`) — útil para desarrollo pero sin la garantía kernel-level.

Para activar BPF LSM en Ubuntu 22.04+:

```bash
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf"/' /etc/default/grub
sudo update-grub
sudo reboot
# verificar tras reiniciar:
cat /sys/kernel/security/lsm   # debe contener ',bpf'
```

---

## 2. Setup inicial (host)

```bash
git clone <repo-url> HALO
cd HALO

# Rust se instala automáticamente al leer rust-toolchain.toml
cargo --version

# Dependencias de sistema (Ubuntu/Debian)
sudo apt install -y build-essential clang llvm libelf-dev pkg-config libssl-dev

# Dependencias de sistema (Fedora)
sudo dnf install -y @development-tools clang llvm elfutils-libelf-devel pkgconf-pkg-config openssl-devel

# Build de verificación
cargo build --workspace
cargo test --workspace
```

---

## 3. VM de pruebas (Multipass)

Recomendado si tu host no tiene BPF LSM o si no quieres arriesgar tu kernel.

```bash
# Crear VM
multipass launch 24.04 --name agentguard-dev --cpus 2 --memory 4G --disk 20G

# Habilitar BPF LSM dentro de la VM
multipass exec agentguard-dev -- bash -c '
    sudo sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf\"/" /etc/default/grub
    sudo update-grub'
multipass restart agentguard-dev
multipass exec agentguard-dev -- cat /sys/kernel/security/lsm   # verificar

# Montar el repo
multipass mount "$PWD" agentguard-dev:/home/ubuntu/HALO

# Entrar y compilar
multipass shell agentguard-dev
# dentro:
sudo apt install -y build-essential clang llvm libelf-dev pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
cd HALO && cargo build --workspace
```

---

## 4. Entorno de pruebas Docker (test-env)

Para ejecutar la suite automatizada contra agentes maliciosos simulados, ver el documento dedicado en `test-env/README.md`. TL;DR:

```bash
docker build -t agentguard-test -f test-env/Dockerfile test-env
docker run --rm -it --privileged --cap-add=ALL \
    -v /sys:/sys:rw -v "$(pwd):/workspace" agentguard-test
# dentro:
run-tests.sh
```

---

## 5. Workflow de desarrollo recomendado

1. Edita código en el host (mejor soporte de IDE).
2. `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
3. Para cambios que tocan `kernel_loader.rs` o `agentguard-ebpf/`: ejecuta `run-tests.sh` en la VM o en Docker.
4. Commit solo cuando CI local pasa.

---

## 6. Layouts de datos en desarrollo

| Recurso | Ruta (user mode) |
|---|---|
| Config | `~/.agentguard/config.toml` |
| Vault | `~/.agentguard/vault/` |
| Incidents | `~/.agentguard/incidents.jsonl` |
| Socket IPC | `~/.agentguard/daemon.sock` |
| CA root | `~/.agentguard/ca/` (perms `0600`) |

En modo servicio estas rutas viven bajo `/var/lib/agentguard/` y `/run/agentguard/` — ver `.windsurf/rules/07-paths-and-privileges.md`.

---

## 7. Troubleshooting

**`cargo build` falla con `linker cc not found`**
Falta `build-essential` (Debian/Ubuntu) o `@development-tools` (Fedora).

**`permission denied` al cargar BPF**
El proceso necesita `CAP_BPF` + `CAP_SYS_ADMIN`. Corre como root durante
desarrollo o configura las capabilities via `setcap`.

**`/sys/kernel/security/lsm` no contiene `bpf`**
Ver sección 1 (activar BPF LSM). Alternativa rápida: usa la VM de pruebas (sección 3) que viene ya configurada.

**`aya` no encuentra BTF**
Instala `dwarves` (`sudo apt install dwarves`) o `pahole` y verifica que exista `/sys/kernel/btf/vmlinux`.
