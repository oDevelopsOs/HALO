# AgentGuard — Entorno de pruebas seguro

**Campo de batalla aislado** para verificar que AgentGuard bloquea todo lo que un
agente de IA en malas manos intentaría hacer. Nada de lo que se ejecuta aquí
puede tocar tu `$HOME` del host.

---

## TL;DR

```bash
# desde la raíz del repo HALO:
docker build -t agentguard-test -f test-env/Dockerfile test-env
docker run --rm -it \
  --privileged \
  --cap-add=ALL \
  -v /sys:/sys:rw \
  -v "$(pwd):/workspace" \
  agentguard-test

# dentro del contenedor:
run-tests.sh
```

---

## Qué incluye

| Archivo | Propósito |
|---|---|
| `Dockerfile` | Ubuntu 24.04 + Rust stable/nightly + toolchain eBPF (clang, llvm, bpftool, bpf-linker). |
| `entrypoint.sh` | Banner informativo + chequeo de BPF LSM al entrar. |
| `simulate_ai_agent.rs` | **El "agente loco"**: intenta 8 ataques distintos (unlink, rename, rm -rf, sobrescribir `.env`, crear malware, truncar archivos, symlink escape, exfiltración DLP). Exit code 1 si todo fue bloqueado, 0 si algo se rompió. |
| `run-tests.sh` | Suite automatizada de 12 tests: entorno → build → arranque daemon → ataques → vault snapshot/restore → DLP. |
| `verify_protection.sh` | Check manual rápido: estado del kernel, daemon, socket IPC, hash de los archivos protegidos. |

---

## Layout dentro del contenedor

```
/workspace              ← tu repo HALO montado (read-write)
/protected/
├── test-zone/          ← zona protegida por AgentGuard
│   ├── important.md
│   ├── data.txt
│   └── nested/deep.md
└── secrets/
    └── .env            ← contiene API key falsa para probar DLP
/opt/test-env/
└── simulate_ai_agent.rs
/usr/local/bin/
├── run-tests.sh
├── verify_protection.sh
└── entrypoint.sh
```

---

## Requisitos del host

- Docker Engine 24+ o Podman 4+.
- **Kernel 5.7+ con BPF LSM habilitado** si quieres probar la protección real a
  nivel kernel. Verifícalo así:

  ```bash
  cat /sys/kernel/security/lsm   # debe contener "bpf"
  ```

  Si no lo incluye, edita `/etc/default/grub` añadiendo `lsm=...,bpf` en
  `GRUB_CMDLINE_LINUX_DEFAULT`, corre `sudo update-grub` y reinicia. La mayoría
  de Ubuntu 24.04+ ya lo traen.

- Sin BPF LSM el daemon cae al modo userspace (`notify` crate) y los tests
  marcados como kernel-level se saltan automáticamente (resultado `SKIP`).

---

## Flujo recomendado

### 1. Construir la imagen (una vez)

```bash
docker build -t agentguard-test -f test-env/Dockerfile test-env
```

### 2. Arrancar el contenedor con el repo montado

```bash
docker run --rm -it \
  --privileged \
  --cap-add=ALL \
  -v /sys:/sys:rw \
  -v "$(pwd):/workspace" \
  agentguard-test
```

Flags explicados:

- `--privileged --cap-add=ALL`: necesario para cargar programas eBPF LSM.
- `-v /sys:/sys:rw`: el loader de eBPF consulta `/sys/kernel/security/lsm` y
  usa bpffs (`/sys/fs/bpf`).
- `-v $(pwd):/workspace`: montaje del código fuente.

### 3. Suite completa

```bash
run-tests.sh
```

Output esperado cuando AgentGuard funciona:

```
 Resumen:  12 pass  /  0 fail  /  0 skip
```

### 4. Ataque manual interactivo

```bash
# compila el simulador
rustc --edition 2021 /opt/test-env/simulate_ai_agent.rs -O -o /tmp/rogue

# en otra terminal (o background) arranca el daemon:
/workspace/target/release/agentguard-daemon --protect /protected/test-zone &

# lanza el agente loco:
/tmp/rogue /protected/test-zone
```

Esperado: `✓ BLOCKED` en los 8 ataques y exit code 1.

---

## Alternativas al Dockerfile

### Multipass (VM real con su propio kernel)

```bash
multipass launch 24.04 --name agentguard-test --cpus 2 --memory 4G --disk 20G
multipass mount . agentguard-test:/workspace
multipass shell agentguard-test
# dentro: sudo apt install docker.io && sigue los pasos Docker arriba,
# o compila y corre el daemon directamente.
```

Ventaja: aísla incluso del kernel del host; si tu host no tiene BPF LSM, la VM
sí puede traerlo.

### systemd-nspawn (ligero, sin Docker)

```bash
sudo debootstrap noble /var/lib/machines/agentguard
sudo systemd-nspawn -D /var/lib/machines/agentguard \
    --bind=/sys --bind="$(pwd):/workspace" --capability=all
```

---

## ¿Qué prueba exactamente?

| # | Escenario | Ataque | Resultado esperado |
|---|---|---|---|
| 1 | Borrado directo | `unlink(important.md)` | EPERM |
| 2 | Sobrescritura de secreto | `truncate(.env) + write` | EPERM |
| 3 | Renombrar la zona | `rename(zone, zone_DELETED)` | EPERM |
| 4 | `rm -rf` recursivo | `remove_dir_all(zone)` | EPERM |
| 5 | Plantar malware | `write(zone/malware.sh)` | EPERM |
| 6 | Truncar anidado | `truncate(zone/nested/deep.md)` | EPERM |
| 7 | Symlink TOCTOU | `symlink + unlink via link` | EPERM |
| 8 | Exfiltración | `curl -X POST --data @.env` | HTTP 403 del DLP |

Extras en `run-tests.sh`: vault snapshot + restore, persistencia de hash,
chequeo del daemon tras matar al atacante, arranque del proxy DLP.

---

## Troubleshooting

**`docker: Error response from daemon: ... privileged`**
El daemon de Docker rechaza `--privileged` en modo rootless. Usa root:
`sudo docker run ...` o instala Docker en modo rootful.

**`failed to load BPF program: operation not permitted`**
El kernel del host no tiene BPF LSM activo. El contenedor usa el kernel del
host. Activa BPF LSM (ver "Requisitos") o usa Multipass.

**`run-tests.sh` marca todo como SKIP**
El daemon aún no está compilado en `target/release/`. Ejecuta
`cargo build --release` primero o espera a completar Fase 1 del plan.

---

## Seguridad del entorno

- El contenedor corre con `--privileged` porque cargar eBPF LSM lo requiere.
  **Nunca** corras imágenes de terceros con estas flags.
- Los secretos en `/protected/secrets/.env` son **falsos** — cadenas con
  formato de API key pero sin valor real. Seguros para probar el DLP.
- El simulador solo opera sobre el path que le pases como argumento. Nunca le
  pases `/` ni `$HOME`: siempre `/protected/test-zone`.
