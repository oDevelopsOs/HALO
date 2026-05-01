---
trigger: glob
globs: crates/agentguard-ebpf/**/*.rs
description: Safety rules for eBPF kernel-side code
---

# eBPF Safety

Aplica a todo código en `crates/agentguard-ebpf/`.

- **Siempre** `#![no_std]` y `#![no_main]` en cada archivo con programas BPF.
- **Bucles:** todos los bucles DEBEN tener un bound estático conocido por el verifier. Usar constantes como `MAX_PREFIXES`, `MAX_PREFIX_LEN`. Romper con `if i >= count { break; }` dentro del bucle.
- **Fail-open:** si un helper del kernel (`bpf_d_path`, `bpf_probe_read_kernel`, etc.) devuelve error, el hook DEBE retornar `0` (permitir), nunca denegar por error interno. Romper el sistema del usuario por un bug del BPF es inaceptable.
- **Lecturas de memoria kernel:** usar siempre `bpf_probe_read_kernel` o `bpf_probe_read_user`; **nunca** dereferenciar punteros crudos directamente.
- **`unsafe`:** cada bloque requiere `// SAFETY:` explicando los invariantes del verifier que hacen la operación correcta.
- **Tamaño de stack:** los programas BPF tienen stack limitado (512 bytes). Buffers grandes (>256 B) van en map arrays (`PerCpuArray`, `Array`), no en variables locales.
- **Maps:**
  - El tamaño (`max_entries`) es fijo en compile-time.
  - Documentar quién escribe (kernel/userspace) y quién lee en un comentario sobre la declaración del map.
- **Ring buffers:** siempre reservar con `reserve()` y `submit(0)`; si `reserve` devuelve `None`, descartar el evento silenciosamente (no bloquear el hook).
- **Logs:** `aya_log_ebpf::info!` solo para debug temporal. Eliminar antes de merge.
- **Panic handler:** `#[panic_handler]` obligatorio con `loop {}` — un panic en BPF no es recuperable.
