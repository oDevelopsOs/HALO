//! eBPF LSM hook: filesystem.
//!
//! Scaffold de Fase 0. La implementación real (hooks `file_unlink`,
//! `file_rename`, `file_open`, array map `PROTECTED_PREFIXES`, ring buffer
//! `FILE_EVENTS`) llega en Fase 1.5.
//!
//! Cuando se compile para el target `bpfel-unknown-none` este archivo será
//! `#![no_std] #![no_main]` con los attrs de aya. Por ahora es un stub
//! nativo vacío para que el workspace se compile en host durante Fase 0.

fn main() {
    // Placeholder: el binario real nunca se ejecutará en userspace.
    // Se convertirá en programa BPF en Fase 1.5.
}
