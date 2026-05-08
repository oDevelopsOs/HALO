//! Build script del daemon AgentGuard para Linux.
//!
//! Con `--features ebpf`: copia los bytecodes eBPF pre-compilados a OUT_DIR
//! para que `include_bytes_aligned!` los pueda embeber en el binario.
//!
//! Los bytecodes deben generarse ANTES con: scripts/build-ebpf.sh

fn main() {
    #[cfg(feature = "ebpf")]
    embed_ebpf_bytecode();
}

#[cfg(feature = "ebpf")]
fn embed_ebpf_bytecode() {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bytecode_dir = manifest.join("../../target/ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let any_missing = ["file_guard", "net_guard", "process_exec"]
        .iter()
        .any(|n| !bytecode_dir.join(n).exists());

    if any_missing {
        println!(
            "cargo:warning=\n\
             ═══════════════════════════════════════════════\n\
             eBPF bytecode not found in {}\n\n\
             Build it first with: ./scripts/build-ebpf.sh\n\n\
             Daemon will compile WITHOUT eBPF support.\n\
             Kernel-level blocking will be unavailable;\n\
             userspace observation-only fallback will be used.\n\
             ═══════════════════════════════════════════════",
            bytecode_dir.display()
        );
        // Write an empty placeholder so include_bytes_aligned! doesn't fail.
        // At runtime, EbpfGuard::try_load will detect and skip gracefully.
        for name in &["file_guard", "net_guard", "process_exec"] {
            let dst = out_dir.join(format!("{name}.bpf.o"));
            let _ = fs::write(&dst, b"\0");
        }
        return;
    }

    for name in &["file_guard", "net_guard", "process_exec"] {
        let src = bytecode_dir.join(name);
        let dst = out_dir.join(format!("{name}.bpf.o"));
        fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy {src:?} → {dst:?}: {e}"));
    }

    println!(
        "cargo:rerun-if-changed={}",
        bytecode_dir.join("file_guard").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        bytecode_dir.join("net_guard").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        bytecode_dir.join("process_exec").display()
    );
    println!("cargo:rerun-if-changed=../../scripts/build-ebpf.sh");
    println!("cargo:rerun-if-changed=../agentguard-ebpf/src/");
}
