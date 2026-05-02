//! Build script del daemon AgentGuard.
//!
//! Con `--features ebpf`: copia los bytecodes eBPF pre-compilados a OUT_DIR
//! para que `include_bytes_aligned!` los pueda embeber en el binario.
//!
//! Los bytecodes deben generarse ANTES con: scripts/build-ebpf.sh
//! Si no existen, la compilación con --features ebpf falla con un mensaje claro.

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
    // scripts/build-ebpf.sh deposita los binarios en target/ebpf/
    let bytecode_dir = manifest.join("../../target/ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    for name in &["file_guard", "net_guard"] {
        let src = bytecode_dir.join(name);
        if !src.exists() {
            panic!(
                "\n========================================\n\
                 eBPF bytecode not found: {src:?}\n\n\
                 Build it first with:\n\
                 \t./scripts/build-ebpf.sh\n\n\
                 Or disable the eBPF feature:\n\
                 \tcargo build --no-default-features\n\
                 ========================================",
            );
        }
        let dst = out_dir.join(format!("{name}.bpf.o"));
        fs::copy(&src, &dst)
            .unwrap_or_else(|e| panic!("copy {src:?} → {dst:?}: {e}"));
    }

    println!(
        "cargo:rerun-if-changed={}",
        bytecode_dir.join("file_guard").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        bytecode_dir.join("net_guard").display()
    );
    println!("cargo:rerun-if-changed=../../scripts/build-ebpf.sh");
    println!("cargo:rerun-if-changed=../agentguard-ebpf/src/");
}
