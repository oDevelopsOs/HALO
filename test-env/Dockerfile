# AgentGuard test environment — Ubuntu 24.04 con kernel host (eBPF LSM requerido)
# Uso: docker build -t agentguard-test . && docker run --rm -it --privileged \
#       -v /sys:/sys:rw -v $(pwd)/../..:/workspace agentguard-test
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    libssl-dev \
    linux-tools-common \
    linux-tools-generic \
    bpftool \
    bpftrace \
    strace \
    curl \
    git \
    sudo \
    tree \
    jq \
    iproute2 \
    procps \
    psmisc \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Rust stable + nightly (nightly necesario para compilar agentguard-ebpf)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup toolchain install nightly --profile minimal \
    && rustup component add rust-src --toolchain nightly \
    && rustup target add bpfel-unknown-none --toolchain nightly \
    && rustup component add clippy rustfmt

# bpf-linker para compilar programas eBPF de aya
RUN cargo install bpf-linker --locked

# Layout de prueba: /protected es la zona que el daemon debe proteger
RUN mkdir -p /protected/test-zone /protected/secrets /workspace \
    && echo "CONTENIDO IMPORTANTE — NO BORRAR" > /protected/test-zone/important.md \
    && echo "OPENAI_API_KEY=sk-test1234567890abcdef1234567890abcdef12345678" > /protected/secrets/.env \
    && echo "datos arbitrarios" > /protected/test-zone/data.txt \
    && mkdir -p /protected/test-zone/nested \
    && echo "archivo anidado" > /protected/test-zone/nested/deep.md

# Scripts del entorno
COPY run-tests.sh /usr/local/bin/run-tests.sh
COPY verify_protection.sh /usr/local/bin/verify_protection.sh
COPY simulate_ai_agent.rs /opt/test-env/simulate_ai_agent.rs
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/run-tests.sh \
             /usr/local/bin/verify_protection.sh \
             /usr/local/bin/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
