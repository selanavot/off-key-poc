# FANNG-MPC build/run environment.
#
# The framework requires x86 AES-NI + PCLMULQDQ and is only supported on
# Ubuntu <= 20.04.  On Apple Silicon we therefore build & run it inside a
# linux/amd64 Ubuntu 20.04 container (Docker emulates x86_64; the emulated
# CPU exposes aes/pclmul/sse4.1 but NOT avx/bmi2/adx, so the project must be
# compiled WITHOUT those flags -- see docker/run.sh and the avx_memcpy.h patch).
FROM --platform=linux/amd64 ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Stage 1: apt dependencies
#   crypto++ is built from source below (the project includes it as
#   "cryptopp/..." which the apt layout does not provide); everything else
#   (openssl 1.1.1, boost, cereal, mysql-cppconn) comes from apt on focal.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make m4 yasm curl wget unzip cmake git ca-certificates pkg-config \
        libboost-dev libmysqlcppconn-dev libcereal-dev libssl-dev \
        python2 python2-dev \
        vim less procps psmisc gdb \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# MPIR 3.0.0 -> /opt/mpir   (not packaged for focal; build from source)
# ---------------------------------------------------------------------------
RUN cd /opt \
 && curl -fSL -o mpir-3.0.0.tar.bz2 'https://src.fedoraproject.org/lookaside/extras/mpir/mpir-3.0.0.tar.bz2/sha512/c735105db8b86db739fd915bf16064e6bc82d0565ad8858059e4e93f62c9d72d9a1c02a5ca9859b184346a8dc64fa714d4d61404cff1e405dc548cbd54d0a88e/mpir-3.0.0.tar.bz2' \
 && tar xf mpir-3.0.0.tar.bz2 \
 && cd mpir-3.0.0 \
 && ./configure --enable-cxx --prefix=/opt/mpir \
 && make -j"$(nproc)" && make install \
 && cd /opt && rm -rf mpir-3.0.0 mpir-3.0.0.tar.bz2

# ---------------------------------------------------------------------------
# crypto++ 8.2.0 -> /opt/cryptopp
#   (runtime CPU-feature detection means its AVX paths are skipped on the
#    emulated CPU, so it is safe to use the upstream build as-is)
# ---------------------------------------------------------------------------
RUN cd /opt \
 && wget -q https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_2_0/cryptopp820.zip \
 && unzip -q cryptopp820.zip -d cryptopp820 \
 && cd cryptopp820 \
 && make -j"$(nproc)" && make install PREFIX=/opt/cryptopp \
 && cd /opt && rm -rf cryptopp820 cryptopp820.zip

# ---------------------------------------------------------------------------
# Python 2 pip + numpy (compile-mamba.py runs under python2)
# ---------------------------------------------------------------------------
RUN curl -fSL -o /tmp/get-pip.py https://bootstrap.pypa.io/pip/2.7/get-pip.py \
 && python2 /tmp/get-pip.py \
 && (python2 -m pip install numpy || echo "numpy (py2) optional - continuing") \
 && rm -f /tmp/get-pip.py

# ---------------------------------------------------------------------------
# Rust, pinned to the toolchain in ./rust-toolchain (nightly-2021-01-15).
# Needed by ./scasm (the scale_repo_helper assembler) at compile time.
# ---------------------------------------------------------------------------
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/opt/openssl/bin:${PATH}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain nightly-2021-01-15 --profile minimal \
 && rustup target add wasm32-unknown-unknown

# ---------------------------------------------------------------------------
# Include / library search paths (mirrors installation/export-variables.txt).
# openssl/boost/cereal/mysql come from the default /usr paths.
# ---------------------------------------------------------------------------
ENV C_INCLUDE_PATH=/opt/mpir/include:/opt/cryptopp/include \
    CPLUS_INCLUDE_PATH=/opt/mpir/include:/opt/cryptopp/include \
    LIBRARY_PATH=/opt/mpir/lib:/opt/cryptopp/lib \
    LD_LIBRARY_PATH=/opt/mpir/lib:/opt/cryptopp/lib
# NOTE: do NOT set CARGO_TARGET_DIR away from <ROOT>/target -- the scasm helper
# (Assembler/src/bin/scale_repo_helper.rs) locates the workspace Cargo.toml as
# current_exe/../../../Cargo.toml, i.e. it requires the build dir to be
# /fanng/target.  Leaving it unset makes cargo use /fanng/target by default.

WORKDIR /fanng
CMD ["/bin/bash"]
