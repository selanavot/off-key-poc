# Self-contained build of SCALE-MAMBA for the cross-run MAC-key PoC.
#
# SCALE-MAMBA needs x86 AES-NI/PCLMULQDQ and Ubuntu <= 20.04, so we build &
# run it as linux/amd64 (Docker emulates x86_64 via Rosetta/QEMU). The emulated
# CPU lacks AVX/BMI2/ADX, so the runtime is compiled with a reduced ISA and the
# one source file that uses AVX unconditionally (Tools/avx_memcpy.h) is replaced
# with an #ifdef-guarded copy (patches/avx_memcpy.h). That patch is the ONLY
# source change and does not touch the protocol; everything else is upstream.
#
#   docker build --platform linux/amd64 -t scale-mamba-attack .
#   ./run-attack.sh                       # see README.md
FROM --platform=linux/amd64 ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# --- dependencies (SCALE-MAMBA does not link MySQL) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make m4 yasm curl wget unzip cmake git ca-certificates pkg-config \
        libboost-dev libcereal-dev libssl-dev \
        python2 python2-dev python3 \
        vim less procps psmisc gdb \
    && rm -rf /var/lib/apt/lists/*

# --- MPIR 3.0.0 -> /opt/mpir ---
RUN cd /opt \
 && curl -fSL -o mpir-3.0.0.tar.bz2 'https://src.fedoraproject.org/lookaside/extras/mpir/mpir-3.0.0.tar.bz2/sha512/c735105db8b86db739fd915bf16064e6bc82d0565ad8858059e4e93f62c9d72d9a1c02a5ca9859b184346a8dc64fa714d4d61404cff1e405dc548cbd54d0a88e/mpir-3.0.0.tar.bz2' \
 && tar xf mpir-3.0.0.tar.bz2 && cd mpir-3.0.0 \
 && ./configure --enable-cxx --prefix=/opt/mpir && make -j"$(nproc)" && make install \
 && cd /opt && rm -rf mpir-3.0.0 mpir-3.0.0.tar.bz2

# --- crypto++ 8.2.0 -> /opt/cryptopp (runtime CPU detection skips AVX paths) ---
RUN cd /opt \
 && wget -q https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_2_0/cryptopp820.zip \
 && unzip -q cryptopp820.zip -d cryptopp820 && cd cryptopp820 \
 && make -j"$(nproc)" && make install PREFIX=/opt/cryptopp \
 && cd /opt && rm -rf cryptopp820 cryptopp820.zip

# --- python2 numpy (compile-mamba.py) ---
RUN curl -fSL -o /tmp/get-pip.py https://bootstrap.pypa.io/pip/2.7/get-pip.py \
 && python2 /tmp/get-pip.py && (python2 -m pip install numpy || true) && rm -f /tmp/get-pip.py

# --- Rust, pinned to SCALE-MAMBA's rust-toolchain (nightly-2021-01-15) ---
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:${PATH}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain nightly-2021-01-15 --profile minimal \
 && rustup target add wasm32-unknown-unknown

ENV C_INCLUDE_PATH=/opt/mpir/include:/opt/cryptopp/include \
    CPLUS_INCLUDE_PATH=/opt/mpir/include:/opt/cryptopp/include \
    LIBRARY_PATH=/opt/mpir/lib:/opt/cryptopp/lib \
    LD_LIBRARY_PATH=/opt/mpir/lib:/opt/cryptopp/lib \
    CARGO_TARGET_DIR=/scale/target \
    USE_RUST=0

# --- clone SCALE-MAMBA at a pinned commit ---
ARG SCALE_COMMIT=c111516e3ebc1efd12a2bd47dd2122b160e13d1e
RUN git clone https://github.com/KULeuven-COSIC/SCALE-MAMBA.git /scale \
 && cd /scale && git checkout "$SCALE_COMMIT"
WORKDIR /scale

# --- the single source patch (AVX -> #ifdef-guarded) + build config ---
COPY patches/avx_memcpy.h /scale/src/Tools/avx_memcpy.h

# --- Section 4.4 recovery instrumentation (env-gated; attacker-only at runtime) ---
# Adds the OFFKEY_RECOVER path to the unmasked MAC check so the malicious party
# can invert the opened check value and read the honest input y outright. Gated
# on an env var, so an honest party running the same binary is unaffected.
COPY patches/offkey_recover.py /scale/patches/offkey_recover.py
RUN python3 /scale/patches/offkey_recover.py /scale/src/LSSS/Open_Protocol.cpp

RUN printf 'ROOT = /scale\nOSSL = /usr\nMAX_MOD = 7\nMAX_GFP = 3\nFLAGS = -DMAX_MOD_SZ=$(MAX_MOD) -DMAX_GFP_SZ=$(MAX_GFP)\nOPT = -O3\nLDFLAGS =\n' > CONFIG.mine

# --- build the runtime with the reduced (no-AVX) instruction set ---
RUN make -C src ARCH='-maes -mpclmul -msse4.1 -march=core2 -mtune=generic' -j"$(nproc)"

# --- 2-party Full Threshold, 128-bit prime (variant 18) ---
RUN cp Auto-Test-Data/18/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/

# --- attack programs + tooling; compile bytecode (also builds the scasm assembler) ---
COPY Programs/attack_store   /scale/Programs/attack_store
COPY Programs/attack_open    /scale/Programs/attack_open
COPY Programs/attack_recover /scale/Programs/attack_recover
COPY Programs/attack_affine  /scale/Programs/attack_affine
COPY patcher.py poc.sh /scale/poc/
RUN ./compile-new.sh Programs/attack_store \
 && ./compile-new.sh Programs/attack_open \
 && ./compile-new.sh Programs/attack_recover \
 && ./compile-new.sh Programs/attack_affine

CMD ["/bin/bash"]
