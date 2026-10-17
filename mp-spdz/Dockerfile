FROM python:3.10-bullseye

# Bullseye is oldstable: the live mirrors' package indices name point-release
# versions whose .debs the pools have already superseded, so a plain
# `apt-get update` then install 404s. Pin apt to an immutable snapshot, which
# retains every historical .deb, so the index and pool always agree.
RUN printf '%s\n' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250601T000000Z bullseye main' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250601T000000Z bullseye-updates main' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20250601T000000Z bullseye-security main' \
    > /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        automake build-essential clang-11 cmake git \
        libboost-dev libboost-thread-dev libboost-filesystem-dev \
        libboost-iostreams-dev libclang-dev libgmp-dev \
        libsodium-dev libssl-dev libtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/MP-SPDZ

# Pin to a specific pre-fix MP-SPDZ commit for reproducibility.
#
# 58d2739 (2026-03-31) is after the v0.4.2 release and before the fix. The
# cross-thread MAC-key vulnerability this PoC exploits was fixed in MP-SPDZ
# v0.4.3 (2026-07-06, commit 982e91e), so this attack does NOT reproduce on
# v0.4.3 or later. Do not bump this pin if you want the demo to work.
ARG MPSPDZ_COMMIT=58d2739ac251262c0bd6034f7fc7d0666a6b1e2c
RUN git init && git remote add origin https://github.com/data61/MP-SPDZ.git \
    && git fetch --depth 1 origin $MPSPDZ_COMMIT \
    && git checkout FETCH_HEAD \
    && git submodule update --init --recursive

# Configure build
RUN echo "CXX = clang++-11" >> CONFIG.mine \
    && echo "USE_NTL = 0" >> CONFIG.mine \
    && echo "MY_CFLAGS += -I/usr/local/include" >> CONFIG.mine \
    && echo "MY_LDLIBS += -Wl,-rpath -Wl,/usr/local/lib -L/usr/local/lib" >> CONFIG.mine

# Fix ARM compatibility (harmless no-ops on x86)
RUN sed -i 's/static uint16_t _sse2neon_aggregate_equal_ordered_8x16(int bound,/static uint16_t _sse2neon_aggregate_equal_ordered_8x16(int __attribute__((unused)) bound,/' deps/sse2neon/sse2neon.h \
    && sed -i 's/static uint16_t _sse2neon_aggregate_equal_ordered_16x8(int bound,/static uint16_t _sse2neon_aggregate_equal_ordered_16x8(int __attribute__((unused)) bound,/' deps/sse2neon/sse2neon.h \
    && sed -i '/LIBSIMPLEOT_ASM/d' Makefile \
    && cd deps/SimplestOT_C/ref10 && cmake . && make && cd /usr/src/MP-SPDZ

# Build dependencies and mascot-party.x
RUN make clean-deps boost libote && make -j4 mascot-party.x
