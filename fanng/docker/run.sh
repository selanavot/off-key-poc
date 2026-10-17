#!/usr/bin/env bash
#
# Build and drive the FANNG-MPC linux/amd64 container on Apple Silicon (or any
# host).  The framework needs x86 AES-NI/PCLMULQDQ; we run it under Docker's
# linux/amd64 emulation.  The emulated CPU lacks AVX/BMI2/ADX, so the C++
# runtime is compiled with a reduced instruction set (ARCH_NOAVX below) and the
# avx_memcpy.h AVX path is #ifdef-guarded.
#
# Usage:
#   docker/run.sh build          # build the image (slow, one-time)
#   docker/run.sh up             # start a background container with repo mounted
#   docker/run.sh progs          # compile the C++ runtime (PlayerBinary.x/SetupBinary.x)
#   docker/run.sh variant [N]    # install protocol variant N data+certs (default 1 = Shamir)
#   docker/run.sh compile <prog> # compile a Programs/<prog> (.mpc -> bytecode)
#   docker/run.sh shell          # interactive shell inside the container
#   docker/run.sh exec <cmd...>  # run an arbitrary command in the container
#   docker/run.sh down           # remove the container
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="fanng-mpc:focal"
CONTAINER="fanng"
# Reduced ISA for the emulated x86_64 CPU (no avx/bmi2/adx).
ARCH_NOAVX='-maes -mpclmul -msse4.1 -march=core2 -mtune=generic'

up() {
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker run -d --name "$CONTAINER" --platform linux/amd64 \
      -e CARGO_TARGET_DIR=/fanng/target \
      -v "$REPO":/fanng -w /fanng "$IMAGE" sleep infinity >/dev/null
  elif ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker start "$CONTAINER" >/dev/null
  fi
}
dexec() { docker exec -i "$CONTAINER" bash -lc "$*"; }

case "${1:-}" in
  build)   docker build --platform linux/amd64 -t "$IMAGE" -f "$REPO/docker/Dockerfile" "$REPO" ;;
  up)      up ;;
  progs)   up; dexec "make -C src ARCH='$ARCH_NOAVX' -j\$(nproc)" ;;
  variant) up; N="${2:-1}"; dexec "cp Auto-Test-Data/$N/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/ && echo 'variant $N installed'" ;;
  compile) up; shift; dexec "./compile-new.sh Programs/$*" ;;  # bytecode only; does NOT rebuild the runtime
  shell)   up; docker exec -it "$CONTAINER" bash -l ;;
  exec)    up; shift; dexec "$*" ;;
  down)    docker rm -f "$CONTAINER" 2>/dev/null || true ;;
  *)       grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' ;;
esac
