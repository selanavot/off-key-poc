#!/usr/bin/env bash
# Cross-run MAC-key attack on FANNG-MPC Full Threshold, applied to EXAMPLE 2:
# private affine evaluation  f(x; (y, r)) = x * y + r. FANNG is a SCALE-MAMBA
# fork; this mirrors ../scale-mamba/run-affine.sh (see that README for analysis).
#
# The honest party P0 holds y (run 1) and a 64-bit uniform mask r (run 2); the
# attacker P1 holds x. The output z = x*y + r is masked by r, which the attacker
# does not know, so it reveals nothing about y for the small x used here. Yet the
# off-key restart turns complete-vs-abort into a selective-failure oracle: run 2
# completes iff y == guess. Unlike Example 1 (x = 0, whose zero output is
# trivially simulatable), leaking y here is a genuine violation of malicious
# security -- the ideal functionality reveals only the masked x*y+r.
#
# Prerequisite: a running FANNG container named `fanng` with the repo at /fanng,
# built via the Crypto-TII/FANNG-MPC docker harness:
#     docker/run.sh build && docker/run.sh up && docker/run.sh progs
#
# Usage: ./run-affine.sh [guess] [secret] [x]
#   ./run-affine.sh 1 1          # y == guess -> COMPLETE -> attacker learns y = 1
#   ./run-affine.sh 1 4          # y != guess -> ABORT    -> attacker learns y != 1
#   FAKE=1 ./run-affine.sh 1 1   # fast, low-memory trusted-dealer offline
set -euo pipefail
cd "$(dirname "$0")"

GUESS="${1:-1}"
SECRET="${2:-1}"
X="${3:-1}"
# Honest party's mask r. Example 2's privacy wants r uniform over the whole
# field, but the attack is independent of r's distribution, and the
# SCALE-MAMBA/FANNG clear input path is only 64-bit, so we sample r uniformly
# over [0, 2^64) -- ample for the small x used here. (A full-field uniform mask is the
# theoretical ideal.)
R=$(python3 -c "import secrets; print(secrets.randbits(64))")   # 64-bit uniform mask r
CONTAINER=fanng
FAKE="${FAKE:-0}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "error: container '$CONTAINER' is not running."
  echo "Build FANNG first via its docker harness (in the FANNG-MPC repo):"
  echo "    docker/run.sh build && docker/run.sh up && docker/run.sh progs"
  exit 1
fi

echo "=== FANNG-MPC cross-run attack on Example 2: f(x;(y,r)) = x*y + r ==="
echo "Attacker's guess:      g = $GUESS ,  attacker's x = $X"
echo "Honest party's secret: y = $SECRET   (known only to the honest party)"
echo "Honest party's random: r = $R   (uniform 64-bit mask, hidden from the attacker)"
echo "Legitimate output x*y+r hides y for the small x used here (attack is independent of r)."
[ "$FAKE" = 1 ] && echo "Offline: trusted-dealer (FAKE=1) + -dOT  (fast, low memory)" \
                || echo "Offline: FHE/BGV (real, default) + -dOT  (needs native x86, >= 32 GB RAM; FAKE=1 for fast low-memory run)"
echo

# Install variant 18 (2-party Full Threshold, 128-bit), sync the attack program
# and the current poc scripts, and (re)compile the bytecode.
docker exec "$CONTAINER" bash -lc 'cp Auto-Test-Data/18/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/ && mkdir -p /fanng/poc /fanng/Programs/attack_store /fanng/Programs/attack_affine' >/dev/null
docker cp poc.sh     "$CONTAINER":/fanng/poc/poc.sh     >/dev/null
docker cp patcher.py "$CONTAINER":/fanng/poc/patcher.py >/dev/null
docker cp Programs/attack_store/attack_store.mpc   "$CONTAINER":/fanng/Programs/attack_store/attack_store.mpc   >/dev/null
docker cp Programs/attack_affine/attack_affine.mpc "$CONTAINER":/fanng/Programs/attack_affine/attack_affine.mpc >/dev/null
docker exec "$CONTAINER" bash -lc './compile-new.sh Programs/attack_store >/dev/null 2>&1 && ./compile-new.sh Programs/attack_affine >/dev/null 2>&1' \
  || { echo "error: failed to compile the attack programs (is the runtime built? see run-affine prerequisites)"; exit 1; }

poc() { docker exec -e FAKE="$FAKE" -e QUIET=1 -e AFF_X="$X" -e AFF_R="$R" "$CONTAINER" bash -lc "bash /fanng/poc/poc.sh $*"; }

echo "--- Run 1: honest party stores its secret y (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1, adds guess g=$GUESS to y's MAC) ---"
if poc affine "guess:$GUESS"; then verdict=complete; else verdict=abort; fi

echo
echo "=== RESULT ==="
if [ "$verdict" = complete ]; then
  echo "Protocol COMPLETED  ->  guess CORRECT  ->  the attacker learns y = $GUESS"
else
  echo "Protocol ABORTED (mac_fail)  ->  guess WRONG  ->  the attacker learns y != $GUESS"
fi
echo
echo "The revealed output x*y+r is masked by the honest party's r, so it reveals"
echo "nothing about y; the secret leaks purely through complete-vs-abort. The"
echo "honest party ran the unmodified FANNG binary in both runs; only P1's own"
echo "MKey-1.key and Memory-P1 were edited between them."
