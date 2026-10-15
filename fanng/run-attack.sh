#!/usr/bin/env bash
# Cross-run MAC-key selective-failure attack on FANNG-MPC Full Threshold. Pick
# the honest secret and the attacker's guess; learn whether the guess was right
# from whether the protocol completes. Same attack as ../scale-mamba/ (FANNG is a
# SCALE-MAMBA fork); see README.md.
#
# Prerequisite: a running FANNG container named `fanng` with the repo at /fanng,
# built via the Crypto-TII/FANNG-MPC docker harness:
#     docker/run.sh build && docker/run.sh up && docker/run.sh progs
#
# Usage: ./run-attack.sh [guess] [secret]
#   ./run-attack.sh 5 5          # correct guess -> COMPLETE -> attacker learns y = 5
#   ./run-attack.sh 5 4          # wrong guess   -> ABORT    -> attacker learns y != 5
# Default offline is real FHE/BGV (needs native x86, >= 32 GB RAM; OOMs under Mac
# emulation). For a fast, low-memory run use the trusted-dealer offline:
#   FAKE=1 ./run-attack.sh 5 5
set -euo pipefail
cd "$(dirname "$0")"

GUESS="${1:-5}"
SECRET="${2:-5}"
CONTAINER=fanng
FAKE="${FAKE:-0}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "error: container '$CONTAINER' is not running."
  echo "Build FANNG first via its docker harness (in the FANNG-MPC repo):"
  echo "    docker/run.sh build && docker/run.sh up && docker/run.sh progs"
  exit 1
fi

echo "=== FANNG-MPC cross-run MAC-key selective-failure attack ==="
echo "Attacker's guess:      g = $GUESS"
echo "Honest party's secret: y = $SECRET   (known only to the honest party; the attacker is guessing)"
echo "Both parties run the identical, unmodified FANNG Player binary."
[ "$FAKE" = 1 ] && echo "Offline: trusted-dealer (FAKE=1) + -dOT  (fast, low memory)" \
                || echo "Offline: FHE/BGV (real, default) + -dOT  (needs native x86, >= 32 GB RAM; FAKE=1 for fast low-memory run)"
echo

# Install variant 18 (2-party Full Threshold, 128-bit), sync the attack programs
# and the current poc scripts, and (re)compile the bytecode.
docker exec "$CONTAINER" bash -lc 'cp Auto-Test-Data/18/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/ && mkdir -p /fanng/poc' >/dev/null
docker cp poc.sh     "$CONTAINER":/fanng/poc/poc.sh     >/dev/null
docker cp patcher.py "$CONTAINER":/fanng/poc/patcher.py >/dev/null
docker cp Programs/attack_store/attack_store.mpc "$CONTAINER":/fanng/Programs/attack_store/attack_store.mpc >/dev/null
docker cp Programs/attack_open/attack_open.mpc   "$CONTAINER":/fanng/Programs/attack_open/attack_open.mpc   >/dev/null
docker exec "$CONTAINER" bash -lc './compile-new.sh Programs/attack_store >/dev/null 2>&1 && ./compile-new.sh Programs/attack_open >/dev/null 2>&1' \
  || { echo "error: failed to compile the attack programs (is the runtime built? run-attack prerequisites)"; exit 1; }

poc() { docker exec -e FAKE="$FAKE" -e QUIET=1 "$CONTAINER" bash -lc "bash /fanng/poc/poc.sh $*"; }

echo "--- Run 1: honest party stores its secret (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1, adds guess g=$GUESS to the carried MAC) ---"
if poc open "guess:$GUESS"; then verdict=complete; else verdict=abort; fi

echo
echo "=== RESULT ==="
if [ "$verdict" = complete ]; then
  echo "Protocol COMPLETED  ->  guess CORRECT  ->  the attacker learns y = $GUESS"
else
  echo "Protocol ABORTED (mac_fail)  ->  guess WRONG  ->  the attacker learns y != $GUESS"
fi
echo
echo "The revealed output was 0 regardless of y; the secret leaks purely through"
echo "complete-vs-abort. The honest party (P0) ran the unmodified FANNG binary in"
echo "both runs; only P1's own MKey-1.key and Memory-P1 were edited between them."
