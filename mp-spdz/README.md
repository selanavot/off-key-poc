# Cross-Thread MAC-Key Inconsistency in MP-SPDZ (MASCOT)

A proof-of-concept off-key attack on **MP-SPDZ**'s MASCOT protocol: a malicious
party breaks the confidentiality of an honest party's secret input, while the
opened output reveals nothing. The honest party runs an **unmodified**
`mascot-party.x` in a separate Docker container; only the attacker's binary is
patched. MASCOT runs over a 128-bit prime field (the MP-SPDZ default).

**Off-key vector: cross-thread.** In MP-SPDZ's multi-threaded execution each
thread generates its own preprocessing, so a malicious party can use a different
MAC-key share per thread. Shares from different threads then meet in the same MAC
check, with no cross-thread consistency check to catch it: thread 0 uses key `α`
and the worker thread uses `α + 1`.

Three demonstrations, in increasing strength:

- **Selective failure** (`run-attack.sh`): the attacker guesses `y` and learns
  one bit, whether the guess was right, from whether the protocol aborts.
- **Full input recovery** (`run-recovery.sh`): the attacker recovers `y` outright
  in a single run, with no guessing, by reading the value opened during MP-SPDZ's
  unmasked MAC check.
- **Private affine evaluation** (`run-affine.sh`): the same attack on
  `f(x; (y, r)) = x·y + r`, whose output is masked by a uniform `r`, making the
  leak a genuine violation of malicious security rather than a simulatable one.

> **Fixed upstream in MP-SPDZ [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (Jul 2026); this PoC targets the earlier pinned commit [`58d2739`](https://github.com/data61/MP-SPDZ/commit/58d2739ac251262c0bd6034f7fc7d0666a6b1e2c).**

## How to run

Requires Docker. Run these from this directory (`mp-spdz/`):

```bash
# Build unmodified MP-SPDZ at the pinned pre-fix commit (one-time, ~10 min)
docker build -t mpspdz:built .

# Selective failure: correct vs. wrong guess (attacker learns one bit)
./run-attack.sh 7 7          # guess right -> succeeds -> learns y = 7
./run-attack.sh 7 3          # guess wrong -> aborts   -> learns y != 7

# Full input recovery: recover y in ONE run, no guessing
./run-recovery.sh 42         # attacker prints "y = 42"

# Example 2: private affine evaluation f(x;(y,r)) = x·y + r, output to P0 only
./run-affine.sh 42 1         # recovery: recovers y = 42 while the output stays uniform
GUESS=1 ./run-affine.sh 1 1  # selective failure: completes iff y == 1
```

Each run starts two Docker containers on a private network, an `honest` party
running the stock `mascot-party.x` and an `attacker` party whose binary is patched
at runtime, and reports what the attacker learns.

## The program

`simple_threaded_mul.mpc` is a standard multi-threaded MPC program (Example 1):

```python
x = MemValue(sint.get_input_from(0))   # party 0's input
y = MemValue(sint.get_input_from(1))   # party 1's input
result = sint.Array(1)

def worker():
    result[regint(0)] = x.read() * y.read()

tape = program.new_tape(worker)
program.join_tape(program.run_tape(tape, 0))
print_ln('x * y = %s', result[0].reveal())
```

Main thread takes inputs, worker thread computes, main thread reveals. This is the
standard MP-SPDZ pattern, the same architecture used by `vickrey.mpc`,
`idash_train.mpc` / `idash_predict.mpc`, `bankers_bonus.mpc`, and any program
using `@for_range_multithread` or `@for_range_opt_multithread`. Both parties run
this exact same unmodified program; only the attacker's binary is patched.

## The attack, in brief

The attacker patches their binary (not the program) in two places: increment the
MAC-key share (`α += 1`) between thread initializations so the worker thread runs
under `α + 1`, and, before the multiplication gate, add the guess `g` to the MAC
of the honest party's input share. With `x = 0` the opened output is always `0`,
yet the worker thread's MAC check passes if and only if `y = g`, so the attacker
learns `y` from pass/fail alone. For full input recovery, the unmasked MAC check
opens each party's check share, and the attacker reads `y` directly off the
reconstructed value of a single off-key opening, with no guess.

See [REPORT.md](REPORT.md) for the full technical analysis, the recovery and
Example 2 mechanisms, the probability and key-assignment details, and code traces.

## Files

| File | Description |
|------|-------------|
| `run-attack.sh` | Selective-failure demo (Example 1): `[guess] [secret]` |
| `run-recovery.sh` | Full input-recovery demo (Example 1): `[secret]` |
| `run-affine.sh` | Private affine evaluation (Example 2): `[secret] [x]`, `GUESS=1` for selective failure |
| `simple_threaded_mul.mpc` | Example 1 program `x·y` (both parties run this, unmodified) |
| `affine_eval.mpc` | Example 2 program `x·y + r` (both parties run this, unmodified) |
| `patch_guess.py` | Patches applied to the attacker's binary at runtime |
| `Dockerfile` | Builds unmodified MP-SPDZ at the pinned pre-fix commit |
| `REPORT.md` | Technical analysis with code traces |
