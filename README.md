# Off-Key: a selective-failure attack on MP-SPDZ MASCOT via MAC-key inconsistency

A proof-of-concept **input-guessing selective-failure attack** against MP-SPDZ's
MASCOT protocol. A malicious party learns an honest party's secret input by
observing only whether the protocol succeeds or aborts — while the opened output
reveals nothing.

> **Fixed upstream in MP-SPDZ [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (Jul 2026); this PoC targets the earlier pinned commit [`58d2739`](https://github.com/data61/MP-SPDZ/commit/58d2739ac251262c0bd6034f7fc7d0666a6b1e2c).**

## Background: the SPDZ MAC scheme

SPDZ-style MPC authenticates every secret `x` with a MAC `α·x` under a global,
additively-shared MAC key `α = Σ αᵢ`. Inputs and Beaver triples come
pre-authenticated under `α`, and every opened value is checked against its MAC.
That check silently assumes everything in it was authenticated under the same `α`.

A malicious party who can get material authenticated under **inconsistent MAC
keys** can mount selective-failure attacks: they guess a secret-shared value and
learn whether the guess was right from whether the protocol aborts, while the
opened output reveals nothing. This is a property of the SPDZ MAC scheme, so the
same class of issue can arise in other SPDZ-family frameworks wherever
preprocessing generated under different key shares can be combined online.

## This PoC: MP-SPDZ (MASCOT)

In MP-SPDZ's multi-threaded execution each thread generates its own preprocessing,
so a malicious party can use a different MAC-key share per thread; shares from
different threads then meet in the same MAC check with no cross-thread consistency
check to catch it.

To demonstrate, we compute `f(x, y) := x · y`, where `x` and `y` come from the two
parties. The attacker inputs `x = 0`, so the opened output is always `0`
regardless of the honest party's input `y`. The output reveals nothing — yet the
attacker learns whether `y` equals a value of their choice from the protocol's
pass/fail alone.

The honest party runs an **unmodified** MP-SPDZ binary in a separate Docker
container. Only the attacker's binary is patched.

The PoC uses MASCOT over a 128-bit prime field (MP-SPDZ default).

## Quick start

Requires Docker. Run these from the repository root:

```bash
# 1. Build MP-SPDZ at the pinned pre-fix commit (one-time, ~10 min)
docker build -t mpspdz:built .

# 2. Correct guess → program succeeds → attacker learns y = 7
./run-attack.sh 7 7

# 3. Wrong guess → MAC check fails → attacker learns y ≠ 7
./run-attack.sh 7 3
```

`run-attack.sh [guess] [secret]` starts two containers on a Docker network — an
`honest` party running the stock `mascot-party.x`, and an `attacker` party whose
binary is patched at runtime — and reports what the attacker learns.

## The program

`simple_threaded_mul.mpc` is a standard multi-threaded MPC program:

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
standard MP-SPDZ pattern — the same architecture used by:

- [`vickrey.mpc`](https://github.com/data61/MP-SPDZ/blob/master/Programs/Source/vickrey.mpc) — Vickrey auction (main thread inputs bids, workers sort, main thread reveals winner)
- [`idash_train.mpc`](https://github.com/data61/MP-SPDZ/blob/master/Programs/Source/idash_train.mpc) / [`idash_predict.mpc`](https://github.com/data61/MP-SPDZ/blob/master/Programs/Source/idash_predict.mpc) — ML training/prediction benchmarks
- [`bankers_bonus.mpc`](https://github.com/data61/MP-SPDZ/blob/master/Programs/Source/bankers_bonus.mpc) — Millionaires' problem
- Any program using `@for_range_multithread` or `@for_range_opt_multithread`

Both parties run this exact same unmodified program.

## The attack

The attacker patches their binary (not the program) with two changes:

1. **`Processor/Machine.hpp`** — increment the MAC-key share (`alpha += 1`) between
   thread initializations, so thread 0 (main thread) uses key `alpha` and thread 1
   (worker) uses `alpha + 1`.

2. **`Processor/Processor.hpp`** — before the multiplication gate in the worker
   thread, add the guess `g` to the MAC of the honest party's input share.

The attacker always inputs `x = 0`. The output is always `0` — **the attacker
should learn nothing from the output**. But:

- If `y = g`: the MAC error terms cancel, the worker thread's MAC check passes, the
  program prints `DONE`.
- If `y ≠ g`: the error terms don't cancel → `MacCheck Failure` → abort.

The attacker learns `y` from whether the program succeeds or crashes.

## Why it works

In MP-SPDZ's multi-threaded execution with on-demand preprocessing, each thread
independently generates Beaver triples via OT. Each thread's triples pass the
per-batch sacrifice check, but there is no cross-thread MAC-key consistency check —
the offline phase verifies each batch in isolation.

The attacker exploits this by giving thread 0 and thread 1 different MAC keys.
Crucially, each worker thread runs its own MAC check on all opened values before
joining back to the main thread (at end-of-tape). This means the Beaver
multiplication's mask values (`epsilon`, `delta`) are checked under the worker's
modified key — not the main thread's key. The attacker controls the error term via
the guess added to the MAC.

See [REPORT.md](REPORT.md) for the full technical analysis with code traces.

## Files

| File | Description |
|------|-------------|
| `run-attack.sh` | Two-container attack demo |
| `simple_threaded_mul.mpc` | MPC program (both parties run this, unmodified) |
| `patch_guess.py` | Patches applied to the attacker's binary at runtime |
| `Dockerfile` | Builds unmodified MP-SPDZ at the pinned pre-fix commit |
| `REPORT.md` | Technical analysis with code traces |
