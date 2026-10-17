# Cross-Thread MAC-Key Inconsistency in MP-SPDZ (MASCOT)

A proof-of-concept off-key attack on **MP-SPDZ**'s MASCOT protocol: a malicious
party breaks the confidentiality of an honest party's secret input, while the
opened output reveals nothing. The honest party runs an **unmodified**
`mascot-party.x` in a separate Docker container; only the attacker's binary is
patched. MASCOT runs over a 128-bit prime field (the MP-SPDZ default).

**Off-key vector: cross-thread.** In MP-SPDZ's multi-threaded execution each
thread generates its own preprocessing, so a malicious party can use a different
MAC-key share per thread. Shares from different threads then meet in the same MAC
check, with no cross-thread consistency check to catch it: the main thread uses
key `α` and the worker thread uses `α + 1`.

Both attack strengths run on both circuits:

- **Selective abort** (`run-attack.sh`): the attacker guesses `y`, and the check
  passes only if the guess was right, leaking one bit per run.
- **Full secret recovery** (`run-recovery.sh`): the attacker reads `y` outright in
  a single run, with no guessing, from the value opened by the unmasked MAC check.
- **Example 2** (`run-affine.sh`): the same two attacks on the affine functionality
  `f(x; (y, r)) = x·y + r`, whose output is masked by a uniform `r`.

> **Fixed upstream in MP-SPDZ [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (July 2026); this PoC targets the earlier pinned commit [`58d2739`](https://github.com/data61/MP-SPDZ/commit/58d2739ac251262c0bd6034f7fc7d0666a6b1e2c).**

## How to run

Requires Docker. Run from this directory (`mp-spdz/`):

```bash
# Build unmodified MP-SPDZ at the pinned pre-fix commit (one-time, ~10 min)
docker build -t mpspdz:built .

# Selective abort: correct vs. wrong guess (one bit of y)
./run-attack.sh 7 7          # guess right -> succeeds -> learns y = 7
./run-attack.sh 7 3          # guess wrong -> aborts   -> learns y != 7

# Full secret recovery: recover y in ONE run, no guessing
./run-recovery.sh 42         # attacker prints "y = 42"

# Example 2: private affine evaluation f(x;(y,r)) = x·y + r, output to P0 only
./run-affine.sh 42 1         # recovery: recovers y = 42 while the output stays uniform
GUESS=1 ./run-affine.sh 1 1  # selective abort: completes iff y == 1
```

Each run starts two Docker containers on a private network: an `honest` party
running the stock `mascot-party.x`, and an `attacker` party whose binary is patched
at runtime. Both parties run the same unmodified `.mpc` program; only the
attacker's binary differs.

## Files

| File | What |
|---|---|
| `Dockerfile` | Builds unmodified MP-SPDZ at the pinned pre-fix commit |
| `simple_threaded_mul.mpc` | Example 1 program `x·y` |
| `affine_eval.mpc` | Example 2 program `x·y + r` |
| `patch_guess.py` | The attacker's binary patches, applied at runtime |
| `run-attack.sh` | Selective-abort driver (Example 1): `[guess] [secret]` |
| `run-recovery.sh` | Input-recovery driver (Example 1): `[secret]` |
| `run-affine.sh` | Example 2 driver: `[secret] [x]`, `GUESS=1` for selective abort |

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

The main thread takes inputs, a worker thread computes, the main thread reveals.
This is the standard MP-SPDZ pattern, shared by programs such as `vickrey.mpc`,
`idash_train.mpc`, and `bankers_bonus.mpc`, and by anything using
`@for_range_multithread`. Both parties run this exact program unmodified.

## How it works

Each worker thread does its own base OTs and generates its own Beaver triples, so
the MAC key is bound per thread. In `Processor/Machine.hpp`, `prepare()` creates
the threads in a loop, and each reads `*(tinfo->alphapi)`, a pointer to the shared
MAC key. The attacker lets thread 0 finish initializing, then increments
`*alphapi` before thread 1 is created:

```
Thread 0: reads α,   base OTs with key α
          ↓ attacker increments α to α+1
Thread 1: reads α+1, base OTs with key α+1
```

Both threads' triples still pass the offline sacrifice check, because each batch is
verified in isolation against its own key, and there is no cross-thread check that
the keys agree. At end-of-tape each worker thread runs its own MAC check on the
values it opened, under its own key, before joining the main thread. The Beaver
multiplication opens the mask values `ε = x − a` and `δ = y − b`, so these are
checked under the worker key `α + 1`, not the main thread's `α`.

## The selective-abort math

The attacker (party 0) inputs `x = 0` and guesses `y = g`. Before the
multiplication on the worker thread, it adds `g` to its share of `y`'s MAC. With
the worker key incremented to `α + 1`:

```
honest MAC share:          m_1 = α_1 · y
attacker MAC share (+g):   m_0 = α_0 · y + g
attacker key share (+1):   α_0 + 1

check:  (m_0 + m_1) − (α_0 + 1 + α_1) · y  =  g − y
```

The check passes iff `g = y`. The output is always `0` (since `x = 0`), so the
attacker learns `y` only from pass versus abort.

## The input-recovery math

MP-SPDZ's default check (`Protocols/MAC_Check.hpp`) is the *unmasked* Damgard et
al. (2013) check: for each opened value `v`, every party commits to and then opens
its own check share `δ_i = v·α_i − m_{v,i}`, so a participant reconstructs

```
Σ_i δ_i = v·α − m_v
```

for every opened value. No guess is needed. The worker opens `d = y − b` under key
`α + 1`, where `y` was authenticated under `α` and `b` is a fresh triple mask under
`α + 1`, so the opened value on that check is

```
d·(α + 1) − m_d = (y − b)(α + 1) − (α·y − (α + 1)·b) = y
```

`run-recovery.sh` reads `y` straight off this value. The check then aborts (the
value is nonzero), but recovery already happened, since the check shares are opened
before the abort decision, and the opened output `x·y = 0` still reveals nothing.
Adding a guess `g` to `y`'s MAC instead recovers `y − g`; with `g = 0` it is `y`.

## Example 2: private affine evaluation

`affine_eval.mpc` computes `f(x; (y, r)) = x·y + r` with `r` a uniform input of P1
and the result revealed only to P0. Because `r` masks the output uniformly for any
`x`, the output reveals nothing about `y`, yet the attack still recovers `y` (or
tests `y = 1` via abort).

The one structural difference from Example 1 is the key assignment. With `x ≠ 0`,
the opening `ε = x − a` must reconstruct consistently, so `x` has to be
authenticated under the worker key `α + 1`, the same key as the triple; otherwise
`ε` reconstructs to `x ≠ 0` and aborts regardless of `y`. The program takes `y` on
the main thread (key `α`) and `x`, `r`, and the one-sided-output mask on the worker
thread (key `α + 1`), so MP-SPDZ input files are per thread
(`Input-P<i>-<thread>`). Only the `d = y − b` opening then mixes keys, so it is the
sole off-key value. `run-affine.sh` samples `r` as 256 uniform bits reduced modulo
the field prime; the attack itself is independent of `r`'s distribution.

## Threat model

Both parties run the same unmodified `.mpc` program, and the honest party runs a
stock `mascot-party.x` with no patches. Only the attacker's own binary is patched,
in two places: the per-thread key increment in `Processor/Machine.hpp`, and the
guess added to the honest input's MAC before the multiplication gate in
`Processor/Processor.hpp`.

## Relevant MP-SPDZ source locations

| File | What |
|---|---|
| `Processor/Machine.hpp` | Thread creation loop (`prepare()`) |
| `Processor/Online-Thread.hpp` | Per-thread MAC key read (`*(tinfo->alphapi)`) |
| `OT/NPartyTripleGenerator.hpp` | Per-batch sacrifice check |
| `Protocols/MAC_Check.hpp` | `MAC_Check_<U>::Check`, the unmasked check that opens each party's `δ_i` |
| `Processor/Processor.hpp` | `SubProcessor::muls()`, the Beaver multiplication |
