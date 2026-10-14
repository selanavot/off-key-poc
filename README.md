# Off-Key: attacks on MP-SPDZ MASCOT via MAC-key inconsistency

Proof-of-concept **off-key** attacks against MP-SPDZ's MASCOT protocol. A
malicious party arranges for preprocessing under two different MAC keys and, from
that, breaks the confidentiality of an honest party's secret input — while the
opened output reveals nothing. Three demonstrations, in increasing strength:

- **Selective failure** (`run-attack.sh`) — the attacker guesses `y` and learns
  one bit (whether the guess is right) from whether the protocol aborts.
- **Full input recovery** (`run-recovery.sh`) — the attacker recovers `y`
  *outright* in a single run, with no guessing, by reading the value opened during
  MP-SPDZ's (unmasked) MAC check.
- **Private affine evaluation** (`run-affine.sh`) — the same attack on
  `f(x; (y, r)) = x·y + r`, whose output is masked by a uniform `r`, making the
  leak a genuine violation of malicious security rather than a simulatable one.

<!-- TODO(eprint): replace with the ePrint link once the paper is posted. -->
> 📄 **This PoC accompanies our paper — _ePrint: link to be added_.**

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

# 2. Selective failure: correct vs. wrong guess (attacker learns one bit)
./run-attack.sh 7 7          # guess right → succeeds → learns y = 7
./run-attack.sh 7 3          # guess wrong → aborts   → learns y ≠ 7

# 3. Full input recovery: attacker recovers y in ONE run, no guessing
./run-recovery.sh 42         # attacker prints "y = 42"
./run-recovery.sh 12345      # attacker prints "y = 12345"

# 4. Example 2 — private affine evaluation f(x;(y,r)) = x·y + r, output to P0 only:
#    the output is masked by a uniform r, so it reveals nothing about y for ANY x,
#    yet the attacker still recovers y (or tests y==1 via abort).
./run-affine.sh 42 1         # recovery: attacker prints "y = 42"
GUESS=1 ./run-affine.sh 1 1  # selective failure: succeeds iff y == 1
```

`run-attack.sh [guess] [secret]` starts two containers on a Docker network — an
`honest` party running the stock `mascot-party.x`, and an `attacker` party whose
binary is patched at runtime — and reports what the attacker learns.
`run-recovery.sh [secret]` and `run-affine.sh [secret] [x]` use the same
two-container setup; in all of them the honest party runs the unmodified binary.

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

## The stronger attack: full input recovery

The selective-failure attack above leaks one bit per run. MP-SPDZ's MAC check
leaks much more. Its default check (in `Protocols/MAC_Check.hpp`) is the
*unmasked* Damgård et al. (2013) check: for each opened value, **every party
commits to and then opens its own check share** `δᵢ = v· αᵢ − macᵢ`. So the
attacker — as a participant — learns the reconstructed sum `Σ δᵢ = v·α − m_v`
for every opened value.

With the off-key setup, no guess is needed. The worker thread opens the Beaver
mask `d = y − b` under key `α+1`, while `y` was authenticated under `α`, so the
reconstructed check value on that opening is exactly

```
d·(α+1) − m_d = y.
```

`run-recovery.sh` reads `y` straight off that opened check value. The check then
aborts (the value is nonzero for `y ≠ 0`), but recovery already happened — the
check shares are opened before the abort decision. A single run recovers an
arbitrary `y`, and the opened output `x·y = 0` still reveals nothing.

```bash
./run-recovery.sh 42       # → "Attacker recovered the honest party's secret: y = 42"
```

This is why the specific MAC-check variant matters: against the *masked* check
of Kyster et al. (*Rushing at SPDZ*) the attack degrades to the one-bit
selective failure above, but MP-SPDZ's default check is the unmasked one.

## Example 2: private affine evaluation

Example 1 (`x·y` with `x = 0`) has output `0` — an outcome an ideal-world
adversary could also force by substituting inputs, so leaking `y` there is not by
itself a violation of malicious security. `affine_eval.mpc` closes that gap. It
computes

```
f(x; (y, r)) = x·y + r,     output revealed only to P0,     r uniform (P1's input)
```

Because `r` is uniform over the field, the output is uniform for **any** `x`, so
it reveals nothing about `y` — not even whether `y = 1`. An ideal-world adversary
learns nothing. Yet the off-key attack still recovers `y` (or tests `y = 1` via
abort), which is now a genuine breach of malicious security.

The mechanism is identical, with one structural difference: here `x ≠ 0`, so `x`
**must** be authenticated under the worker key `α+1` — otherwise the mask opening
`epsilon = x − a` would fail regardless of `y`. The program achieves this by
inputting `y` on the main thread (key `α`) and `x`, `r`, and the one-sided-output
mask on the worker thread (key `α+1`); MP-SPDZ input files are therefore per
**thread** (`Input-P<i>-<thread>`).

```bash
./run-affine.sh 42 1         # recovery: recovers y = 42 while the output stays uniform
GUESS=1 ./run-affine.sh 1 1  # selective failure: completes iff y == 1
```

`r` must be sampled uniformly over the whole field for this to hold: a
small-range mask would leave the possible outputs disjoint across `y` for a large
`x`, and the output alone would identify `y`. The runner samples `r` as 256
uniform bits, reduced modulo the field prime in-protocol (statistical distance
≤ 2⁻¹²⁸ from uniform). The attack itself is independent of `r`.

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
