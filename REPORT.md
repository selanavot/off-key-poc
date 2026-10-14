# Technical Report: Cross-Thread MAC Key Inconsistency in MP-SPDZ MASCOT

## Summary

MP-SPDZ's MASCOT protocol (over a 128-bit prime field, the default
configuration) does not enforce MAC key consistency across computation threads.
A malicious party can use different MAC key shares for different threads' Beaver
triple generation. Each thread's triples independently pass the sacrifice check
(offline phase), and each thread runs its own MAC check on opened values before
joining — creating a selective failure oracle.

> **Fixed upstream in MP-SPDZ [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (Jul 2026); this PoC targets the earlier pinned commit [`58d2739`](https://github.com/data61/MP-SPDZ/commit/58d2739ac251262c0bd6034f7fc7d0666a6b1e2c).**

## Background

### SPDZ MAC scheme

In the SPDZ protocol, all secret values `x` carry a MAC: `m = alpha * x`, where
`alpha` is the global MAC key. Each party `i` holds additive shares `alpha_i`
and `m_i`. The MAC check verifies `sum(m_i) = sum(alpha_i) * x` when values are
opened.

### Multi-threading in MP-SPDZ

MP-SPDZ supports multi-threaded execution via worker threads. Each thread:
- Reads the MAC key from a shared pointer (`machine.alphapi`)
- Performs independent base OTs with the other party
- Generates its own Beaver triples via the MASCOT protocol
- Runs the sacrifice check on its own batch of triples

The key observation: **each thread does independent OT setup**, binding the
MAC key at that point. There is no mechanism to verify that all threads used
the same key.

## The vulnerability

### Machine.hpp thread initialization

In `Processor/Machine.hpp`, the `prepare()` method creates threads in a loop.
All threads read `*(tinfo->alphapi)` — a pointer to the shared MAC key.
The attacker waits for thread 0 to fully initialize (read the key, complete
base OTs), then increments `*alphapi` before thread 1 is created.

```
Thread 0: reads alpha,   does base OTs with key alpha
           ↓ attacker increments alpha to alpha+1
Thread 1: reads alpha+1, does base OTs with key alpha+1
```

Both threads' triples pass the sacrifice check because each batch is verified
in isolation — sacrifice creates a fresh `MAC_Check(get_mac_key())` per batch.

### Per-thread MAC check at end-of-tape

Each worker thread runs its own MAC check on all values opened during its
execution, before joining back to the main thread. In MP-SPDZ, this happens
at end-of-tape: the thread's `MAC_Check` destructor verifies all pending
MACs using that thread's key. This is essential to the attack — the Beaver
multiplication opens mask values (`epsilon = x - a`, `delta = y - b`), and
these are checked under the worker thread's modified key (`alpha + 1`), not
the main thread's key (`alpha`).

### The selective failure attack

The attacker (party 0) inputs `x = 0` and guesses the honest party's input
`y = g`. The program computes `x * y` on a worker thread (thread 1, key
`alpha+1`). The worker thread's MAC check verifies the Beaver mask openings
under key `alpha+1` before the result is returned to the main thread.

Before the Beaver multiplication on thread 1, the attacker adds `g` to the MAC
of `y`'s share. Combined with the `+1` on the key, this makes `y`'s MAC valid
under `alpha+1` if and only if `y = g`:

- The honest party's MAC share: `m_1 = alpha_1 * y`
- The attacker's MAC share (modified): `m_0 = alpha_0 * y + g`
- The attacker's key share (modified): `alpha_0 + 1`

MAC check computes: `(m_0 + m_1) - (alpha_0 + 1 + alpha_1) * y`
= `(alpha_0 * y + g + alpha_1 * y) - (alpha + 1) * y`
= `g - y`

- If `g = y`: error = 0, MAC check passes, program succeeds.
- If `g ≠ y`: error ≠ 0, `MacCheck Failure`, program aborts.

Since the attacker inputs `x = 0`, the opened output is always `0` — it reveals
nothing about `y`. The attacker learns `y` purely from pass/fail.

### The stronger attack: full input recovery from the unmasked check

The selective-failure attack above leaks one bit per run. But MP-SPDZ's default
MAC check leaks much more. In `Protocols/MAC_Check.hpp`, `MAC_Check_<U>::Check`
implements the *unmasked* Damgård et al. (2013) check: for each opened value
`v`, every party commits to and then opens its own check share

```
delta_i = v * alpha_i - m_{v,i}
```

(the small-batch path uses these per value directly; the batched path opens
`tau_i = gamma_i - alpha_i * a` for a random linear combination). Because the
shares are *opened*, the attacker — as party 0 — receives the honest party's
`delta_1` and can reconstruct the full sum

```
sum_i delta_i = v * alpha - m_v
```

for every opened value. This is exactly the leakage the masked check of Kyster
et al. was introduced to prevent; stock MP-SPDZ does not use the masked check.

With the off-key setup, no guess is needed. The worker opens `d = y - b` under
key `alpha + 1`, where `y` was authenticated under `alpha`, so the reconstructed
check value on that opening is

```
d * (alpha + 1) - m_d = (y - b)(alpha + 1) - (alpha * y - (alpha + 1) b)
                      = (alpha + 1) y - alpha * y
                      = y.
```

The attacker reads `y` directly off the opened check value (the companion
opening `epsilon = x - a` reconstructs to `x = 0`, revealing nothing new). The
check then aborts because the value is nonzero, but recovery has already
happened — the check shares are opened before the abort decision. A single run
recovers an arbitrary `y`, and, as before, the opened output `x * y = 0` reveals
nothing. If the attacker also adds a guess `g` to `y`'s MAC (as in the
selective-failure variant), the recovered value is `y - g`; with `g = 0` it is
`y` itself.

The PoC's patch to `MAC_Check.hpp` simply prints these reconstructed per-opening
values on the attacked worker thread; see `run-recovery.sh`.

### Example 2: private affine evaluation (a true security violation)

Examples 1 and 2 use the same off-key mechanism; they differ in what the honest
output leaks. Example 1 (`x * y` with `x = 0`) has output `0`, an outcome an
ideal-world adversary could also force by substituting inputs, so it does not by
itself violate malicious security. Example 2 removes that loophole.

`affine_eval.mpc` computes `f(x; (y, r)) = x * y + r` with `r` uniform (P1's
input) and the result revealed only to P0. The uniform `r` makes the output
uniform for **any** `x`, so it reveals nothing about `y`; an ideal-world
adversary learns nothing. Yet the off-key attack recovers `y` (or tests `y = 1`
via abort). Leaking `y` while the output is independent of `y` is a genuine
breach of malicious security.

The structural difference from Example 1 is the key assignment. With `x ≠ 0`,
the mask opening `epsilon = x - a` must reconstruct to a *consistent* check
value, so `x` has to be authenticated under the worker key `alpha+1` — the same
key as the triple. Otherwise `epsilon`'s reconstructed check value would be `x`
(nonzero), aborting regardless of `y`. The program arranges this by taking `y`
on the main thread (key `alpha`) and `x`, `r`, and the one-sided-output mask on
the worker thread (key `alpha+1`); MP-SPDZ input files are per thread
(`Input-P<i>-<thread>`). The one-sided output uses `reveal_to(0)`, which draws a
fresh mask supplied by P0 — exactly the "mask `s` known only to P0" the
construction requires. Only the `d = y - b` opening then mixes keys, so it is
the sole nonzero reconstructed check value, equal to `y - g`.

`r` must be sampled uniformly over the whole field for the output to hide `y`
for every `x`; `run-affine.sh` samples it as 256 uniform bits reduced modulo the
field prime (the attack itself is independent of `r`'s distribution). Verified:
recovery of `y ∈ {0, 1, 42, 987654}` for `x ∈ {1, 3}` (output masked by `r`
throughout), and the selective-failure variant (`GUESS=1`) succeeding iff
`y = 1`.

## Reproduction

See [README.md](README.md) for Docker-based reproduction. The PoC runs two
separate containers — the honest party uses a completely unmodified MP-SPDZ
binary.

## Relevant MP-SPDZ source locations

| File | What |
|------|------|
| `Processor/Machine.hpp` | Thread creation loop (`prepare()`) |
| `Processor/Online-Thread.hpp` | Per-thread MAC key read (`*(tinfo->alphapi)`) |
| `OT/NPartyTripleGenerator.hpp` | Per-batch sacrifice check |
| `Protocols/MAC_Check_Base.h` | Online MAC verification |
| `Protocols/MAC_Check.hpp` | `MAC_Check_<U>::Check` — unmasked check that opens each party's `delta_i` (input recovery) |
| `Processor/Processor.hpp` | `SubProcessor::muls()` — Beaver multiplication |
