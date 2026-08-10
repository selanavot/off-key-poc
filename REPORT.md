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
| `Processor/Processor.hpp` | `SubProcessor::muls()` — Beaver multiplication |
