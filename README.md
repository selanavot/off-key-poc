# Proof of Concept for *Off-Key: Inconsistent MAC keys cause selective-failure attacks in SPDZ-family MPC*

This repository is the proof-of-concept companion to the paper *Off-Key*. It
demonstrates the attack on three SPDZ-family MPC frameworks, MP-SPDZ,
SCALE-MAMBA, and FANNG-MPC, each as a self-contained PoC run against an
**unmodified** honest party.

> 📄 **Accompanying paper.** This PoC accompanies a research paper submitted to
> the [IACR Cryptology ePrint Archive](https://eprint.iacr.org/). The paper is not
> public yet; we will add a direct link here the moment it is posted.

## Background: the SPDZ MAC scheme

SPDZ-style MPC authenticates every secret `x` with a MAC `α·x` under a global,
additively-shared MAC key `α = Σ αᵢ`. Inputs and Beaver triples come
pre-authenticated under `α`, and every opened value is checked against its MAC.
That check silently assumes everything in it was authenticated under the same `α`.

A malicious party who can get material authenticated under **inconsistent MAC
keys** breaks that assumption. By arranging for a secret `y` (authenticated under
`α`) and a fresh multiplication-triple mask (a Beaver-triple value authenticated
under `α + 1`) to meet in one check, the attacker makes the MAC check itself leak
information about `y`.

## Two strengths of the attack

The attack comes in two strengths, differing in how much the MAC check gives up
and in which MAC-check protocols they work against:

- **Selective abort, MAC-check-protocol independent.** The attacker folds a guess for `y`
  into the off-key material so the check passes if and only if the guess was
  right. Because it uses nothing but the abort signal, it works against *any* SPDZ
  MAC check.

- **Full secret recovery.** No guessing: the attacker recovers
  `y` outright in a single run. It relies on the **unmasked** MAC check of Damgård
  et al. (2013), in which every party commits to and then opens its own check
  share, so a participant reconstructs the check value directly and one off-key
  opening reconstructs to `y` itself. All three frameworks here ship this unmasked
  check; against the masked check it degrades to the selective-abort variant.

## The circuits

We demonstrate both strengths on two functionalities:

- **Example 1: `f(x, y) = x · y`.** The attacker inputs `x = 0`, so the opened
  output is always `0` regardless of `y`. The leak is real, but a zero output is
  an outcome an ideal-world adversary could also force by choosing its own input,
  so Example 1 on its own is not yet a violation of malicious security.

- **Example 2: `f(x; (y, r)) = x · y + r`,** revealed only to P0, with `r` a
  uniform input of the honest party. Because `r` masks the output uniformly for
  **any** `x`, the output carries no information about `y`, yet the attack still
  recovers `y` (or tests a guess via abort). This closes Example 1's loophole: it
  is a genuine breach of malicious security.

## Frameworks

Each framework is a self-contained PoC in its own directory, and each demonstrates
**both strengths of the attack on both circuits**, with build and run
instructions. The frameworks differ only in the *vector* that supplies the
inconsistent MAC keys:

- **[`mp-spdz/`](mp-spdz/)**, MP-SPDZ (MASCOT). Cross-thread: each thread
  generates its own preprocessing, so a different MAC-key share can be used per
  thread. See [`mp-spdz/README.md`](mp-spdz/README.md).
- **[`scale-mamba/`](scale-mamba/)**, SCALE-MAMBA (Full Threshold). Cross-run
  restart: the MAC-key share is re-read from disk at the start of every run. See
  [`scale-mamba/README.md`](scale-mamba/README.md).
- **[`fanng/`](fanng/)**, FANNG-MPC (Full Threshold). A SCALE-MAMBA fork that
  inherits the same cross-run vector unchanged; verified on native x86 under the
  real FHE/BGV offline phase. See [`fanng/README.md`](fanng/README.md).
