# Proof of Concept for *Off-Key: Inconsistent MAC keys cause selective-failure attacks in SPDZ-family MPC*

This repository is the proof-of-concept companion to the paper *Off-Key*. It
demonstrates the attack on three SPDZ-family MPC frameworks, MP-SPDZ,
SCALE-MAMBA, and FANNG-MPC, each as a self-contained PoC run against an
**unmodified** honest party.

> 📄 **Accompanying paper.** This PoC accompanies the submitted paper *Off-Key*.

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

All the attacks here exploit implementation vulnerabilities, and they do not break the theoretical security of SPDZ.

## Two strengths of the attack

We present two attacks, differing in their generality and privacy leakage.

- **Selective abort, MAC-check-protocol independent.** The attacker folds a guess for a secret `y`
  into the off-key material, and the check passes if and only if the guess was
  correct. This attack uses nothing but the abort signal, so it works against *any* SPDZ
  MAC check. This allows the adversary to check whether a potentially low-entropy secret `y` equals a value of their choice.

- **Full secret recovery.** The attacker recovers
  `y` outright in a single run. This attack uses the internal values of the MAC-check protocol used by all of the frameworks we attack, specifically the **unmasked** MAC check of Damgård
  et al. (2013). Every party commits to and then opens its own check
  share, so a participant reconstructs the check value directly and one off-key
  opening reconstructs to `y` itself.

## The circuits

We demonstrate both strengths on two functionalities, and refer the reader to the paper to see why these circuits were selected.

- **Example 1 - multiplication:** `f(x, y) = x · y`. The attacker inputs `x = 0`, so the opened
  output is always `0` regardless of `y`, which means that the adversary should learn nothing about the honest party's input.
  Our two attacks allow testing whether `y = g`, and learning `y` outright respectively.

- **Example 2 - affine transformation:** `f(x; (y, r)) = x · y + r`, with the adversary inputting `x` and the honest party `(y, r)`. In the case where `r` is uniformly random, it completely masks the output, so the adversary should learn no information about `y`. As before, in our first attack the adversary checks whether `y = g` for a guess `g`,
and in the second the adversary recovers `y` outright.

## Frameworks

We present the PoC against each framework in its own self-contained directory. Each demonstrates
**both strengths of the attack on both circuits**, with build and run
instructions. The frameworks differ only in the *vector* that supplies the
inconsistent MAC keys, which we explain in detail in their respective READMEs.

- **[`mp-spdz/`](mp-spdz/)**. Each thread in its parallelized MASCOT implementation
  generates its own preprocessing, allowing an adversary to input different keys to different threads in the same computation.
- **[`scale-mamba/`](scale-mamba/)**. In the full threshold implementation, a computation can be restarted across runs. The MAC-key share is re-read from disk at the start of every run, allowing the adversary to input a different MAC key share.
- **[`fanng/`](fanng/)**. A SCALE-MAMBA fork that inherits the same cross-run vulnerability.

The MP-SPDZ vulnerability has been fixed in [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (July 2026). We have permission from the maintainers of all frameworks to make this attack public. We refer the readers to our paper for more information, including mitigation.
