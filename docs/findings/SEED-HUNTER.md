# Seed Hunter and coverage-guided modes

| Field | Value |
|---|---|
| Instrument | `fuzz/ahdg_hunt.c` |
| Modes | `normal` · `stress` · `deep` · `extreme` · `hunt` |
| Ranking | novelty (rare-state coverage), **not** CPU time |
| Status | reproducible, CI-gated (`make hunt`) |

## What it is

An adversarial engine over the real `isotp_rx + uds` pipeline with campaign
modes and a **Seed Hunter** that searches for the seed maximizing coverage —
specifically rare states — rather than one that merely burns CPU.

After every action it measures coverage: distinct **states** (a fingerprint over
session × security × ISO-TP phase × reassembly length × DTC count × reset), distinct
**transitions**, distinct **outcomes** (positive SIDs, NRCs), **depth** reached,
and **rare states** (visited ≤ 3 times).

```
normal  [seed] [budget]      1M sequences, depth <= 8, random
stress  [seed] [budget]      100M sequences, depth <= 64
deep    [seed] [max_iters]   coverage-guided, depth <= 256, havoc mutations
extreme [seed] [max_seconds] run until: counterexample | coverage plateau | delay
hunt    [n_seeds] [attack]   scan seeds, rank by novelty, report hardest, attack it
```

The mutation alphabet already contains timing (`clock += N_Cr / S3 / lockout`),
ISO-TP (FF / CF good & bad SN / FC / interleave / garbage) and UDS (session /
seed / key / reset / read) actions, so havoc mutation covers the timing, ISO-TP,
UDS and state-mutation classes at once.

## The Seed Hunter output

```
 seed           etats  transitions   rares  novelty    runtime
 0x0005EED1      24          120       1     1.00       62 ms
 0x0BADC0DE      24          119       1     1.00       64 ms
 ...
 0x00001234      23          113       0     0.92       63 ms

 HARDEST SEED FOUND : 0x0005EED1   (novelty 1.00)
   score = states + 0.4*transitions + 3*rares + issues + 0.1*depth
   (CPU time does NOT enter the score)
```

`0x0005EED1` wins not because it is slow but because it reaches a rare state and
one more transition than the others; `0x00001234` reaches only 23 of the 24
states and scores lowest. The seed genuinely influences exploration, and the
hunter finds the most novel one on its own.

## An honest finding: the state space is bounded

The first version of this tool exposed something real: with a coarse fingerprint,
**every seed saturated the same ~12 states, with 0 rare states** — the seed did
not matter, because the reachable space was too small. That is exactly the signal
that a coverage-guided fuzzer needs a larger space to become interesting.

Enriching the fingerprint with genuinely-reachable dimensions (DTC count, ISO-TP
reassembly length, reset flag) roughly doubled it to ~24 states and made rare
states and seed differentiation appear. But the space is still bounded by the
real ECU's complexity — a single ECU with a handful of services simply does not
have thousands of reachable states. Making it genuinely vast is what the
multi-ECU / cross-ECU-invariant future (roadmap M107–M108) is for; this tool is
the instrument that will measure it when it exists.

## Coverage-guided beats random on depth and breadth

The same seed, same effort, two engines:

| Engine | states | transitions | max depth |
|---|---:|---:|---:|
| `normal` (random, depth ≤ 8) | 23 | 105 | 8 |
| `deep` (coverage-guided, depth ≤ 256) | 24 | **146** | **37** |

The guided engine builds on inputs that reached new coverage and mutates them, so
it drives sequences to depth 37 and finds 40 % more transitions than random —
the "intelligent" exploration a flat random fuzzer cannot do. `extreme` runs the
same engine until a counterexample, a coverage plateau, or a time limit.

## Result

Across all modes and the hunter, on the current hardened stack: **no
counterexample** (bounded assurance — the invariants hold), and the state space
is characterised rather than assumed. A counterexample, if one is ever found,
is delta-debug-minimized and printed as an irreducible frame sequence.

## Reproduce

```bash
make hunt                              # rank seeds by novelty
./build/ahdg_hunt deep 0x0005EED1      # coverage-guided, depth 256
./build/ahdg_hunt extreme 0x0005EED1 60   # run for up to 60 s
./build/ahdg_hunt hunt 32 1            # scan 32 seeds, then attack the hardest
```
