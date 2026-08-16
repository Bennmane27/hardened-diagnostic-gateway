# Roadmap

Status of each milestone. The detailed rationale behind every decision lives in
[docs/PROJECT_MEMORY.md](docs/PROJECT_MEMORY.md).

## Done

| # | Milestone |
|---|---|
| M01–M02 | ISO-TP Single Frame module and its unit tests |
| M03 | SocketCAN transport layer, built once a second caller justified it |
| M04–M05 | UDS module extraction, negative responses |
| M08 | ReadDataByIdentifier, virtual ECU data model |
| M11–M16 | ISO-TP multi-frame: First Frame, Flow Control, Consecutive Frames, reassembly, transmission, sequence errors |
| M17–M18 | Injectable clock, `N_Bs` / `N_Cr` timers and their tests |
| M06–M07 | Session access rules, `TesterPresent`, `S3server` expiry |
| M09–M10 | `ECUReset`, DTC model, `ReadDTCInformation`, `ClearDiagnosticInformation` |
| M20–M22 | `SecurityAccess`, replay refusal, brute-force lockout |
| M23–M24 | On-bus fault injector, in-process parser fuzzer |
| M26–M27 | Sanitizers and static analysis in CI |
| M29–M30 | GitHub Actions, measured metrics |
| M32 | Portability proof: protocol layers build freestanding, no external symbols |
| M34 | Cross-validation against the Linux kernel ISO-TP stack |
| M35 | Interactive diagnostic client and a recorded, reproducible demo |
| M40 | Web console: four terminals, live control, automated scenario |
| M41 | `vcan0` made permanent through a systemd unit |

## Research track — the hardened gateway

See [docs/RESEARCH.md](docs/RESEARCH.md) for the full brief and
[docs/NOVELTY.md](docs/NOVELTY.md) for the claim discipline. This is where the
project stops being an excellent implementation and becomes a falsifiable,
reproducible experiment.

| # | Milestone | Status |
|---|-----------|--------|
| M50 | `invariants.h` — cross-layer invariant catalogue as code | done |
| M51 | Gateway shadow state: passive ISO-TP + UDS tracking | next |
| M52 | Invariant engine: evaluate, verdict ALLOW / DROP / RECOVER | |
| M53 | In-line CAN gateway, transparent on the nominal path | |
| M54 | RECOVER: post-violation resynchronization, availability restored | |
| M55 | Adversarial state-space explorer + delta-debug minimizer | **partial** — UDS-level explorer (`fuzz/ahdg_explore.c`) live; found AHDG-0001 |
| M56 | Frozen counterexample corpus + exact replay | |
| M57 | Benchmark harness S0 (ECU) / S1 (firewall) / S2 (gateway) | |
| M58 | STM32 + FDCAN port, measured latency | |
| M59 | One-command reproduction + CI gate on blocked-attack count | |
| M60 | Prior-art review — hard gate on the novelty claim | |
| M61 | Write-up: threat model, invariants, discovery, results | |
| M62 | In-browser WASM lab: real stack + adversary, zero install | done |

First experimental finding: [docs/findings/AHDG-0001.md](docs/findings/AHDG-0001.md)
— a cross-layer state confusion in the real UDS server, discovered automatically,
minimized to four actions, fixed, regressed, and re-attacked clean over 2,000,000
sequences. The research loop, demonstrated on real code.

The designation the project earns on completion, and the exact wording allowed
at each stage, are defined in [docs/RESEARCH.md](docs/RESEARCH.md) §10 and
[docs/NOVELTY.md](docs/NOVELTY.md). The short version: no "world first" — a
scoped "to the best of our knowledge, first open and evaluated ..." claim,
earned by the prior-art review, which is stronger because it is falsifiable.

## Not planned yet

| # | Milestone | Why it would matter |
|---|---|---|
| M36 | `SecurityAccess` with HMAC-SHA256 and a hardware RNG | Replaces the demonstration key algorithm with a real one |
| M37 | libFuzzer / AFL++ harnesses over the parsers | Coverage-guided fuzzing finds what a hand-rolled generator misses |
| M38 | CAN FD | 64-byte frames change the ISO-TP framing rules |
| M39 | STM32 + FreeRTOS port of `src/platform/` | The portability work already done, actually exercised |

## Deferred on purpose

Nothing currently. M03 was deferred until multi-frame gave the ECU and the
tester an identical non-trivial service loop, which was the trigger recorded in
decision D2. It is now built.
