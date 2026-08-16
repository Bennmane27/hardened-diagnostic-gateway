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
