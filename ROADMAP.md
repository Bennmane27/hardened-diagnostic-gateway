# Roadmap

Status of each milestone. The detailed rationale behind every decision lives in
[docs/PROJECT_MEMORY.md](docs/PROJECT_MEMORY.md).

## Done

| # | Milestone | Commit |
|---|---|---|
| M01 | ISO-TP Single Frame module | `9fb2b42`, `aa1cb80` |
| M02 | Single Frame unit tests | `aea496e` |
| M04 | UDS module extraction | `a3293dc` |
| M05 | UDS negative responses | `a3293dc` |
| M08 | ReadDataByIdentifier + virtual ECU data model | `c91ec8d`, `a2a76b7` |

## In progress

| # | Milestone |
|---|---|
| M11–M16 | ISO-TP multi-frame: First Frame, Flow Control, Consecutive Frames, reassembly, transmission, sequence errors |

## Next

| # | Milestone | Why it comes here |
|---|---|---|
| M17–M18 | Timeout abstraction and its tests | Multi-frame is meaningless without `N_Bs` / `N_Cr`: a peer that stops mid-transfer must not wedge the receiver |
| M06–M07 | Session access rules, `TesterPresent` | Sessions are tracked but gate nothing yet |
| M09–M10 | `ECUReset`, DTC model, `ReadDTCInformation`, `ClearDiagnosticInformation` | Makes the virtual ECU behave like a real one |
| M20–M22 | `SecurityAccess`, brute-force protection | Needs stable sessions underneath |
| M23–M24 | Fault injector and parser fuzzing | Needs a state machine worth attacking |
| M26–M30 | Sanitizers in CI, static analysis, GitHub Actions, measured metrics | |
| M32 | Portability proof: protocol core built with no Linux headers | |

## Later

CAN FD, an STM32 + FreeRTOS port, DoIP.

## Deferred on purpose

**M03 — SocketCAN abstraction layer.** There are two callers, and the protocol
layers already contain no Linux dependency, which was the actual goal. Building
the abstraction now would add indirection with no benefit. The trigger is a
second backend, not tidiness.
