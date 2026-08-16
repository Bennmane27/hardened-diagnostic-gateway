# Project Memory — Hardened Diagnostic Gateway

> **What this file is.** The project's brain. Anyone — human or assistant — picking
> this repository up should read this file first and trust it over any external
> description. It records the current state, the invariants that must never be
> broken, why each significant decision was made, and what remains to be done.
>
> **Maintenance rule.** This file is updated in the same commit as the work it
> describes. A milestone is not done until this file reflects it.

---

## 1. What the project is

A hardened automotive diagnostic stack written from scratch in C, running over
Linux SocketCAN with a virtual CAN bus (`vcan0`).

The goal is **not** "send a CAN frame". It is to demonstrate that the stack stays
correct, bounded and predictable when the traffic is malformed, truncated, out of
sequence or hostile. Correct rejection carries the same weight as correct service.

Secondary goal: the protocol layers must be portable to a microcontroller without
rewriting them.

Repository: `Bennmane27/hardened-diagnostic-gateway` (public).

---

## 2. Invariants — never break these

These are load-bearing. Violating one silently undoes the point of the project.

| # | Invariant | Why |
|---|---|---|
| I1 | `src/isotp/` and `src/uds/` include **no system header**. Only `<stdint.h>`, `<stddef.h>`, `<string.h>`. | This is what makes the STM32 port possible without a rewrite. Verified by `make check-portability`. |
| I2 | No `malloc`/`calloc`/`realloc`/`free` anywhere in `src/`. | Bounded, predictable memory. Verified by `make check-portability`. |
| I3 | Every public function returns an explicit status enum; data leaves through pointers. | A caller cannot use a result without being able to test for failure. |
| I4 | Buffer capacity is checked **before** any write, never after. | Makes overflow structurally impossible rather than detected too late. |
| I5 | Multi-byte protocol values are encoded byte by byte, big endian. Never `memcpy` a `uint16_t`. | A `memcpy` would silently produce little-endian bytes on x86 and break on another target. |
| I6 | Simulated data evolves from a counter, never from `rand()`. | Demonstrations are reproducible and the model is testable. |
| I7 | No commit is pushed unless `make` and `make test` both pass on it. | `git bisect` stays usable. Verified per-commit with `git worktree`. |
| I8 | A malformed input never crashes, never overflows, and always leaves the context in a defined state. | The entire premise of the project. |

---

## 3. Current state

**Last updated:** milestone M08 complete.

### Implemented

| Layer | Status |
|---|---|
| SocketCAN transport | `ecu.c`, `tester.c` — raw CAN sockets on `vcan0` |
| ISO-TP | Single Frame encode/decode, full validation |
| UDS | `0x10` DiagnosticSessionControl, `0x22` ReadDataByIdentifier, negative responses |
| Virtual ECU | Simulated sensors + static identification, DID provider callback |
| Tests | 3 suites, ASan + UBSan, 2576 checks |

### Not yet implemented

ISO-TP multi-frame (FF/FC/CF), any ISO-TP timer, session access rules,
`TesterPresent`, DTCs, SecurityAccess, fuzzer, CI, CAN FD, DoIP.

---

## 4. Decision log

Decisions that would otherwise look arbitrary later.

### D1 — ISO-TP takes byte buffers, not `struct can_frame`

Rejected the API shape `isotp_decode_single_frame(const struct can_frame *, ...)`.
It would have forced `#include <linux/can.h>` into the protocol layer, which
breaks **I1**. The chosen signature takes `(const uint8_t *frame, uint8_t len)`.
Costs nothing, removes the coupling entirely.

### D2 — No SocketCAN abstraction layer yet

The backlog listed one early. Deferred: there are exactly two callers, and the
protocol layers are already Linux-free, which was the real goal. Building it now
would be abstraction for its own sake. The trigger to build it is a **second
backend** (STM32 stub, or a fuzzer that needs its own transport), not a feeling
of tidiness.

### D3 — UDS reads application data through a callback

`uds.c` holds no vehicle data. The application registers
`uds_set_did_provider(ctx, fn, user_ctx)`. This keeps the server reusable across
different ECUs and lets tests inject a fake provider instead of dragging the
simulated ECU into the UDS test binary.

### D4 — The VIN is kept at its real 17 bytes even though it does not fit

It cannot be transported by a Single Frame. Rather than shorten it to make the
demo pass, the server answers `7F 22 14` *responseTooLong* — the code ISO 14229
defines for exactly this situation. The failure is the feature: it is what makes
multi-frame a demonstrated need rather than a checkbox.

### D5 — Makefile, not CMake

Introduced when the build outgrew a single `gcc` line. CMake buys cross-platform
generation we do not need yet. Revisit if a second toolchain appears.

### D6 — `-D_DEFAULT_SOURCE` is required

Under strict `-std=c11`, glibc hides `struct ifreq`. Without the macro the build
fails with `storage size of 'ifr' isn't known`. Applications only — the test
binaries do not need it, which is itself a check on **I1**.

### D7 — Tests carry an independent oracle

`tests/test_isotp.c` reimplements the Single Frame classification from the
specification, separately from `isotp.c`, and compares the two. A test derived
from the code under test reproduces its bugs and passes.

### D8 — Frames are decoded in buffers sized to the exact DLC

Under ASan, any read past the announced length aborts the run. With a
comfortable `uint8_t frame[8]` the same over-read would be silent. This is what
turns "the parser looks safe" into a mechanically checked property.

---

## 5. Conventions

### Commits

`type(scope): imperative summary`, body explaining **why**, not what.

Types used: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `chore`.
Scopes: `isotp`, `uds`, `ecu`, `tester`, `fuzz`, `ci`.

Every commit must build and pass tests on its own (**I7**).

### Code

Fixed-width types. Named constants, no magic numbers. Short functions. `u`
suffix on unsigned literals in protocol code. Comments explain intent and
protocol reasoning, not syntax. French comments in source, English in the README
and commits (the repository is public and international; the source comments are
the author's working language).

### Tests

No framework. A `check(condition, "description")` helper, a counter, exit code.
Prefer exhaustive sweeps where the input space is enumerable. Always build with
`-fsanitize=address,undefined`.

Every new UDS service must be added to the implemented-services list in
`tests/test_uds.c`, or the SID sweep fails. This is deliberate: it forces a test
to accompany each service.

---

## 6. Language on standards — do not oversell

The README and any post must say:

- "targeting ISO 15765-2 behavior", not "ISO 15765-2 compliant"
- "a subset of ISO 14229-1", not "full UDS"
- "MISRA-oriented style", not "MISRA compliant"
- "fuzz-tested", "stress-tested", "deterministic failure handling" — never
  "mathematically proven", "unhackable", "production-ready"

Protocol details here follow widely published descriptions of both standards.
They have **not** been verified against the paid standard documents, and the
README says so.

---

## 7. Backlog

Status: `[x]` done · `[>]` in progress · `[ ]` not started

```
[x] M01  ISO-TP Single Frame module
[x] M02  Single Frame unit tests
[~] M03  SocketCAN abstraction            deferred, see D2
[x] M04  UDS module extraction
[x] M05  UDS negative responses
[x] M08  ReadDataByIdentifier + ECU data model
[ ] M11  ISO-TP First Frame parsing
[ ] M12  ISO-TP Flow Control
[ ] M13  ISO-TP Consecutive Frame RX
[ ] M14  ISO-TP multi-frame reassembly
[ ] M15  ISO-TP multi-frame TX
[ ] M16  Sequence error handling
[ ] M17  Timeout abstraction (injectable clock)
[ ] M18  Timeout tests (N_Bs, N_Cr)
[ ] M06  UDS session access rules
[ ] M07  TesterPresent + session timeout
[ ] M09  ECUReset
[ ] M10  DTC model, ReadDTCInformation, ClearDiagnosticInformation
[ ] M20  SecurityAccess, demo algorithm
[ ] M22  Brute-force protection
[ ] M23  Targeted fault injector
[ ] M24  Parser fuzzing
[ ] M26  Sanitizers in CI
[ ] M27  Static analysis
[ ] M29  GitHub Actions
[ ] M30  Measured metrics
[ ] M32  Portability proof: protocol core built without Linux
```

---

## 8. Standing instructions for future work

Reminders that would otherwise be rediscovered the hard way.

### When adding a UDS service

1. Constant in `uds.h` (`UDS_SID_*`).
2. Handler in `uds.c`, `static`, one function.
3. Add the SID to `implemented[]` in `tests/test_uds.c` — the sweep fails otherwise.
4. Test the **rejection** paths before the nominal one: wrong length, wrong
   sub-function, wrong session, absent provider.
5. Add a step to the tester scenario.
6. README: service table, limitations, roadmap.
7. This file: sections 3 and 7.

### When adding an ISO-TP frame type

1. Never trust an announced length. Compare against both the received DLC and
   the buffer capacity, before copying (**I4**).
2. Any error resets the reception context to a defined state (**I8**).
3. Add the malformed case to the fuzzer scenario list.
4. Sweep the input space exhaustively if it is enumerable.

### When touching the build

`make check-portability` must keep passing. It is what guards **I1** and **I2**.

### Before any push

```bash
make clean && make && make test && make check-portability
```

Then verify each new commit individually with `git worktree` (**I7**).

### Documents still to write

| Path | Purpose | Trigger |
|---|---|---|
| `docs/isotp.md` | Frame formats, state machines, timers, error table | when multi-frame lands |
| `docs/uds.md` | Service table, NRC table, session matrix | when session rules land |
| `docs/security.md` | SecurityAccess design, threat model, demo-key warning | when `0x27` lands |
| `docs/testing.md` | Test strategy, oracles, how to add a suite | when the fuzzer lands |
| `docs/results.md` | Measured metrics only — never estimated | when the fuzzer produces numbers |
| `docs/demo.md` | Reproducible demo script | before recording the GIF |

### Visual interface — decided direction

A web dashboard is **last**, and possibly never. It would reframe the project as
a web project with some C in it, which is the opposite of the intended
impression. The order is: scripted terminal GIF → interactive tester REPL in C →
`ncurses` TUI once the fuzzer produces counters worth watching.

---

## 9. Environment

Windows 11 → WSL 2 → Ubuntu → VS Code (WSL mode). Working directory
`~/can_project`.

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Git identity is the GitHub noreply address `86740046+Bennmane27@users.noreply.github.com`,
matching the existing history. Credentials go through Git Credential Manager on
the Windows side; never store a token in the repository or in plain text.

`gh` CLI is **not** installed. `asciinema`, `vhs` and `libncurses-dev` are not
installed either — they need `apt` and therefore the user.
