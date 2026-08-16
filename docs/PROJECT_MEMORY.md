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

**A research phase is now specified.** `docs/RESEARCH.md` turns the stack into a
hardened cross-layer gateway with an adversarial state-space fuzzer, evaluated
against baselines. `docs/NOVELTY.md` governs the novelty claim. Read both before
touching `src/gateway/`.

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

**Last updated:** all planned milestones through M32 complete.

### Implemented

| Layer | Status |
|---|---|
| SocketCAN transport | `src/platform/socketcan/` — the only Linux-dependent module |
| Diagnostic link | `src/platform/diag_link.c` — ISO-TP session driving loop |
| ISO-TP | SF, FF, CF, FC, reassembly, sequence numbers, `N_Bs` / `N_Cr` |
| UDS | `0x10` DiagnosticSessionControl, `0x22` ReadDataByIdentifier, negative responses |
| Virtual ECU | Simulated sensors + static identification, DID provider callback |
| UDS services | `0x10`, `0x11`, `0x14`, `0x19`, `0x22`, `0x27`, `0x3E` |
| Access control | Session rules table, `S3server` expiry, security levels |
| Fuzzing | In-process parser fuzzer + on-bus fault injector |
| Interop | Cross-validated against the Linux kernel ISO-TP stack |
| Demo | Interactive client `diagcli`, scripted run, animated SVG, web console |
| Setup | `sudo tools/setup/install.sh` makes `vcan0` survive WSL reboots |
| CI | Build, invariants, tests, fuzz, strict warnings, cppcheck, end-to-end on vcan0 |
| Tests | 4 suites, ASan + UBSan, 14 733 checks |

Measured: 2 000 000 fuzz cases, 12 994 183 ISO-TP frames, 0 anomalies.
8 384 bytes of static state, 0 allocator symbols in the linked binaries.
See `docs/results.md`.

### Not implemented

`0x2E`, `0x31`, `0x34`/`0x36`/`0x37`, response-pending (`0x78`), functional
addressing, SecurityAccess levels beyond 1, real cryptography, CAN FD, DoIP.

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

### D9 — The SocketCAN layer was built when a second caller appeared

D2 deferred it and named the trigger: a second backend or a second
caller with the same non-trivial logic. Multi-frame produced exactly
that — the ECU and the tester both needed an identical loop mixing
reception, flow control emission and transmission progress, differing
only in which CAN identifier they send on. `src/platform/` now holds
`can_socket` (raw transport) and `diag_link` (the ISO-TP session loop).
Both applications shrank to their actual job.

### D10 — Time is a parameter, never read inside the protocol layers

`isotp_rx_process`, `isotp_tx_poll` and friends take `now_ms` as an
argument. The protocol code never calls `clock_gettime`. Two payoffs:
the timer tests advance the clock by hand and run instantly instead of
sleeping for seconds, and the port to a microcontroller does not need a
POSIX clock. `can_monotonic_ms()` lives in the platform layer where it
belongs.

Monotonic, not wall clock: a protocol timer must never jump backwards
because someone corrected the system time. Elapsed time is computed as
`(uint32_t)(now - then)`, which stays correct across the 32-bit
wraparound at 49 days — and there is a test for it.

### D11 — An oversized First Frame is answered, not ignored

A First Frame announcing more than the reassembly buffer gets a Flow
Control with `FlowStatus = Overflow` and no memory is reserved. Silently
dropping it would leave the sender waiting for its own timeout; trusting
it would be the buffer overflow the project exists to prevent.

### D12 — Two fuzzers, not one

They answer different questions and neither replaces the other. The parser
fuzzer drives the state machines in memory: millions of reproducible cases per
campaign, under sanitizers, and it is what finds overflows and impossible
states. The bus fuzzer emits real frames at a separate ECU process: far slower,
but the only one exercising sockets, service loop and reassembly together.

Both build plausible sequences and corrupt them at one point rather than
emitting noise. A purely random PCI byte is rejected outright 15 times out of
16, so pure noise would barely reach the reassembly code at all.

### D13 — The fuzzer's success criterion is liveness, not rejection

Every 25 attacks the bus fuzzer sends a perfectly valid request and requires the
exact expected reply. "The ECU rejected the frame" proves nothing if the context
stays broken afterwards — that is precisely the bug worth finding.

### D14 — SecurityAccess ships with a deliberately weak, deliberately visible key

The algorithm is three lines and published in `docs/security.md`. A more
elaborate obfuscation would have been *worse*: it would look like security
without being any. The valuable part — fresh seed per request, seed consumed by
the first failure, replay refusal, lockout that also blocks seed requests,
re-locking on session change and reset — is real and carries over unchanged to a
proper HMAC-based derivation.

### D15 — A rejected request does not refresh the session deadline

Otherwise an attacker could hold a privileged session open indefinitely using
requests it is not even allowed to make. Deadlines are also evaluated *before*
the incoming request, so a request arriving too late cannot rescue the session
it just missed.

### D16 — The kernel ISO-TP stack is the project's only external oracle

`tests/interop/crossvalidate.sh` drives `isotpsend` / `isotprecv` against our
ECU. It is the only test that can catch a transmitter and a receiver agreeing
because they share the same misreading of the standard — the failure mode every
self-contained suite is structurally blind to.

The `can-isotp` kernel module autoloads on socket creation, so the script needs
no privileged setup beyond `vcan0` itself. It self-tests the environment with a
kernel-to-kernel round trip first, so a failure points at our stack rather than
at a missing module.

### D17 — The demo ships as an animated SVG, not a GIF

`tools/demo/cast2svg.py` turns the asciinema recording into a self-contained
animated SVG: ~100 KB against several megabytes for a GIF, sharp at any zoom,
and GitHub renders it inline in the README. The generator uses only the Python
standard library, so regenerating the demo needs nothing installed beyond
`asciinema` itself.

The recording is reproducible rather than a one-off capture: `tools/demo/demo.sh`
is the script, `DEMO_PACE` controls its rhythm, and the simulated ECU is
deterministic — so `make demo` after a change produces a comparable recording,
not a different story.

### D18 — The demo SVG animates with SMIL, not CSS

The first version used CSS `@keyframes`. An SVG loaded through an `<img>` tag is
an isolated document, and several viewers do not run its stylesheet — the file
rendered as a still image. `<animate>` elements are interpreted by the SVG
engine itself, so they work wherever the SVG renders at all.

For the same reason nothing goes through a CSS class any more: colours and fonts
are presentation attributes. The file stays correct even where `<style>` is
ignored or stripped by a sanitiser.

### D19 — The web console is a tool, never part of the stack

`tools/webdemo/` is Python and lives outside `src/`. It is never compiled or
linked with the diagnostic stack, which stays dependency-free C. The precedent
was already set by `cast2svg.py`: tooling in Python, engine in C.

Two constraints it must keep. It binds to `127.0.0.1` only, because it grants
the right to spawn processes. And the browser never sends a command line — it
sends a preset identifier that the server resolves against a fixed table, so a
malicious page open in the same browser cannot make it run something arbitrary.

### D20 — Derived state beats a status flag

The scenario runner first tracked `_scenario_running` as a boolean. It desynced:
the worker finished but the flag stayed true, leaving the interface stuck on
"running" forever. It now reports `thread.is_alive()`. A flag maintained by hand
eventually lies — one forgotten exit path is enough. State derived from the
thing itself cannot.

### D21 — Novelty is claimed scoped, never as "world first"

"First in the world" is undemonstrable — confidential industrial prototypes
cannot be disproven. The defensible and scientifically stronger form is a scoped
claim tied to a documented search: "to the best of our knowledge, the first
open, evaluated system that ...". `docs/NOVELTY.md` is that search and a hard
gate: nothing stronger than Tier A (descriptive, no superlative) may be said
publicly until the prior-art review (M60) is complete and recorded. This extends
the existing anti-overclaim discipline (§6), it does not replace it.

### D22 — The invariant catalogue is code, shared by three consumers

`src/gateway/invariants.h` is the single source of truth for what "a violation"
means. The engine evaluates them, the fuzzer tries to violate them, the
benchmark counts them. If they were three separate lists they would drift, and a
violation found by one would be invisible to another. IDs are append-only: a
recorded counterexample references an ID, so an ID is never reassigned. Like the
other protocol layers it includes no system header and compiles freestanding.

### D23 — The adversary attacks the real code, and its first finding was real

`fuzz/ahdg_explore.c` drives the production `uds.c` — not a reimplementation —
through action sequences, evaluating the invariant catalogue after each step. On
its first campaign it found AHDG-0001: security surviving a return to the default
session (SEC-4), a genuine cross-layer state confusion. It was minimized to four
actions, fixed, encoded as a permanent regression, and the re-attack found zero
counterexamples over 2,000,000 sequences on two seeds.

Two rules this sets. A counterexample is not a defeat, it is a result: save it
(docs/findings/), understand it, fix it, regress it, re-attack — the loop in
RESEARCH.md §9. And the explorer's exit code gates CI: an uncovered
counterexample fails the build, so a security regression cannot pass unnoticed.

Honesty on impact is mandatory (extends §6): AHDG-0001 is documented as a latent
state confusion, not a demonstrated privilege escalation, because defense-in-depth
(the session check) masks the direct exploit in the current service set. Do not
inflate a finding's severity.

### D24 — The online lab is the real C compiled to WASM, never a JS rewrite

`web/` compiles uds.c, isotp*.c, ecu_data.c and the adversarial explorer to
WebAssembly (emscripten) and serves them on GitHub Pages, so anyone tests the
stack from a URL with no environment. It runs the production code, not a
reimplementation — a JS rewrite would be a second implementation that could
silently disagree with the C, which is exactly the failure mode the project
guards against everywhere else.

The adversary is shared as one source: `fuzz/ahdg_explore_core.h` (header-only)
is included by both the CLI (`fuzz/ahdg_explore.c`) and the WASM entry
(`web/wasm/ahdg_wasm.c`), so the browser and the command line cannot diverge.
The WASM entry lives in `web/`, outside `src/`, so its static return buffers do
not touch invariant I2. The `.wasm`/`.js` are build artefacts (gitignored),
produced by the Pages workflow, not committed.

Enabling it is a one-time manual step the user must do: repo Settings -> Pages
-> Source: GitHub Actions. The Makefile cannot do it.

### D25 — The frame-level adversary tests the cross-layer claim, honestly

`fuzz/ahdg_frames.c` drives the real isotp_rx + uds pipeline with adversarial CAN
frame sequences (SF/FF/CF/FC/garbage/interleave/timeout) and a golden probe after
each, searching for a transport manipulation that forges UDS authority (XL-*) or
wedges the ECU (AVAIL-2). Over 21M frames on two seeds: zero counterexamples
(AHDG-0002). This is bounded assurance, recorded and CI-gated (`make frames`), not
proof — the adversary explores, it does not enumerate. A negative result is a
result: it is the first experimental support for the cross-layer claims, and it
says the transport's reset-on-anomaly discipline closes the authority-forging path
by construction. Do not report it as proof, and never inflate it to "impossible".

### D26 — The gateway is the hardened UDS server reused as an admission controller

`src/gateway/gateway.c` runs the production hardened `uds.c` as a shadow,
synchronized on the ECU by observing both directions (crucially the SecurityAccess
seed the ECU issues), and forwards a request only if the hardened policy would
accept it. So the policy is not a second implementation that could drift - it IS
the audited server, reused. A permissive ECU behind it inherits the hardened
policy. Portable (freestanding, -Wconversion clean).

### D27 — The S0/S1/S2 benchmark demonstrates the thesis, honestly

`bench/bench.c`: same permissive ECU, same attack corpus, three protections.
Result (docs/findings/BENCH-S0-S1-S2.md): a stateless firewall blocks 0 of ~84k
unauthorized resets (they are well-formed known services - indistinguishable
without state), the gateway blocks all of them, and it blocks no legitimate flow
(500/500), at ~80 ns/request on host. The permissive ECU is a labeled model of a
realistic weaker ECU, not a strawman; the result is one attack class vs one
baseline, stated as such - not a coverage claim. The STM32 latency is M58.

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
[x] M03  SocketCAN abstraction            built when justified, see D9
[x] M04  UDS module extraction
[x] M05  UDS negative responses
[x] M08  ReadDataByIdentifier + ECU data model
[x] M11  ISO-TP First Frame parsing
[x] M12  ISO-TP Flow Control
[x] M13  ISO-TP Consecutive Frame RX
[x] M14  ISO-TP multi-frame reassembly
[x] M15  ISO-TP multi-frame TX
[x] M16  Sequence error handling
[x] M17  Timeout abstraction (injectable clock)
[x] M18  Timeout tests (N_Bs, N_Cr)
[x] M06  UDS session access rules
[x] M07  TesterPresent + session timeout
[x] M09  ECUReset
[x] M10  DTC model, ReadDTCInformation, ClearDiagnosticInformation
[x] M20  SecurityAccess, demo algorithm
[x] M22  Brute-force protection
[x] M23  Targeted fault injector
[x] M24  Parser fuzzing
[x] M26  Sanitizers in CI
[x] M27  Static analysis (cppcheck in CI)
[x] M29  GitHub Actions
[x] M30  Measured metrics
[x] M32  Portability proof: freestanding build, no external symbols

--- suite possible, non planifiee ---

[x] M34  Cross-validation against the Linux kernel ISO-TP stack
[x] M35  Interactive tester REPL and a recorded demo
[ ] M36  SecurityAccess with HMAC-SHA256 and a hardware RNG
[ ] M37  libFuzzer / AFL++ harnesses over the parsers
[ ] M38  CAN FD
[ ] M39  STM32 + FreeRTOS port of src/platform
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
make clean && make && make test && make check-portability && make fuzz
```

Then verify each new commit individually with `git worktree` (**I7**).

### Documents still to write

All written:

| Path | Content |
|---|---|
| `docs/isotp.md` | Frame formats, both state machines, timers, error table |
| `docs/uds.md` | Service table, NRC table, session matrix, message shapes |
| `docs/security.md` | SecurityAccess design, threat model, what to replace |
| `docs/testing.md` | Strategy, oracles, the exact-size buffer trick, how to add a suite |
| `docs/results.md` | Measured metrics only, with the commands that produced them |
| `docs/demo.md` | Reproducible five-act demo script |

Still to write, when their subject exists:

| Path | Purpose | Trigger |
|---|---|---|
| `docs/canfd.md` | What changes for 64-byte frames | when CAN FD lands |
| `docs/porting.md` | Step-by-step microcontroller port of `src/platform/` | when a second backend exists |

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
