# Testing strategy

```bash
make test               # unit suites, ASan + UBSan
make fuzz               # parser fuzzing campaign
make check-portability  # architecture invariants
```

Measured results live in [results.md](results.md).

## What is being tested for

Not "does the happy path work". A diagnostic server spends most of its life
rejecting things, and that is where the bugs are. The suites are weighted
accordingly: the UDS tests spend far more assertions on refusal paths than on
successful ones.

Three properties matter more than any individual assertion:

1. A malformed input never reads or writes outside a buffer.
2. A malformed input always leaves the context in a defined state.
3. A protected operation is never granted without its precondition.

Each has a mechanism behind it, described below.

## No framework

A `check(condition, "description")` helper, a counter, and an exit code. That
is the whole harness.

The reasoning is the same one the project applies everywhere: a dependency has
to earn its place. A test framework would buy fixtures and parametrisation
neither suite needs, in exchange for something to install before the project
builds.

## Exhaustive sweeps where the space allows

Fuzzing explores an input space. When the space is small enough to enumerate,
enumeration is strictly better — it proves coverage instead of sampling it.

| Target | Space | Combinations |
|---|---|---:|
| ISO-TP single frame decoder | 256 PCI × 9 lengths | 2 304 |
| ISO-TP multi-frame receiver | same, idle and mid-reassembly | 4 608 |
| UDS server | 256 SID × 4 sub-functions × 7 lengths | 7 168 |
| ECU data provider | 8 identifiers × 21 buffer capacities | 168 |

These are complete for one frame or one request. They say nothing about
sequences of them — that is what the fuzzer is for.

## The exact-size buffer trick

This is the mechanism behind property 1, and it is the single most valuable
idea in the suites.

Every frame handed to a decoder is allocated on the heap at **exactly** the
announced DLC:

```c
uint8_t *frame = malloc(frame_len ? frame_len : 1);
...
isotp_decode_single_frame(frame, frame_len, &payload, &payload_len);
```

Under AddressSanitizer, reading one byte past the end aborts the run. With a
comfortable `uint8_t frame[8]` on the stack, the same over-read would be
silent and the test would pass.

That is what turns "the parser looks safe" into a mechanically checked
property. It is also why the classic ISO-TP bug — trusting the announced length
over the received one — cannot survive here unnoticed.

`malloc` in a test harness is fine. Invariant I2 constrains `src/`, not the
tests, and using the allocator is precisely what gives ASan its bounds.

## Independent oracles

`tests/test_isotp.c` reimplements the single-frame classification straight from
the specification, separately from `isotp.c`, and compares the two across all
2 304 combinations.

A test derived from the code under test reproduces that code's bugs and passes.
Two implementations written independently agreeing on the whole input space is a
real signal.

## Injected fakes

`0x22` and `0x19` are tested against fake providers, not against the simulated
ECU. That is what the callback decoupling buys: the UDS test binary does not
link `ecu_data.c` at all.

It also lets the tests reach conditions the real ECU cannot produce — a
provider that returns a value larger than any buffer, for instance, which is how
`responseTooLong` gets covered.

## Time is injected, never read

The protocol layers take `now_ms` as a parameter. Timer tests therefore advance
the clock by hand:

```c
isotp_rx_process(&rx, ff, 8, 1000u, &out);
isotp_rx_poll_timeout(&rx, 1000u + ISOTP_N_CR_TIMEOUT_MS, &out);
```

A one-second timeout is verified instantly instead of sleeping for a second.
The `S3server` and lockout tests work the same way.

It also makes an otherwise untestable case easy: the 32-bit millisecond counter
wraps after roughly 49 days, and there is a test that drives the clock across
the wrap to confirm no false timeout fires.

## The fuzzers

Two of them, answering different questions.

**Parser fuzzing** (`fuzz/fuzz_parser.c`) feeds the state machines in memory.
Millions of cases, reproducible from a seed, under sanitizers. This is what
finds overflows and impossible states.

It is not random noise: a purely random first byte is rejected outright 15 times
out of 16, so the generator builds plausible frames — a correct sequence number
one time in three, otherwise a wrong one — and degrades them. Contexts are
deliberately *not* reset between iterations, because the interesting states are
the ones reached after a long run of malformed traffic.

What it asserts on every case:

- the reception state is always one of the two known values;
- accumulated bytes never exceed the announced length;
- the announced length never exceeds the buffer;
- a positive response always matches the requested service;
- a response never exceeds the caller's buffer;
- `ECUReset` is never accepted while security is locked.

**Bus fuzzing** (`tools/fuzzer/fuzz_bus.c`) emits real frames on `vcan0` at a
separate ECU process. Far slower, and the only one testing the full chain:
sockets, service loop, reassembly, UDS server.

Eleven targeted scenarios, each building a plausible sequence and corrupting it
at one point — wrong sequence number, missing consecutive frame, oversized
announcement, orphan frames, interleaved transfers, key without seed, reset
without unlock.

Its success criterion is not "the ECU rejected the frame". Every 25 attacks it
sends a perfectly valid request and requires the exact expected reply. Rejecting
an attack proves nothing if the context stays broken afterwards.

## Reproducibility

Both fuzzers take a seed and use xorshift32, so a failing campaign replays
exactly. Anomalies print the generator state at the failing case.

The simulated ECU data evolves from a tick counter, never from `rand()` — two
runs of the demo produce identical traces, which is also what makes a recorded
demonstration honest.

## Cross-validation against the kernel

```bash
tests/interop/crossvalidate.sh
```

This is the most valuable test in the project, and the reason is worth stating
plainly: every other suite only proves that *our* transmitter and *our* receiver
agree with each other. If both share the same misreading of the standard, they
will agree perfectly and every test will pass.

The Linux kernel ISO-TP implementation (`can-isotp`, driven through `isotpsend`
and `isotprecv`) is an independent, widely deployed arbiter. Four exchanges:

| # | Direction | What it proves |
|---|---|---|
| 1 | kernel sends `10 03`, reads our reply | Single-frame round trip, including the `sessionParameterRecord` |
| 2 | kernel requests the VIN, reassembles our reply | **Our multi-frame transmission is standard-conformant**, not merely self-consistent |
| 3 | kernel sends a 30-byte message | Our reassembly accepts a foreign sender's segmentation, then UDS correctly refuses the over-long request |
| 4 | kernel requests an unknown service | Negative responses survive the transport unchanged |

Test 2 is the one that matters most. The kernel receiving `62 F1 90` followed by
the exact 17 VIN bytes means our First Frame length encoding, our sequence
numbers and our response to its Flow Control were all read correctly by code
that has never seen ours.

The script self-tests the environment first — a kernel-to-kernel round trip —
so a failure points at our stack rather than at a missing module.

Result: **5 checks, 0 failures.**

## Architecture invariants

`make check-portability` fails the build if:

- a system header appears in `src/isotp/` or `src/uds/`;
- an allocator call appears anywhere in `src/`;
- the protocol layers stop compiling outside a Linux context;
- they stop compiling under `-Wconversion -Wshadow -Werror -Wpedantic`;
- `nm -u` finds an allocator symbol in the linked binaries.

The last one is stronger than grepping sources: it proves nothing in the whole
link reaches the heap, including through a library.

An invariant nobody verifies is a comment, not a constraint.

## CI

`.github/workflows/ci.yml` runs four jobs: build + invariants + tests + a
500 000 case fuzz campaign; the protocol layers under strict warnings;
`cppcheck`; and an end-to-end job that creates a real `vcan0`, runs the full
diagnostic scenario, cross-validates against the kernel ISO-TP stack, then runs
the bus fuzzer against the same ECU.

The bus fuzzer's exit code is what gates that last job — non-zero if a liveness
probe failed or a protected command was accepted.

## Adding a suite

1. `tests/test_<thing>.c`, no framework, `check()` and a counter, `main` returns
   non-zero on failure.
2. A `$(BUILD)/test_<thing>` rule in the Makefile using `$(TEST_CFLAGS)` — the
   sanitizers are not optional.
3. Add it to the `test` target.
4. Test the refusal paths before the nominal one.
5. If the input space is enumerable, enumerate it.

For a new UDS service, also add its SID to `implemented[]` in
`tests/test_uds.c`. The sweep fails until you do — deliberately, so a service
cannot ship without a test.

## Known gaps

- No coverage measurement.
- `libFuzzer` / AFL++ harnesses are not wired up; the in-process fuzzer is
  hand-rolled.
- No performance or latency benchmarks.
