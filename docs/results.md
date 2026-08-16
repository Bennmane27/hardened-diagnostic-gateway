# Measured results

Every figure on this page was produced by running the commands shown next to
it. Nothing here is estimated. Re-running the commands reproduces the numbers,
because both the simulated ECU data and the fuzzing campaigns are driven by
explicit seeds rather than by `rand()`.

Platform: WSL 2 / Ubuntu on x86-64, GCC 13, `vcan0` virtual CAN interface.

---

## Test suites

```bash
make test
```

| Suite | Checks | Failures |
|---|---:|---:|
| ISO-TP single frame | 2 480 | 0 |
| ISO-TP multi-frame | 4 914 | 0 |
| UDS server | 7 284 | 0 |
| Virtual ECU data | 55 | 0 |
| **Total** | **14 733** | **0** |

All four binaries are compiled with `-fsanitize=address,undefined`. No
sanitizer finding was reported.

Two of those suites are exhaustive rather than sampled, because their input
space is small enough to enumerate completely:

- the ISO-TP single frame decoder is swept over all 256 PCI values crossed with
  all 9 possible frame lengths — 2 304 combinations;
- the multi-frame receiver is swept over the same space twice, once idle and
  once mid-reassembly — 4 608 combinations;
- the UDS server is swept over 256 service identifiers × 4 sub-functions ×
  7 request lengths — 7 168 requests.

## Parser fuzzing

```bash
./build/fuzz_parser 2000000 0x5EED1
```

| Metric | Value |
|---|---:|
| Cases played | 2 000 000 |
| ISO-TP frames processed | 12 994 183 |
| Messages reassembled | 765 756 |
| Sequence errors detected | 988 290 |
| Oversized announcements refused | 268 |
| Reassembly timeouts | 181 926 |
| UDS requests | 2 000 000 |
| Negative responses | 1 933 973 |
| Positive responses | 5 405 |
| **Anomalies** | **0** |

Built with AddressSanitizer and UndefinedBehaviorSanitizer, so a buffer overrun
or an undefined operation would have aborted the run rather than being counted.

"Anomaly" here does not mean "the parser rejected something". Rejection is the
expected outcome for most of these inputs. An anomaly is a violated invariant:
a reception context left in an unknown state, more bytes accumulated than the
message announced, an announced length exceeding the buffer, a positive
response to a service that was not requested, a reply larger than the caller's
buffer, or `ECUReset` accepted while security is still locked.

## Fault injection on the bus

```bash
./build/ecu -q &
./build/fuzz_bus 200 0xBADC0DE
```

Eleven targeted scenarios rather than random bytes, because a stateful protocol
is barely exercised by noise — a purely random first byte is rejected outright
15 times out of 16. Each scenario builds a plausible sequence and then corrupts
it at one specific point.

| Scenario | Runs |
|---|---:|
| Wrong sequence number (`21 22 27`) | 18 |
| Missing consecutive frame | 9 |
| Oversized announced length | 23 |
| Truncated single frame | 24 |
| Orphan consecutive frames | 16 |
| Non-existent frame type | 21 |
| Interleaved transfers | 14 |
| Malformed UDS request | 20 |
| Security key with no seed | 20 |
| `ECUReset` with no unlock | 20 |
| Random frame burst | 15 |

| Result | Value |
|---|---:|
| Attacks played | 200 |
| Frames emitted | 950 |
| Liveness probes | 10 |
| Probes answered correctly | 10 |
| Probes failed | 0 |
| Unauthorised `ECUReset` accepted | 0 |

The liveness probe is what makes this meaningful. Rejecting an attack proves
nothing if the context stays broken afterwards, so every 25 attacks the fuzzer
sends a perfectly valid request and requires the exact expected answer. The
ECU process survived the whole campaign.

## Memory

```bash
size build/ecu
nm -u build/ecu | grep -E '\b(malloc|calloc|realloc|free)\b'
```

| Section | Bytes |
|---|---:|
| `text` | 26 936 |
| `data` | 748 |
| `bss` | 8 496 |
| **Total** | **36 180** |

Static context sizes:

| Context | Bytes |
|---|---:|
| `isotp_rx_context_t` | 4 136 |
| `isotp_tx_context_t` | 4 128 |
| `uds_context_t` | 72 |
| `ecu_data_t` | 48 |
| **Total held by the ECU** | **8 384** |

The two ISO-TP contexts dominate, and both are dominated in turn by their 4 095
byte reassembly buffer — the maximum message size the classic addressing mode
allows. `ISOTP_MAX_PAYLOAD_SIZE` is overridable at compile time, so a
constrained target can trade capacity for RAM without touching the code.

`nm -u` reports **zero** allocator symbols in `build/ecu` and `build/tester`.
That is a stronger statement than grepping the sources for `malloc`: it means
nothing anywhere in the link, including through a library call, reaches the
heap. `make check-portability` enforces it.

## Compiler warnings

```bash
make check-portability
```

`src/isotp/` and `src/uds/` compile clean under:

```
-Wall -Wextra -Werror -Wconversion -Wshadow -Wpedantic -std=c11
```

`-Wconversion` is the demanding one: it flags every implicit narrowing between
integer types, which is exactly where a protocol parser quietly loses a byte.
The protocol layers pass it today with no suppressions.

## What these numbers do not say

They are evidence of robustness, not proof of correctness. Fuzzing explores; it
does not enumerate. The exhaustive sweeps genuinely cover their stated input
space, but that space is one frame or one request at a time — not every
possible *sequence* of them.

No conformance test suite has been run against either standard, and the
protocol details follow published descriptions rather than the paid standard
documents.
