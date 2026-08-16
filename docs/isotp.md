# ISO-TP layer

Transport layer targeting ISO 15765-2 behavior on classic CAN. Implemented in
`src/isotp/`, with no system header anywhere in it — the layer works on raw byte
buffers and is handed the current time as a parameter.

## Why a transport layer at all

A CAN frame carries at most 8 bytes. A diagnostic message routinely needs more:
a VIN alone is 17. ISO-TP is what splits a message across several frames and
puts it back together, with the receiver able to say "slow down" or "I can't
hold that much".

## Frame formats

Every ISO-TP frame starts with a Protocol Control Information byte. Its upper
four bits say what kind of frame it is; the lower four mean something different
per kind.

```
bit  7 6 5 4 | 3 2 1 0
     type    | depends on type
```

### Single Frame — type 0

```
byte 0 : 0x0L        L = payload length, 1..7
bytes 1..7 : payload
```

`0x02 10 03` is a two-byte payload carrying the UDS request `10 03`.

`L = 0` is invalid — a single frame carries at least one byte. `L > 7` cannot
fit and is refused rather than trusted.

### First Frame — type 1

```
byte 0 : 0x1H        H = total length, bits 11..8
byte 1 : L           total length, bits 7..0
bytes 2..7 : first 6 payload bytes
```

`10 14` announces `0x014` = 20 bytes. The length field is 12 bits, so the
classic form tops out at 4 095 bytes.

There is an escape form for longer messages: a 12-bit length of zero means the
real length follows as a 32-bit value in bytes 2..5, leaving 2 payload bytes in
the frame. The parser handles it and then refuses anything larger than the
reassembly buffer — a 4 GB announcement is answered, not ignored.

A First Frame announcing fewer than 8 bytes is malformed: that message should
have been a Single Frame.

### Consecutive Frame — type 2

```
byte 0 : 0x2N        N = sequence number, 0..15
bytes 1..7 : up to 7 payload bytes
```

The First Frame counts as sequence 0, so the first Consecutive Frame is `0x21`.
The counter wraps from 15 back to 0, which is why a long transfer shows
`... 2E 2F 20 21 ...`.

### Flow Control — type 3

```
byte 0 : 0x3S        S = FlowStatus
byte 1 : BlockSize
byte 2 : STmin
```

| FlowStatus | Meaning |
|---|---|
| `0` ContinueToSend | go ahead |
| `1` Wait | hold on, another Flow Control is coming |
| `2` Overflow | I cannot store that message, give up |

`BlockSize` is how many Consecutive Frames the sender may emit before asking
again; `0` means no limit. `STmin` is the minimum gap between two Consecutive
Frames: `0x00`–`0x7F` in milliseconds, `0xF1`–`0xF9` for 100–900 microseconds.
Reserved values are treated as 127 ms, the most conservative reading.

This receiver advertises `BlockSize = 0` and `STmin = 0`. The project hardens
parsing, not throughput.

## Reception state machine

A state machine is three things: a current **state**, **events** that arrive,
and **transitions** saying which state follows. Writing it explicitly, rather
than as nested conditionals, means every transition is visible and an
unforeseen case falls into a default that resets cleanly instead of leaving a
half-open context.

```
                    ┌──────────────────────────────┐
                    │            IDLE              │
                    └──────────────────────────────┘
                       │            │            ▲
        Single Frame   │            │ First      │ message complete
        (message ready)│            │ Frame      │ sequence error
                       │            │ (send FC)  │ N_Cr expired
                       ▼            ▼            │
                    ┌──────────────────────────────┐
                    │      WAIT_CONSECUTIVE        │
                    └──────────────────────────────┘
                              │        ▲
                expected CF,  │        │  expected CF,
                still short   └────────┘  message complete → IDLE
```

Rules that are easy to get wrong and are tested explicitly:

- A Consecutive Frame arriving with no transfer open is **ignored**, not an
  error that resets anything. A fuzzer sending orphan CFs must not be able to
  disturb a legitimate transfer.
- A malformed Single Frame arriving mid-transfer is **ignored** for the same
  reason. Letting an invalid frame destroy a valid transfer would be a
  denial-of-service vector.
- A *valid* Single Frame mid-transfer **replaces** the transfer. The standard
  leaves the choice; the complete, coherent message wins.
- A wrong sequence number **aborts** and resets. One unit off means a lost,
  duplicated or injected frame.
- Whatever happens, the context ends in a defined state. An attacker must not
  be able to wedge it.

## Transmission state machine

```
   IDLE ──── message ≤ 7 bytes ────► IDLE            (one Single Frame)
   IDLE ──── message > 7 bytes ────► WAIT_FLOW_CONTROL   (First Frame sent)

   WAIT_FLOW_CONTROL ── ContinueToSend ──► SENDING
   WAIT_FLOW_CONTROL ── Wait ────────────► WAIT_FLOW_CONTROL  (N_Bs restarted)
   WAIT_FLOW_CONTROL ── Overflow ────────► IDLE  (give up)
   WAIT_FLOW_CONTROL ── N_Bs expired ────► IDLE  (give up)

   SENDING ── STmin elapsed, bytes left ──► SENDING
   SENDING ── block size reached ─────────► WAIT_FLOW_CONTROL
   SENDING ── last byte sent ─────────────► IDLE
```

One subtlety: after a Flow Control the first Consecutive Frame goes out
immediately. `STmin` is the gap *between* Consecutive Frames, not between the
Flow Control and the first one.

## Timers

Two are implemented.

| Timer | Side | Meaning |
|---|---|---|
| `N_Cr` | receiver | maximum gap between two Consecutive Frames |
| `N_Bs` | sender | maximum wait for a Flow Control |

Both default to 1 000 ms and are overridable at compile time.

Without them a peer that stops mid-transfer would hold the other side forever —
which is a denial of service that costs the attacker nothing.

**The layer never reads a clock.** `isotp_rx_process`, `isotp_tx_poll` and the
rest take `now_ms` as an argument. Two consequences: the timer tests advance
the clock by hand and finish instantly instead of sleeping, and a
microcontroller port needs no POSIX clock. `can_monotonic_ms()` lives in the
platform layer.

Elapsed time is computed as `(uint32_t)(now - then)`. Unsigned subtraction stays
correct when a 32-bit millisecond counter wraps — which happens after about 49
days — and there is a test that drives the clock across the wrap to prove it.

## Error table

| Code | Cause |
|---|---|
| `ISOTP_ERR_INVALID_LENGTH` | `SF_DL = 0`, `SF_DL > 7`, First Frame under 8 bytes, reserved FlowStatus |
| `ISOTP_ERR_TRUNCATED_FRAME` | announced payload exceeds the received DLC |
| `ISOTP_ERR_NOT_SINGLE_FRAME` | single-frame decoder handed another type |
| `ISOTP_ERR_UNEXPECTED_FRAME` | Consecutive Frame with no transfer open, unsolicited Flow Control, frame type 4–15 |
| `ISOTP_ERR_SEQUENCE_NUMBER` | sequence number is not the expected one |
| `ISOTP_ERR_OVERFLOW` | announced message larger than the reassembly buffer |
| `ISOTP_ERR_TIMEOUT` | `N_Bs` or `N_Cr` expired |
| `ISOTP_ERR_ABORTED` | peer answered Overflow |
| `ISOTP_ERR_BUSY` | a transmission is already in progress |

## Memory

Two static contexts, no allocation:

| Context | Bytes |
|---|---:|
| `isotp_rx_context_t` | 4 136 |
| `isotp_tx_context_t` | 4 128 |

Both are dominated by their 4 095-byte buffer. `ISOTP_MAX_PAYLOAD_SIZE` is
overridable, so a constrained target trades capacity for RAM without a code
change.

The transmit path copies the caller's payload into its context rather than
holding a pointer to it. That costs memory and buys the removal of every
lifetime question: the caller can reuse its buffer immediately.

## Not implemented

- Extended and mixed addressing modes — normal addressing only.
- `N_As`, `N_Ar`, `N_Br`, `N_Cs`.
- CAN FD frame sizes.
- Cross-validation against the Linux kernel ISO-TP implementation, which
  remains the most valuable test still missing: it is what would catch an
  implementation that works only because both ends share the same
  misunderstanding.
