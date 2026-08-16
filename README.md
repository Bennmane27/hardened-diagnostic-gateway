# Hardened Diagnostic Gateway

A hands-on embedded systems project building a deterministic and robust automotive diagnostic stack in C, from the ground up.

The protocol layers are written from scratch rather than pulled from existing ISO-TP or UDS libraries — implementing them is the point of the project. Development runs against a virtual CAN bus (Linux SocketCAN + `vcan`), with the explicit goal of keeping the protocol cores free of any Linux dependency so they can later be ported to a microcontroller.

## The problem

Sending a CAN frame is easy. The interesting question is different:

> does the stack stay correct, bounded and predictable when the bus traffic becomes malformed, truncated, out of sequence or hostile?

Modern vehicles are moving toward software-defined architectures — domain and zonal controllers, gateways, remote diagnostics, OTA updates — where a diagnostic endpoint is exposed to traffic it does not control. This project therefore treats every incoming frame as untrusted, and gives equal weight to correct rejection and correct service.

## Current status

### Milestone 0 — Development environment ✅

Validated on Windows 11 using WSL 2 + Ubuntu: `can-utils` installed, `vcan0` virtual interface created, traffic verified with `cansend` and `candump`.

### Milestone 1 — First CAN frame from C ✅

A C program sends an 8-byte CAN frame on arbitration ID `0x7E0` through SocketCAN.

### Milestone 2 — Virtual ECU and bidirectional exchange ✅

A second program listens on the bus, filters requests on `0x7E0` and answers on `0x7E8`. The tester waits for and decodes that answer itself; `candump` is now only an independent observer.

### Milestone 3 — ISO-TP Single Frame layer ✅

The ISO-TP protocol control information is no longer decoded inline by the applications. `src/isotp/` owns the format and validates it.

The decoder rejects, rather than trusts, the announced length:

| Input | Result |
|---|---|
| `SF_DL = 0` | rejected — invalid per ISO 15765-2 |
| `SF_DL = 8..15` | rejected — impossible in an 8-byte frame |
| `SF_DL = 7` with `DLC = 3` | rejected — announced payload exceeds received data |
| First / Consecutive / Flow Control frames | rejected — not yet supported |

`isotp.c` includes no system header at all: it operates on raw byte buffers and a length, never on `struct can_frame`.

### Milestone 4 — UDS server with negative responses ✅

`src/uds/` implements a subset of ISO 14229-1. The ECU no longer decodes services inline.

Supported today:

- `0x10` DiagnosticSessionControl — default and extended sessions, with the `sessionParameterRecord` (P2Server_max, P2\*Server_max) in the positive response
- `suppressPosRspMsgIndicationBit` (bit 7 of the sub-function): the positive response is withheld, negative responses are not
- negative responses `7F <SID> <NRC>` for every unsupported service, unknown sub-function and incorrect message length

Like the ISO-TP layer, `uds.c` includes no system header and knows nothing about its transport.

### Milestone 5 — ReadDataByIdentifier and virtual ECU data ✅

`0x22` ReadDataByIdentifier, plus a simulated data model in `src/ecu/ecu_data.c`: engine RPM, vehicle speed, coolant temperature, battery voltage, software version, serial number and VIN.

The UDS server holds no vehicle data. The application registers a provider callback (`uds_set_did_provider`), so the same server could serve an engine controller or a braking controller unchanged — and the unit tests inject a fake provider instead of the real ECU.

This milestone is also where the Single Frame limit becomes visible on purpose. A VIN is 17 bytes; the response would need 20 bytes against the 7 available. Rather than truncate silently, the server answers `7F 22 14` — *responseTooLong*, the NRC ISO 14229 defines for exactly this case: a transport limit surfacing as a protocol error.

## Architecture

```text
        Diagnostic Tester                 Virtual ECU
              │                                ▲
              │ UDS                            │ UDS
              ▼                                │
        ┌───────────┐                    ┌───────────┐
        │  src/uds  │                    │  src/uds  │
        └─────┬─────┘                    └─────▲─────┘
              │                                │
        ┌─────▼─────┐                    ┌─────┴─────┐
        │ src/isotp │                    │ src/isotp │
        └─────┬─────┘                    └─────▲─────┘
              │                                │
        ┌─────▼─────┐                    ┌─────┴─────┐
        │ SocketCAN │                    │ SocketCAN │
        └─────┬─────┘                    └─────▲─────┘
              │                                │
              └────────────► vcan0 ────────────┘
```

`src/isotp` and `src/uds` include only `<stdint.h>` and `<stddef.h>`. Everything Linux-specific lives in the two application files.

## Layout

```text
├── Makefile
├── src/
│   ├── isotp/{isotp.c, isotp.h}       ISO-TP transport, Single Frame
│   ├── uds/{uds.c, uds.h}             UDS server, subset of ISO 14229-1
│   ├── ecu/
│   │   ├── ecu.c                      virtual ECU (SocketCAN)
│   │   └── ecu_data.{c,h}             simulated sensors and identifiers
│   └── tester/tester.c                diagnostic client (SocketCAN)
└── tests/
    ├── test_isotp.c
    ├── test_uds.c
    └── test_ecu_data.c
```

Only `ecu.c` and `tester.c` include Linux headers. Everything else is plain C over byte buffers.

## Setting up the virtual CAN bus

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Check it:

```bash
candump vcan0 &
cansend vcan0 123#1122334455667788
```

## Build

```bash
make          # build/ecu and build/tester
make test     # unit tests, built with ASan + UBSan
make clean
```

Builds with `-Wall -Wextra` and produces no warnings.

## Run

Terminal 1:

```bash
./build/ecu
```

Terminal 2:

```bash
./build/tester
```

Terminal 3 (optional, independent observer):

```bash
candump vcan0
```

### What the tester does

It runs a diagnostic session end to end — open an extended session, read identification and live data, then deliberately hit three rejection paths:

```text
=== Tester de diagnostic ===

[1] DiagnosticSessionControl -> Extended
  TX 7E0 : 02 10 03 00 00 00 00 00
  RX 7E8 : 06 50 03 00 32 01 F4 00
  -> OK     session active : Extended Diagnostic Session
            P2Server_max 50 ms, P2*Server_max 5000 ms

[2] ReadDataByIdentifier -> version logicielle
  TX 7E0 : 03 22 F1 89 00 00 00 00
  RX 7E8 : 06 62 F1 89 01 04 02 00
  -> OK     DID 0xF189 (ECU software version) = 01 04 02

[4] ReadDataByIdentifier -> regime moteur
  TX 7E0 : 03 22 01 00 00 00 00 00
  RX 7E8 : 05 62 01 00 05 44 00 00
  -> OK     DID 0x0100 (engine RPM) = 05 44  = 1348 tr/min

[6] ReadDataByIdentifier -> tension batterie
  RX 7E8 : 05 62 01 03 30 4E 00 00
  -> OK     DID 0x0103 (battery voltage) = 30 4E  = 12.366 V

[7] ReadDataByIdentifier -> VIN (17 octets : ne tient pas en Single Frame)
  TX 7E0 : 03 22 F1 90 00 00 00 00
  RX 7E8 : 03 7F 22 14 00 00 00 00
  -> REFUS  service 0x22, NRC 0x14 (responseTooLong)

[8] ReadDataByIdentifier -> identifiant inconnu
  RX 7E8 : 03 7F 22 31 00 00 00 00
  -> REFUS  service 0x22, NRC 0x31 (requestOutOfRange)

[9] Service inexistant 0x99
  RX 7E8 : 03 7F 99 11 00 00 00 00
  -> REFUS  service 0x99, NRC 0x11 (serviceNotSupported)
```

Reading the first exchange byte by byte:

```text
02        ISO-TP Single Frame, 2 bytes of payload
10 03     DiagnosticSessionControl -> extended session

06        ISO-TP Single Frame, 6 bytes of payload
50 03     positive response (0x10 + 0x40), extended session
00 32     P2Server_max  = 50 ms
01 F4     P2*Server_max = 500 x 10 ms = 5000 ms
```

### Injecting malformed traffic by hand

```bash
cansend vcan0 7E0#071003               # SF_DL says 7 bytes, DLC carries 2
cansend vcan0 7E0#0F1003               # SF_DL = 15, impossible
cansend vcan0 7E0#1008100300000000     # First Frame, not supported yet
cansend vcan0 7E0#0210420000000000     # unknown sub-function
cansend vcan0 7E0#0110000000000000     # 0x10 with no sub-function
cansend vcan0 7E0#0210830000000000     # suppressPosRspMsgIndicationBit
```

Observed on the bus:

```text
7E0  [3]  07 10 03   ->   (no response, ISO-TP rejects: truncated frame)
7E0  [3]  0F 10 03   ->   (no response, ISO-TP rejects: invalid length)
7E0  [8]  10 08 ...  ->   (no response, ISO-TP rejects: unsupported type)
7E0  [8]  02 10 42   ->   7E8  [8]  03 7F 10 12 ...   subFunctionNotSupported
7E0  [8]  01 10 00   ->   7E8  [8]  03 7F 10 13 ...   incorrectMessageLength
7E0  [8]  02 10 83   ->   (no response, as requested)
```

## Tests

```bash
make test
```

Both suites are compiled with AddressSanitizer and UndefinedBehaviorSanitizer.

**ISO-TP — 2480 checks.** The decoder is swept over all 256 possible PCI values crossed with all 9 possible frame lengths, and compared against a reference classifier written independently from the implementation so the oracle cannot inherit the same bug. Each frame is passed in a heap buffer allocated to the *exact* announced DLC, so any read past the end of the received data aborts the run under ASan. Also covers NULL arguments, encoder limits, padding and encode/decode round-trips.

**UDS — 64 checks.** Focused on rejection paths: every non-implemented SID, invalid sub-functions, wrong request lengths, the suppress-positive-response bit, NULL arguments and undersized response buffers. `0x22` is tested against an injected fake DID provider rather than the real ECU, which is what the callback decoupling buys.

**ECU data — 32 checks.** Determinism of the simulated values, big-endian encoding, sign preservation on negative temperatures, and a sweep of every identifier against every buffer capacity from 0 to 20 bytes to confirm nothing is ever written past the space provided.

Current result: **2576 checks, 0 failures, no sanitizer findings.**

### Fault injection

Malformed frames injected on the live bus with `cansend` — truncated ISO-TP frames, invalid `SF_DL`, unsupported frame types, unknown services, wrong lengths. The ECU process stayed alive throughout, emitted a response only where the protocol requires one, and logged an explicit reason for every rejection.

## Design constraints

- no dynamic allocation in the protocol layers — all buffers belong to the caller
- no global state; the UDS server carries an explicit context
- every public function returns an explicit status code
- fixed-width integer types, named constants instead of magic numbers
- bounded operations: a Single Frame payload is at most 7 bytes

## Current limitations

Stated explicitly rather than glossed over:

- ISO-TP: Single Frame only. No First Frame, Consecutive Frame or Flow Control, so messages are capped at 7 bytes of payload — which is why the VIN cannot be read yet.
- No ISO-TP timers — none of `N_As`, `N_Ar`, `N_Bs`, `N_Br`, `N_Cs`, `N_Cr` are implemented. The tester has a socket receive timeout, nothing more.
- UDS: two services (`0x10`, `0x22`). `0x22` accepts a single identifier per request, not the list the standard allows.
- Sessions are tracked but do not gate anything yet: no service is restricted to a session, and there is no session timeout or `TesterPresent`.
- No SecurityAccess, no DTCs.
- The ECU accepts requests on `0x7E0` without masking the CAN ID flag bits.
- Classic CAN only; CAN FD is out of scope for now.
- Not cross-validated against the Linux kernel ISO-TP implementation yet.

## Roadmap

| Next | Then | Later |
|---|---|---|
| ISO-TP First Frame + Flow Control | Session-based access rules | SecurityAccess (`0x27`) |
| Consecutive Frames + reassembly | `0x3E` TesterPresent + session timeout | Fault injector / fuzzer |
| Read the VIN in multiple frames | DTC model (`0x19`, `0x14`) | libFuzzer / AFL++ on the parsers |
| Sequence-error handling | Timeout abstraction | CI, static analysis, metrics |
| | Cross-validation vs Linux ISO-TP | CAN FD, STM32 + FreeRTOS port |

Multi-frame moves to the front because `0x22` just proved the need for it concretely: the VIN is unreadable until ISO-TP can span several frames.

## A note on standards

This is an ISO-TP implementation *targeting* ISO 15765-2 behavior and a UDS server implementing a *subset* of ISO 14229-1. Neither is a conformance-tested implementation, and no claim of full compliance is made. The protocol details here follow widely published descriptions of both standards; they have not been checked against the paid standard documents.

Likewise the code is written in a MISRA-oriented style — fixed-width types, no dynamic allocation, explicit error handling, short functions — but no MISRA conformance analysis has been run.

The stack is fuzz-tested and stress-tested against malformed traffic. That is evidence of robustness, not proof of correctness.
