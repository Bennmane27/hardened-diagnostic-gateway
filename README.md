# Hardened Diagnostic Gateway

A hands-on embedded systems project focused on building a deterministic and robust automotive diagnostic stack from the ground up.

The project starts with a virtual CAN bus using Linux SocketCAN and `vcan`, then progressively adds:

- a custom CAN transport layer in C;
- an ISO-TP engine;
- a UDS diagnostic server/client;
- static-memory / zero-dynamic-allocation design;
- deterministic state machines and timeouts;
- fault injection and fuzzing;
- later, CAN FD and hardened security mechanisms.

## Current status

### Milestone 0 — Development environment ✅

Validated on Windows 11 using WSL + Ubuntu:

- WSL / Ubuntu installed;
- `can-utils` installed;
- `vcan0` virtual CAN interface created;
- CAN traffic verified with `cansend` and `candump`.

### Milestone 1 — First CAN frame from C ✅

A first C program sends an 8-byte CAN frame on arbitration ID `0x7E0` using SocketCAN.

Observed with `candump`:

```text
vcan0  7E0  [8]  11 22 33 44 55 66 77 88
```

## Target architecture

```text
Diagnostic Tester
       |
       | UDS
       v
    ISO-TP
       |
       v
   SocketCAN
       |
      vcan
       |
   SocketCAN
       v
    ISO-TP
       |
       v
  Virtual ECU
```

A fault-injection/fuzzing tool will later interact with the same virtual bus to test malformed frames, invalid sequence numbers, timeout handling, oversized payloads, unauthorized diagnostic requests, and recovery behavior.

## Development philosophy

The protocol layers will be kept independent from the Linux transport backend so they can later be ported to a microcontroller platform such as STM32 + FreeRTOS without rewriting the ISO-TP and UDS cores.

The project is intentionally built step by step, with each milestone documented and validated before the next layer is introduced.
