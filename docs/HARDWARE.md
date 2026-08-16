# Hardware bench — what to buy, why, and how (milestone M58)

The whole software stack runs today on a virtual bus. This document is the
recipe for the physical hardware-in-the-loop bench that turns "it works in
simulation" into "it runs on a real microcontroller between two real CAN buses,
with measured latency." That is the one part of the project that genuinely needs
you: I can write every line of the firmware — the protocol cores already compile
freestanding, proven by `make check-portability` — but flashing a board, wiring a
bus and reading a logic analyzer are physical acts.

## The picture

The gateway must sit **between** the attacker and the ECU, on **two separate
buses**. That is what makes it a gateway and not a sniffer.

```
   Attacker PC              Gateway board                 ECU board
  (tester/fuzzer)        (2 CAN controllers)          (1 CAN controller)
       │                    │          │                     │
   USB-CAN ── CAN bus A ── CAN1      CAN2 ── CAN bus B ── CAN
   (can0)     (untrusted)              (trusted)
       └─120Ω─┘                          └─120Ω─┘
```

The attacker (your existing `./build/tester` and `./build/fuzz_bus`, unchanged)
injects on bus A. The gateway reconstructs state and forwards to bus B only what
its policy admits. The ECU never sees a dropped frame.

## The kit — recommended (CAN FD ready)

Prices are rough EU street prices; you will find them on TME, Mouser, AliExpress,
Amazon.

| Item | Role | Why | ~Price |
|---|---|---|---:|
| **NUCLEO-G474RE** ×1 | the gateway | STM32G4 has **3× FDCAN** — one board mediates two buses with one to spare. Cheap, FD-capable, ST-Link built in. | 18 € |
| **NUCLEO-G431RB** ×1 | the ECU | 1× FDCAN, same family, same toolchain. (Or a second G474.) | 15 € |
| **CAN transceiver breakout** ×3 | logic ↔ bus | The STM32 outputs logic-level TX/RX; a transceiver drives the differential CAN_H/CAN_L. One per controller: 2 gateway + 1 ECU. Use **MCP2542FD** or **TCAN1042** for FD; SN65HVD230 for classic only. | 3 € ea |
| **CANable 2.0** ×1 | PC → bus | USB-CAN(FD) adapter that appears as **SocketCAN `can0`** on Linux — so your existing SocketCAN code targets it with a one-line change. | 30 € |
| Breadboard + jumpers + 2× **120 Ω** resistors | wiring + termination | A CAN bus must be terminated with 120 Ω at each end. | 10 € |
| **8-ch USB logic analyzer** (sigrok) ×1 (optional) | wire-level timing | Toggle a GPIO on "frame in" / "frame out" and read end-to-end latency in PulseView. | 12 € |

**Total: ~90–100 €** for a complete, CAN-FD-capable bench.

### Cheaper classic-CAN-only variant (~50 €)

- NUCLEO-F446RE (2× bxCAN) as gateway — 15 €
- STM32F103 "Blue Pill" (1× CAN) as ECU — 5 €
- 3× MCP2551 / TJA1050 modules — 6 €
- Any SLCAN USB-CAN — 12 €
- wires + 120 Ω — 10 €

### Absolute minimum (~50 €, one board)

One **NUCLEO-G474RE** can be *both* the ECU and the gateway: run the ECU on
FDCAN1 and the gateway on FDCAN2/FDCAN3, bridged in firmware. Add a CANable for
the attacker. Less clean, but it proves the concept on real silicon.

## The toolchain (free software you install)

```bash
sudo apt install gcc-arm-none-eabi        # the compiler
# STM32CubeProgrammer, or:
sudo apt install stlink-tools              # st-flash over the Nucleo's USB
# you already have can-utils (slcand, candump)
```

The Nucleo's on-board **ST-Link** means flashing is just USB — no separate
programmer.

## What you do with it, step by step

1. **Flash the ECU.** `st-flash write ecu.bin 0x8000000` to the ECU board. It
   runs the port of `uds` + `isotp` + `ecu_data` over FDCAN. (I write this
   firmware; the cores are already portable.)
2. **Flash the gateway.** Same, to the gateway board — the port of
   `gateway.c` + the ISO-TP shadow over two FDCAN peripherals.
3. **Wire it.** Attacker CANable ↔ bus A ↔ gateway CAN1 transceiver; gateway
   CAN2 transceiver ↔ bus B ↔ ECU transceiver. A 120 Ω resistor across CAN_H/
   CAN_L at each bus end.
4. **Bring up the PC side.**
   ```bash
   sudo slcand -o -c -s6 /dev/ttyACM0 can0 && sudo ip link set up can0
   candump can0        # you now watch the REAL bus
   ```
   Your `tester`/`fuzz_bus` change one line — `vcan0` → `can0` — and run against
   physical hardware.
5. **Run the experiment.**
   - *Without the gateway* (attacker wired straight to the ECU): the unauthorized
     reset lands — the ECU board resets (watch an LED / a DTC).
   - *With the gateway*: the same attack is dropped; the ECU LED never blinks;
     a legitimate unlock-then-reset still works.
6. **Measure latency, honestly.**
   - In-firmware: the Cortex-M **DWT cycle counter** around the admission
     decision → nanoseconds, no extra hardware.
   - Wire-level: toggle a GPIO high on "frame received on bus A", low on "frame
     emitted on bus B"; the logic analyzer reads the gateway's added delay.

## The division of labour

| I can do | You must do |
|---|---|
| Write the FDCAN backend and both firmwares (ECU, gateway) | Buy the boards, flash them (USB), wire the buses |
| Keep `isotp`/`uds`/`gateway` byte-identical to the host build | Read the LED / logic-analyzer / DWT numbers |
| Adapt `tester`/`fuzz_bus` from `vcan0` to `can0` | Run the campaign on the physical bench |

Nothing above needs a vehicle. **Never attack a real vehicle or third-party
equipment** — this is a self-contained lab bench you own, which is exactly what
makes the offensive testing legitimate.

## Where this fits

This is milestone **M58**. It is what earns the "runs on embedded hardware with
measured latency" clause of the eventual scoped claim (see `NOVELTY.md`). Until
the boards exist and the numbers are read, that clause stays unproven — and I
will not write it.
