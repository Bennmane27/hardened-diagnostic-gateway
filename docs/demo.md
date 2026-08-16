# Demonstration script

A reproducible walk-through, meant to be run in front of someone or recorded.
Roughly four minutes.

Every run produces the same values: the simulated ECU evolves from a tick
counter and the fuzzers take explicit seeds, so nothing here depends on luck.

## Setup

Once per boot:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Build:

```bash
make && make test
```

Expected: `14733 verifications, 0 echec(s)` across four suites, all compiled
with AddressSanitizer and UndefinedBehaviorSanitizer.

## Act 1 — It works

Terminal 1:

```bash
./build/ecu
```

Terminal 2:

```bash
./build/tester
```

Terminal 3, the independent witness:

```bash
candump vcan0
```

The tester walks 19 steps. The ones worth pausing on:

**Step 3** — the session opens, and the ECU returns its timing parameters:

```
  RX 7E8 : 06 50 03 00 32 01 F4 00
  -> OK     session active : Extended Diagnostic Session
            P2Server_max 50 ms, P2*Server_max 5000 ms
```

**Step 6** — the VIN. Seventeen bytes do not fit in a CAN frame, so `candump`
shows the transport doing its job:

```
7E0  03 22 F1 90 ...          request
7E8  10 14 62 F1 90 56 46 31  First Frame, 0x014 = 20 bytes announced
7E0  30 00 00 ...             Flow Control, ContinueToSend
7E8  21 48 44 47 32 41 58 34  Consecutive Frame, sequence 1
7E8  22 37 31 32 39 33 30 35  Consecutive Frame, sequence 2
```

```
  -> OK     DID 0xF190 (VIN) = ... "VF1HDG2AX47129305"
```

**Step 7** — the fault memory:

```
  -> OK     3 code(s) defaut
            011700  statut 09  capteur de temperature moteur
            C12345  statut 08  defaut de communication reseau
            016200  statut 09  sous-tension batterie
```

The third one was not there at startup. The ECU raised it on its own when the
simulated battery voltage dropped below its threshold.

## Act 2 — It refuses

**Step 2** — `ECUReset` from the default session, before anything is open:

```
  -> REFUS  service 0x11, NRC 0x7F (serviceNotSupportedInActiveSession)
```

**Step 8** — the same command, now in the extended session but still locked.
The refusal code *changes*, which is the interesting part: the session check
passed and the security check took over.

```
  -> REFUS  service 0x11, NRC 0x33 (securityAccessDenied)
```

## Act 3 — Authentication

**Steps 9 to 12** — seed, wrong key, new seed, correct key:

```
[9]  SecurityAccess -> demande de graine
  -> OK     graine recue : E912E607

[10] SecurityAccess -> cle fausse
  -> REFUS  service 0x27, NRC 0x35 (invalidKey)

[11] SecurityAccess -> nouvelle graine
  -> OK     graine recue : 9610E388
```

Two things to point out here. The seed is different — a fixed seed would make
the whole exchange a static password. And a new seed had to be requested at all:
the first failure consumed the old one, so the key space cannot be swept against
a frozen challenge.

```
[12] SecurityAccess -> cle correcte
  -> OK     ACCES DEVERROUILLE
```

**Step 13** — the same valid key, replayed immediately:

```
  -> REFUS  service 0x27, NRC 0x22 (conditionsNotCorrect)
```

No seed is pending, so a recorded key is worthless.

> Say out loud that the key derivation is a demonstration and protects nothing —
> the algorithm is public in this repository. What is being demonstrated is the
> state handling around it. See [security.md](security.md).

**Steps 14 to 16** — operations that are now permitted: clear the faults, read
them back empty, reset the ECU.

**Step 17** — `ECUReset` again, right after the reset:

```
  -> REFUS  service 0x11, NRC 0x7F (serviceNotSupportedInActiveSession)
```

The reset re-locked everything. No access survived it.

## Act 4 — It survives

Terminal 2:

```bash
./build/fuzz_bus 200 0xBADC0DE
```

Eleven targeted scenarios — wrong sequence numbers, missing consecutive frames,
4 GB length announcements, orphan frames, interleaved transfers, keys with no
seed, resets with no unlock, random bursts.

Watch terminal 1: the ECU narrates every rejection with a reason.

```
     200 attaques ... ECU toujours operationnel

  attaques jouees        : 200
  trames emises          : 950
  sondes de vitalite     : 10
  sondes reussies        : 10
  sondes echouees        : 0
  ECUReset non autorises : 0
```

The line that matters is `sondes reussies : 10`. Every 25 attacks the fuzzer
stops and sends a perfectly valid request, requiring the exact expected reply.
Rejecting an attack proves nothing if the context stays broken afterwards.

Stop the ECU with Ctrl-C and it prints its own tally:

```
--- Statistiques ISO-TP ---
  trames recues        : ...
  trames rejetees      : ...
  erreurs de sequence  : ...
  debordements         : ...
  delais expires       : ...
```

## Act 5 — At scale

```bash
./build/fuzz_parser 2000000 0x5EED1
```

Roughly a minute, in memory, under sanitizers:

```
  cas joues              : 2000000
  trames ISO-TP          : 12994183
  erreurs de sequence    : 988290
  debordements refuses   : 268
  delais expires         : 181926
  reponses negatives     : 1933973

  ANOMALIES              : 0
```

An anomaly is not "something was rejected" — rejection is the expected outcome
for most of these. It is a violated invariant: a context in an unknown state,
more bytes accumulated than announced, a positive response to a service that
was not requested, or `ECUReset` accepted while locked.

Finish with:

```bash
make check-portability
```

```
== I1 : aucun header systeme dans les couches protocole ==   OK
== I2 : aucune allocation dynamique dans src/ ==             OK
== I1bis : les couches protocole compilent hors Linux ==     OK
== I1ter : couches protocole sous -Wconversion et -Wshadow == OK
== I2bis : aucun symbole d'allocation dans les binaires ==   OK
```

## What to say about it

Honest framing, which is also the more convincing one:

> An ISO-TP implementation targeting ISO 15765-2 behavior, and a UDS server
> implementing a subset of ISO 14229-1. Fuzz-tested and stress-tested against
> malformed traffic, with bounded memory and deterministic failure handling.

Do not say "ISO compliant", "MISRA compliant", "production-ready" or
"mathematically proven". None of it has been demonstrated, and a technical
interviewer spots the overclaim immediately. The measured numbers are strong
enough on their own — see [results.md](results.md).

## If something goes wrong

**No response at all.** Check `vcan0` exists (`ip link show vcan0`) and that
exactly one ECU is running (`pgrep -a ecu`). Two ECUs answering the same
requests produce interleaved, confusing traces.

**The fuzzer refuses to start.** It probes the ECU before attacking anything;
if that first probe fails it stops rather than reporting a meaningless campaign.
Start `./build/ecu` first.

**Stale binaries.** `make clean && make`.
