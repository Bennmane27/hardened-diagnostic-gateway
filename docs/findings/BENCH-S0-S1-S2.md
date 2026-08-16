# Benchmark S0 / S1 / S2 — the gateway blocks what a stateless firewall cannot

| Field | Value |
|---|---|
| Instrument | `bench/bench.c` |
| Systems | S0 ECU-only · S1 stateless firewall + ECU · S2 AHDG gateway + ECU |
| Gateway | `src/gateway/gateway.c` — the hardened UDS server reused as an admission controller |
| Status | reproducible, CI-gated (`make bench`) |

## The setup

Three protections in front of the **same** permissive ECU, facing the **same**
attack corpus. The ECU is deliberately permissive on a real, common weakness: it
accepts `ECUReset` as soon as the session is extended, without requiring a
SecurityAccess unlock. Many production ECUs gate reset on the session alone.

The attack: `10 03` (extended session) then `11 01` (reset) — no unlock. It is
well-formed and uses only known service identifiers, so nothing about the bytes
distinguishes it from an authorized reset. Telling the two apart requires
knowing the security state, which only a stateful protection reconstructs.

- **S0** — ECU alone.
- **S1** — a stateless firewall (service-identifier allow-list) then the ECU.
  This is the strawman a non-stateful defense represents.
- **S2** — the AHDG gateway then the ECU. The gateway runs the hardened UDS
  server as a shadow, synchronized on the ECU by observing both directions, and
  forwards a request only if the hardened policy would accept it.

## Result (200,000 scenarios, two seeds)

| System | Unauthorized resets reaching the ECU | Legitimate flows served |
|---|---:|---:|
| S0 ECU only | 83,895 | 500 / 500 |
| S1 stateless firewall + ECU | 83,895 | — |
| **S2 AHDG gateway + ECU** | **0** | **500 / 500** |

Gateway admission latency: **~80 ns per request** (host, x86-64).

Second seed `0x1234`: S0 = S1 = 83,986, S2 = 0. The numbers move with the seed;
the conclusion does not.

## Reading it

- **Security.** The stateless firewall blocks exactly nothing the ECU-only
  baseline does not: an unauthorized reset and an authorized one are both known,
  well-formed services, and a filter without state cannot tell them apart. The
  gateway, which reconstructs the security state, blocks every one — 83,895 to 0.
- **Availability.** The gateway blocked no legitimate flow: 500 of 500 proper
  unlock-then-reset sequences were served, identical to the ECU alone. It is not
  a blunt "deny everything"; it denies exactly the unauthorized operation.
- **Cost.** ~80 ns per admission decision on the host. The STM32 figure is a
  separate milestone (M58), which is where the "low enough for embedded" claim
  is earned or lost.

## Honest scope

This demonstrates one attack class (unauthorized privileged operation on a
permissive ECU) against one stateless baseline, in a deterministic in-memory
harness. It is a clear, reproducible demonstration of the thesis — a stateful
cross-layer policy engine enforces what a stateless filter cannot, at negligible
cost — not a claim of coverage over all attacks or all baselines. The permissive
ECU is a model of a realistic weaker ECU, clearly labeled as such.

## Reproduce

```bash
make bench                 # 200k scenarios, seed 0xB0A7
./build/bench 200000 0x1234
```
