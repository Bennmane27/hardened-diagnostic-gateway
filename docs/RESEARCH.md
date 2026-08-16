# Research brief — AHDG

**Autonomous Hardened Diagnostic Guardian** — an autonomous cross-layer
automotive diagnostic security gateway.

> This document is the complete brief for the research-grade phase of the
> project. It defines the contribution precisely, the architecture, the
> invariant model that is the intellectual core, the adversarial evaluation, the
> experimental protocol, and — at the end — the exact conditions under which the
> system earns its designation and how that designation must be worded.
>
> It is written to be executed. Each section maps to milestones (M50+ in
> [../ROADMAP.md](../ROADMAP.md)). The novelty discipline lives in
> [NOVELTY.md](NOVELTY.md) and gates the final naming.

---

## 0. What changes, in one paragraph

Today the project is a correct, well-tested diagnostic stack: an ECU answers, a
tester asks, ISO-TP and UDS behave, malformed traffic is rejected. That is an
**excellent engineering project and nothing more** — comparable systems exist.
The research phase turns it into something else: a **gateway that sits between
the attacker and the ECU, holds a shadow model of the ISO-TP / UDS /
SecurityAccess state, enforces cross-layer invariants in real time before the
ECU sees anything, and is co-designed with an adversarial fuzzer that
automatically discovers, minimizes and reproduces the sequences that violate
those invariants — then blocks them, recovers a coherent state, and keeps the
diagnostic service available.** The contribution is not the amount of code. It
is a falsifiable, reproducible experiment: *here is a class of attacks the
reference mechanisms do not stop; here is why; here is our mechanism; here are a
million adversarial sequences; here are the numbers, on host and on hardware.*

---

## 1. The honest novelty position

We do **not** claim "first in the world / never conceived before." That is
undemonstrable: confidential industrial prototypes cannot be ruled out, and no
review can prove their absence.

We claim, and only after the prior-art review in [NOVELTY.md](NOVELTY.md)
concludes, the scoped form:

> **To the best of our knowledge, the first open-source, experimentally
> evaluated system combining invariant-based stateful cross-layer
> (CAN / ISO-TP / UDS / SecurityAccess) enforcement, automatic adversarial
> exploration of the combined state machine, minimized reproducible
> counterexamples, and post-violation resynchronization — benchmarked against
> ECU-only and stateless-firewall baselines on identical adversarial corpora,
> including on physical hardware.**

Everything in that sentence is a load-bearing qualifier. Each clause must be
individually true and individually checked against prior art. If any clause is
already covered by a published, open, evaluated system, the claim is narrowed or
dropped. This is stronger than a superlative, because it is falsifiable and it
survives scrutiny.

### State of the art — user-supplied leads, to be verified

The following were provided as starting points. **They are unverified** and must
be confirmed independently during the prior-art milestone before any of them is
cited as fact:

- AUTOSAR Adaptive Platform — *Specification of Firewall* (a firewall is
  specified, but not an invariant-based dynamic CAN→ISO-TP→UDS verifier attacked
  by its own fuzzer).
- *From ECU to VSOC: UDS Security Monitoring Strategies* (arXiv 2510.25375) —
  monitoring strategies; notes gaps in standardized security events.
- *The Vehicle May Be Sick: Denial of Diagnostic Services by Exploiting the CAN
  Transport Protocol* (arXiv id as given: 2604.23617) — claims eight ISO-TP
  attack scenarios derived from ISO 15765-2, three causing diagnostic DoS on a
  real vehicle.

The working hypothesis is that existing work covers **pieces** — a firewall
spec, stateful fuzzing, UDS monitoring, ISO-TP attacks — but not the whole chain
as one evaluated system. The prior-art review exists to confirm or refute that,
rigorously, before we name anything.

---

## 2. Architecture

```
                 ┌────────────────────────┐
                 │  ADVERSARIAL STATE      │
                 │  FUZZER  (offline)      │
                 └───────────┬─────────────┘
                             │ discovers, minimizes, records
                             ▼
   Tester / Attacker ──CAN──► HARDENED GATEWAY ──CAN──► ECU
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                 ▼
        ISO-TP shadow    UDS shadow      SecurityAccess
          state            state            shadow state
              └───────────────┼────────────────┘
                              ▼
                       COMBINED STATE  (one epoch)
                              │
                      INVARIANT ENGINE   (src/gateway/invariants.h)
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
              ALLOW         DROP         RECOVER
             forward       discard    resynchronize
              frame        frame       both sides
```

The gateway is **transparent** on the nominal path (ALLOW adds bounded latency
and nothing else) and **active** only when an invariant is at risk. It never
originates diagnostics; it observes, models, decides.

Reuse: the shadow ISO-TP and UDS models are the *same* portable code already in
`src/isotp/` and `src/uds/`, run in a passive "observe" mode. That is the payoff
of the no-system-header discipline (invariant I1): the protocol logic can be
instantiated a second time, inside the gateway, watching rather than answering.

Layout to add:

```
src/gateway/
├── invariants.h        catalogue of invariant IDs and severities (done, M50)
├── shadow.{c,h}        passive ISO-TP + UDS state tracking
├── engine.{c,h}        invariant evaluation, ALLOW / DROP / RECOVER
└── gateway_main.c      the in-line CAN gateway process
fuzz/
└── fuzz_state.c        adversarial state-space explorer + minimizer
bench/
└── harness.{c,py}      S0 / S1 / S2 comparison on a frozen corpus
```

---

## 3. The invariant model — the intellectual core

State observed by the gateway, per address pair:

- **ISO-TP**: RX state, TX state, expected/received length, next sequence
  number, N_Cr / N_Bs deadlines.
- **UDS**: session, security level, seed-pending flag, S3 deadline, failed-key
  count, lockout deadline.
- **Epoch**: a counter bumped on every ECUReset and power cycle; binds authority
  to a lifetime.

The invariants are catalogued as code in
[../src/gateway/invariants.h](../src/gateway/invariants.h). Summary:

**SEC — authority**
- `SEC_NO_UNAUTH_EFFECT`: no security-gated service takes positive effect while
  `security == LOCKED`.
- `SEC_SEED_KEY_BINDING`: a key is accepted only against an outstanding,
  unconsumed seed issued in the current epoch and session.
- `SEC_RELOCK_ON_RESET`: security is `LOCKED` after any ECUReset.
- `SEC_RELOCK_ON_DEFAULT`: security is `LOCKED` after any transition to the
  default session (explicit or S3 timeout).
- `SEC_MONOTONIC_ATTEMPTS`: the failed-key counter is never cleared by a
  transport event — only by a real unlock or a lockout expiry.

**XL — cross-layer (the contribution)**
- `XL_TRANSPORT_CANNOT_FORGE_AUTHORITY`: no ISO-TP anomaly (sequence error,
  interleave, overflow, timeout) may cause the UDS layer to act on anything but
  a complete, in-order reassembly of a single transfer.
- `XL_NO_AUTHORITY_CARRYOVER`: a transport abort must not leave UDS authority
  higher than a clean re-initialization would.
- `XL_EPOCH_CONSISTENCY`: the gateway's shadow and the ECU share one epoch; a
  window where they disagree on session or security is itself a violation.
- `XL_SINGLE_WRITER`: at most one in-flight transfer per address pair reaches
  the UDS layer; interleaved First Frames cannot both deliver.

**TP — transport integrity**
- `TP_LENGTH_HONESTY`, `TP_SEQUENCE_MONOTONIC`, `TP_BOUNDED_BUFFER`.

**TIME**
- `TIME_DEADLINE_CONSISTENCY`, `TIME_NO_STALE_RESUME`.

**AVAIL — availability (what a DoS attacker targets)**
- `AVAIL_RECOVERABLE`: after any single blocked attack, a well-formed session
  succeeds within a bounded time.
- `AVAIL_NO_WEDGED_CONTEXT`: no sequence leaves the ECU unable to serve — the
  exact DoS class the 2026 ISO-TP work reports.

The `XL_*` group is where the novelty concentrates: invariants that **span**
transport and application layers, which neither a transport parser nor a UDS
monitor can express alone.

---

## 4. Enforcement semantics

Three verdicts per frame:

- **ALLOW** — forward unchanged. The nominal path. Must be O(1) and add bounded
  latency (target measured, not assumed).
- **DROP** — discard the frame; the ECU never sees it. Used when forwarding
  would risk a violation but the context is still recoverable by ignoring.
- **RECOVER** — resynchronize. The gateway resets its own shadow reassembly and,
  when needed, drives both sides back to a known state (e.g. forces its shadow
  security to LOCKED, optionally emits a benign session reset toward the ECU) so
  that `AVAIL_RECOVERABLE` holds. This is the difference between a firewall that
  blocks and a gateway that *keeps the vehicle diagnosable*.

Every verdict is logged with the invariant ID, the observed vs expected state,
and the triggering frame, so a violation is not just stopped but **explained**.

---

## 4quater. The live gateway (M53 + M54)

`src/gateway/gateway_main.c` is the in-line mediator: external bus (tester) on one
side, trusted bus (ECU) on the other. It reassembles each request, asks the
hardened policy (`gw_admit`) whether it may reach the ECU, and forwards only what
is admitted; on a drop it returns the hardened negative response to the tester
itself (recovery) while the ECU's bus never carries the frame. `make gwdemo`
demonstrates it over vcan0/vcan1: an unauthorized ECUReset is dropped and is
provably absent from the trusted-bus capture, while a legitimate unlock-then-reset
passes intact. Enforcement before the ECU, on real (virtual) buses.

## 4ter. Benchmark result (S0/S1/S2)

`bench/bench.c` puts three protections in front of the same permissive ECU on the
same attack corpus. A stateless firewall lets through every one of ~84,000
unauthorized resets (they are well-formed, known services); the AHDG gateway
(`src/gateway/gateway.c`, the hardened UDS server reused as an admission
controller) blocks all of them and blocks no legitimate flow (500/500), at ~80 ns
per request. This is milestones M52 (enforcement) and M57 (benchmark). See
[findings/BENCH-S0-S1-S2.md](findings/BENCH-S0-S1-S2.md). Remaining: RECOVER
(M54), the live two-bus mediator (M53), and the STM32 latency (M58).

## 4bis. First experimental support (frame level)

`fuzz/ahdg_frames.c` already drives the real `isotp_rx + uds` pipeline with
adversarial CAN frames and checks the SEC, XL and AVAIL invariants after each
sequence, with a golden probe verifying the ECU stays serviceable. Over 21
million frames on two seeds it found no transport-forged authority and no denial
of diagnostic — bounded assurance for the XL/AVAIL claims, re-checked in CI. See
[findings/AHDG-0002.md](findings/AHDG-0002.md). This is the reconstruction half
of M51 and the frame-level half of M55; the remaining work is the in-line gateway
that mediates and enforces before the ECU (M52-M53).

## 5. The adversarial state-space fuzzer

Not the byte fuzzer already in `fuzz/fuzz_parser.c` — that finds parser
overflows. This one explores the **combined state machine** looking for a
sequence of well-formed-enough frames that drives the ECU to violate an
invariant.

- **Search**: guided over the state space (session × security × ISO-TP phase ×
  epoch), rewarding transitions into rarely-seen combined states, seeded and
  reproducible.
- **Oracle**: the invariant engine, run against the *unprotected* ECU. A
  sequence is a counterexample if it makes the ECU reach a state violating any
  invariant.
- **Minimization**: delta-debugging — remove frames while the violation
  persists — until a minimal reproducer remains. A 40-frame discovery becomes a
  4-frame proof.
- **Recording**: every counterexample is frozen as a reproducer (seed + minimal
  frame list) under `bench/corpus/`, versioned, replayable frame-for-frame.

Success condition: the fuzzer finds at least one violation sequence **that was
not written by hand** — a genuine discovery, not a replay of a known scenario.

---

## 6. Experimental protocol (pre-registered)

State the predictions **before** running, so the result can falsify them.

**Systems under test**
- **S0** — ECU alone (today's system).
- **S1** — naive stateless firewall: CAN-ID allow-list + rate limit. The
  strawman that a non-stateful defense represents.
- **S2** — the Hardened Gateway.

**Corpus** — frozen union of hand-written scenarios and fuzzer-discovered,
minimized counterexamples. Identical across S0/S1/S2. Seeded.

**Metrics**
- **Security**: fraction of invariant-violating outcomes that reach the ECU.
  Prediction: S0 high, S1 partial, S2 ≈ 0.
- **Availability**: after the corpus, does a golden diagnostic session succeed,
  and in what time? Prediction: S0/S1 can be left wedged; S2 recovers within a
  bounded delay.
- **Performance**: added per-frame latency (median and worst case), on host and
  on STM32. Prediction: S2 median added latency below a stated threshold.

A result where S2 does **not** clearly beat S1 on some class is reported as-is.
The experiment is the contribution, not a foregone conclusion.

---

## 7. Hardware validation

Host results are necessary but not sufficient; the DoS-relevance argument needs
real timing. Target: STM32 with FDCAN, gateway on one node, ECU and
tester/attacker on others (or loopback). Latency measured with the DWT cycle
counter and, if available, a GPIO toggle on a logic analyzer. This is where the
"low enough to run on embedded hardware" clause of the claim is earned or lost.

The port reuses `src/isotp/` and `src/uds/` unchanged — the freestanding
compilation already proven by `make check-portability` is the evidence that this
is realistic, not aspirational.

---

## 8. Reproducibility and artifact standard

The claim is only as strong as its reproducibility.

- Every figure regenerated by one command from committed corpora and seeds.
- Fuzzers and simulated data are deterministic (already true today).
- Counterexamples stored as minimal reproducers, not prose.
- CI runs the whole benchmark on every push; a regression in blocked-attack
  count fails the build.
- A single `bench/run.sh` produces the S0/S1/S2 tables verbatim as they appear
  in any write-up.

---

## 9. Milestone map

See [../ROADMAP.md](../ROADMAP.md) for the tracked list. In brief:

```
M50  invariants.h — the catalogue as code                        [done]
M51  gateway shadow state: passive ISO-TP + UDS tracking
M52  invariant engine: evaluate, verdict ALLOW/DROP/RECOVER
M53  in-line CAN gateway process, transparent on the nominal path
M54  RECOVER: post-violation resynchronization, AVAIL restored
M55  adversarial state-space fuzzer + delta-debug minimizer
M56  frozen counterexample corpus + replay
M57  benchmark harness S0 / S1 / S2, host
M58  STM32 + FDCAN port, latency measurement
M59  full artifact + one-command reproduction + CI gate
M60  prior-art review (NOVELTY.md) — hard gate on the claim
M61  write-up: threat model, invariants, discovery, results
```

---

## 10. The designation — how this is named at the end

The project earns its name only when **every** box below is ticked. Until then
the strongest permissible wording is descriptive, not superlative.

### Recognition checklist

- [ ] Cross-layer invariants enforced in real time before the ECU (M52–M53).
- [ ] Post-violation recovery keeps the ECU diagnosable (M54, `AVAIL_*`).
- [ ] The fuzzer discovers a violation sequence **not written by hand** (M55).
- [ ] That sequence is automatically minimized and replays exactly (M55–M56).
- [ ] Benchmark shows a class where S0/S1 fail and S2 does not (M57).
- [ ] Latency measured on real hardware, within the stated bound (M58).
- [ ] One-command reproduction of every figure (M59).
- [ ] Prior-art ledger complete and reviewed, claim frozen (M60,
      [NOVELTY.md](NOVELTY.md)).

### The target sentence — an objective, not a claim

The finish line, to be earned only when the recognition checklist below is
complete and the prior-art review (M60) has concluded:

> To the best of our knowledge, and after a systematic review of the public
> state of the art, we designed and experimentally validated the first
> published architecture combining cross-layer diagnostic state reconstruction,
> real-time invariant enforcement, stateful adversarial exploration, automatic
> discovery and minimization of counterexamples, and protocol-aware recovery on
> an embedded automotive gateway operating over CAN / ISO-TP / UDS.

If that sentence cannot yet be written truthfully, the mission is not done: find
which clause is already covered, and build the missing capability. It is never
weakened to "win."

### The name, once earned

When and only when the checklist is complete, the system is designated:

> **HDG — the first open, invariant-based, stateful cross-layer automotive
> diagnostic security gateway with adversarial state-space co-design, to the
> best of our knowledge and pending the antecedence review recorded in
> NOVELTY.md.**

Three tiers govern how it may be described, and the tier is set by the
evidence, never by ambition — see [NOVELTY.md](NOVELTY.md) §Naming. The bare
phrases "world first," "never done before," "unbreakable" and "mathematically
proven" are **never** used, in keeping with the project's standing honesty
discipline (`PROJECT_MEMORY.md` §6). The scoped claim is stronger precisely
because it is true.
