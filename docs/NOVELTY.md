# Novelty ledger and prior-art protocol

This file is the mechanism that turns "probably new" into a claim that survives
review. It is a hard gate: **no novelty wording stronger than Tier A appears
anywhere public — README, LinkedIn, CV, paper — until this ledger is complete
and its search is recorded here.**

The reasoning is the project's, stated once so it is not re-litigated: proving
"first in the world" is impossible, because confidential industrial prototypes
cannot be disproven. The defensible, and scientifically stronger, form is a
*scoped* claim tied to a documented search — "to the best of our knowledge, the
first open, evaluated system that ...". This document is that search.

---

## The claim, decomposed

The full claim is only made if **every** clause below survives the search. Each
is checked independently; a clause already covered by published, open, evaluated
work is struck, and the claim narrows to what remains.

| # | Clause | Status |
|---|--------|--------|
| C1 | invariant-based enforcement (not signature/rate-based) | open |
| C2 | stateful, spanning CAN → ISO-TP → UDS → SecurityAccess | open |
| C3 | enforcement **before** the ECU (in-line gateway, not monitor) | open |
| C4 | cross-layer invariants (transport anomaly ⇏ application authority) | open |
| C5 | adversarial fuzzer exploring the **combined** state machine | open |
| C6 | automatic minimized, replayable counterexamples | open |
| C7 | post-violation resynchronization preserving availability | open |
| C8 | S0/S1/S2 benchmark on an identical adversarial corpus | open |
| C9 | validated on physical hardware with measured latency | open |
| C10 | fully open source and one-command reproducible | open |

The distinctive conjunction is **C2 ∧ C3 ∧ C4 ∧ C5 ∧ C7** — the others exist
individually in the literature. The search must focus there.

---

## Search protocol (milestone M60)

Run the search, record every hit, fill the tables, then decide. Do not skip a
venue because a term "feels" absent.

### Venues

- Security: USENIX Security, IEEE S&P, ACM CCS, NDSS, ACSAC, DIMVA, RAID.
- Automotive: ESCAR (EU/USA/Asia), SAE WCX, SAE journals, IEEE VTC, escar
  proceedings.
- Standards & industry: AUTOSAR (Classic + Adaptive specs), ISO 15765-2,
  ISO 14229, UNECE R155/R156, Vector / ETAS / Bosch white papers.
- Preprints & databases: arXiv (cs.CR, eess.SY), IEEE Xplore, ACM DL,
  Semantic Scholar, Google Scholar.
- Patents: Google Patents, Espacenet, USPTO — assignees to check explicitly:
  Bosch, Continental, Vector, ETAS, Denso, Toyota, BMW, Mercedes, VW, Argus,
  Karamba, Aptiv.
- Open source: GitHub / GitLab search for ISO-TP + UDS + fuzzer + gateway
  combinations; caring/can-isotp, python-uds, uds-server, scapy-automotive,
  gallia (Fraunhofer AISEC), and any stateful-fuzzing automotive tool.

### Search strings (seed set, extend as hits appear)

```
automotive diagnostic firewall invariant
UDS SecurityAccess stateful enforcement gateway
ISO-TP cross-layer verification runtime
CAN transport protocol denial of service reassembly
stateful fuzzing UDS state machine counterexample
diagnostic gateway resynchronization recovery attack
in-vehicle intrusion prevention ISO 14229 stateful
```

### For each relevant hit, record

| Work | Venue / year | Which clauses it covers | Open? | Evaluated? | Hardware? | Notes |
|------|--------------|-------------------------|-------|-----------|-----------|-------|

(table filled during M60; leads to verify first are the three in `RESEARCH.md`
§1 — AUTOSAR Firewall spec, arXiv 2510.25375, arXiv 2604.23617. None verified
yet.)

### Decision rule

- If no single open, evaluated work covers **C2 ∧ C3 ∧ C4 ∧ C5 ∧ C7**, the
  scoped claim (Tier C) is defensible over that conjunction.
- If a work covers part, narrow the claim to the uncovered remainder and record
  exactly what was ceded.
- If a work covers all of it, the claim is dropped; the project remains an
  excellent open reference implementation, and the write-up says so plainly.

The outcome is written here, dated, with the search date and the databases as of
that date — because "to our knowledge" is a statement about a moment, and an
honest one names the moment.

---

## Naming — the three tiers

The wording used in public is set by the evidence available, never by ambition.

### Tier A — always permitted (descriptive, no novelty)

Usable as soon as the system works, from M53 onward:

> An open-source, invariant-based, stateful cross-layer (CAN / ISO-TP / UDS /
> SecurityAccess) automotive diagnostic security gateway, co-designed with an
> adversarial state-space fuzzer and evaluated against ECU-only and
> stateless-firewall baselines.

No "first," no superlative. Simply true.

### Tier B — after internal evidence + a documented but partial search

Usable once the recognition checklist in `RESEARCH.md` §10 is complete **and** a
first search pass is recorded here, even if not exhaustive:

> To our knowledge, the first open-source system to combine cross-layer
> ISO-TP/UDS invariant enforcement with automatic adversarial discovery of the
> violating sequences.

Hedged, scoped, honest about being non-exhaustive.

### Tier C — only after this ledger is complete and reviewed (M60)

The full scoped claim from `RESEARCH.md` §1, stated as "to the best of our
knowledge," with the search date. This is the strongest form the project will
ever use.

### Never permitted

"World first." "Never conceived before." "Unbreakable." "Mathematically
proven." "Production-ready." "100% ISO/MISRA compliant." These are indefensible
and a reviewer discards the whole work on sight of one. The project's credibility
is the asset; a single overclaim spends it.

---

## Status

Ledger opened. All ten clauses open. Prior-art review is milestone M60 and has
not started. Current permissible tier: **A** (once the gateway is built).
