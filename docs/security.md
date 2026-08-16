# SecurityAccess

> **The key derivation in this repository is a demonstration. It protects
> nothing.** The algorithm is published here in full, so anyone reading this
> file can compute a valid key. It exists to show the *mechanics* of the
> seed/key exchange and the state handling around it — never to secure
> anything. Read [Replacing the demo algorithm](#replacing-the-demo-algorithm)
> before drawing any conclusion about the design.

## What the service is for

Some diagnostic operations can damage a vehicle or defeat a safety function:
reprogramming, clearing protections, forcing actuators. UDS gates them behind
`0x27` SecurityAccess, a challenge-response exchange that proves the tester
holds a secret without ever transmitting that secret.

```
   Tester                                   ECU
     │                                       │
     │  27 01            request seed        │
     ├──────────────────────────────────────►│
     │                                       │  draws a seed
     │  67 01 <seed:4>                       │
     │◄──────────────────────────────────────┤
     │                                       │
     │  computes key = f(seed, secret)       │
     │                                       │
     │  27 02 <key:4>                        │
     ├──────────────────────────────────────►│
     │                                       │  recomputes and compares
     │  67 02            unlocked            │
     │◄──────────────────────────────────────┤
```

The secret never crosses the bus. An attacker recording the exchange sees a
seed and a key, but a different seed next time makes the recorded key useless —
provided the implementation actually behaves that way, which is where most of
the real work is.

## What is implemented

`0x27` requires the extended session, so the exchange cannot even begin from
the default session.

### A fresh seed per request

Every `27 01` draws a new seed. Two consecutive requests return different
values, and there is a test asserting it. A fixed seed would turn the whole
mechanism into a static password.

### The seed is consumed by the first wrong key

A failed `27 02` clears the pending seed. The attacker must request a new one
before trying again, which prevents sweeping the key space against a frozen
challenge. Without this, three attempts per lockout would be meaningless —
an attacker would simply try 2³² keys against one seed.

### Replay is refused

A key arriving with no seed pending is `conditionsNotCorrect` (`0x22`). That
covers both the out-of-sequence case and the recorded-key replay: after a
successful unlock, sending the same key again fails, because the seed that
justified it is gone.

### Lockout after repeated failures

Three consecutive wrong keys lock the server for ten seconds. During the
lockout, **seed requests are refused too** (`requiredTimeDelayNotExpired`,
`0x37`), not just key submissions. Refusing only the keys would let an attacker
restart a fresh cycle immediately and make the counter pointless.

The lockout lifts on its own once the delay elapses.

### Unlocking does not survive a session change

`S3server` expiry, an explicit return to the default session, and a successful
`ECUReset` all re-lock security. An access granted once must not outlive the
context that justified it.

### Requesting a seed while already unlocked

Returns a zero seed, signalling "nothing to do" rather than starting a pointless
exchange.

## The demo algorithm

```c
uint32_t uds_demo_key_from_seed(uint32_t seed)
{
    uint32_t k = seed ^ 0xA5A5A5A5u;
    k = (k << 3) | (k >> 29);      /* rotate left by 3 */
    k = k + 0x3C3C3C3Cu;
    return k;
}
```

XOR with a constant, rotate, add a constant. It is deterministic, it is fast,
and it is **worthless as protection** — it has no secret input, and it is
printed above.

It is kept deliberately simple and deliberately visible. A slightly more
elaborate obfuscation would have been worse: it would look like security
without being any, which is the failure mode this document exists to avoid.

## The seed generator

A linear congruential generator seeded by `uds_seed_entropy()`, which the
application feeds from the monotonic clock at startup.

That is also not cryptographic. An LCG's internal state can be recovered from a
few outputs, after which every future seed is predictable — and a predictable
seed means an attacker can precompute the key before the exchange even starts.

The choice is documented rather than hidden, and the header says so at the
declaration. A real ECU draws seeds from a hardware random number generator.

## Replacing the demo algorithm

The protocol handling above — fresh seeds, seed consumption, replay refusal,
lockout, re-locking on session change — is the part that carries over unchanged.
Only two things must be swapped:

1. **Key derivation.** Use HMAC-SHA256 over the seed with a per-ECU shared
   secret, truncated to the key length. Do not implement SHA-256 by hand; link
   a reviewed implementation. The secret must be provisioned per unit, never
   committed, and never the same across a fleet — one extracted key should not
   open every vehicle of the model.

2. **Seed generation.** Hardware RNG. If none exists, a CSPRNG seeded from a
   genuine entropy source at manufacturing time, with state persisted across
   resets so a power cycle does not replay the sequence.

Both belong behind the same two functions that exist today, which is why they
were isolated in the first place.

## Threat model

What this design does address:

| Attack | Defence |
|---|---|
| Replaying a captured key | Fresh seed per request; key refused without a pending seed |
| Brute forcing against one seed | Seed consumed by the first failure |
| Brute forcing across seeds | Lockout after three failures, seed requests refused during it |
| Reaching the service from the default session | Session rule checked before the handler |
| Keeping access after a reset | `ECUReset` re-locks |
| Holding a session open indefinitely | `S3server` expiry; rejected requests do not refresh it |

What it does **not** address, with the demo algorithm in place:

- An attacker who reads this repository. The algorithm is public and there is
  no secret. This is fatal, and it is the whole point of the warning at the top.
- Seed prediction. The LCG state is recoverable.
- Physical access to the bus. Anything on a CAN bus can send anything; UDS
  security is an authorisation gate, not authentication of the sender.
- Timing side channels in the key comparison. The comparison is a plain
  equality test.

## Where it stops

Only security level 1 is implemented (`27 01` / `27 02`). ISO 14229 defines
further odd/even sub-function pairs for additional levels, which a real ECU
uses to separate, say, "read protected data" from "reprogram".

No cryptography library is linked into the project today, by design: the
protocol stack had to be solid first.
