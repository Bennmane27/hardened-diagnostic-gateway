# UDS layer

Diagnostic server implementing a subset of ISO 14229-1. Lives in `src/uds/`,
includes no system header, and knows nothing about its transport — it receives
a request payload and fills a response buffer.

## Message shapes

```
request           SID  [sub-function]  [data...]
positive response SID+0x40  [echo]  [data...]
negative response 7F  SID  NRC
```

`0x7F` is not a service, it is a rejection marker. Any client must test for it
*before* trying to interpret a positive response — mistaking one for the other
turns a clean refusal into an incomprehensible reply.

The rejected SID is echoed back so a tester with several requests in flight
knows which one failed.

## Implemented services

| SID | Service | Extended session? | Unlock? |
|---|---|:---:|:---:|
| `0x10` | DiagnosticSessionControl | no | no |
| `0x11` | ECUReset | **yes** | **yes** |
| `0x14` | ClearDiagnosticInformation | **yes** | no |
| `0x19` | ReadDTCInformation | no | no |
| `0x22` | ReadDataByIdentifier | no | no |
| `0x27` | SecurityAccess | **yes** | no |
| `0x3E` | TesterPresent | no | no |

That table is not documentation of the code — it *is* the code. `SERVICE_RULES`
in `uds.c` holds exactly these rows, and the access checks run from it before
any handler is reached. A service added without a rule is rejected by default
rather than silently reachable, and the SID sweep in `tests/test_uds.c` fails
until the new service is listed there too.

### `0x10` DiagnosticSessionControl

```
request  10 <session>
response 50 <session> <P2Server_max:2> <P2*Server_max:2>
```

Sessions: `01` default, `03` extended. `02` programming is a valid sub-function
of the standard that this server does not implement, so it is refused with
`subFunctionNotSupported` rather than accepted with no effect.

The `sessionParameterRecord` in the positive response is not optional padding:
`P2Server_max` is how long the client should wait for a reply (50 ms here), and
`P2*Server_max` how long after a `0x78` *ResponsePending* (5 000 ms, encoded
with a 10 ms resolution, hence `01 F4`). Both are big endian.

### `0x22` ReadDataByIdentifier

```
request  22 <DID:2>
response 62 <DID:2> <value...>
```

One identifier per request. The standard allows several; this server refuses a
longer request with `incorrectMessageLengthOrInvalidFormat`. That is a stated
limitation, not an oversight.

The server holds no vehicle data. The application registers a callback with
`uds_set_did_provider`, so the same server could sit in an engine controller or
a braking controller unchanged — and the unit tests inject a fake provider
instead of dragging the simulated ECU into the UDS test binary.

Provider failures map onto standard codes:

| Provider returns | NRC |
|---|---|
| `UDS_ERR_DID_NOT_FOUND` | `0x31` requestOutOfRange |
| `UDS_ERR_BUFFER_TOO_SMALL` | `0x14` responseTooLong |

`responseTooLong` is worth dwelling on. Before multi-frame existed, a 17-byte
VIN could not be transported at all. Three reactions were possible: truncate it
(the client gets a wrong VIN and never knows), stay silent (the client waits for
a timeout it cannot explain), or say `7F 22 14`. ISO 14229 defines that code for
exactly this case — a network limitation surfacing as a named protocol error.

### `0x19` ReadDTCInformation

Only sub-function `0x02` reportDTCByStatusMask is implemented.

```
request  19 02 <status mask>
response 59 02 <availability mask> [<DTC:3> <status:1>]...
```

Faults whose status shares no bit with the requested mask are omitted. The
availability mask tells the client which status bits this ECU actually
maintains.

### `0x14` ClearDiagnosticInformation

```
request  14 <group:3>
response 54
```

`FF FF FF` clears everything. Clearing a group that does not exist is
`requestOutOfRange`, not a silent success.

### `0x11` ECUReset

```
request  11 <type>       01 hard, 03 soft
response 51 <type>
```

The deliberately sensitive command of the demonstration: extended session **and**
an unlocked security level. A reset returns the server to the default session
and re-locks security, so no access survives across it.

### `0x3E` TesterPresent

```
request  3E 00
response 7E 00
```

Does nothing, and that is the point: having been processed is what pushed the
`S3server` deadline back. Diagnostic tools emit it periodically, usually with
the suppress bit set so it does not clutter the bus.

## The suppress-positive-response bit

Bit 7 of a sub-function is `suppressPosRspMsgIndicationBit`.

```
0x83 = 1000 0011
       ^          bit 7 : do not reply on success
         ^^^ ^^^  bits 6..0 : the actual sub-function
```

So `0x83` is not sub-function `0x83`, it is `0x03` with the bit set. Hence
`raw & 0x80` to read the intent and `raw & 0x7F` to extract the value.

**It silences positive responses only.** A negative response still goes out —
otherwise an error would never reach the client, which would wait for a timeout
without ever learning why. There is a test for exactly that.

## Sessions

```
   DEFAULT ──── 10 03 ────► EXTENDED
   EXTENDED ─── 10 01 ────► DEFAULT
   EXTENDED ─── S3server expired, no activity ────► DEFAULT (security re-locked)
   any ──────── successful ECUReset ─────────────► DEFAULT (security re-locked)
```

`S3server` is a security property, not a convenience. A privileged session
nobody is watching is a door left open, so it closes on its own after five idle
seconds.

Two details that are easy to get wrong:

- A **rejected** request does not refresh the deadline. Otherwise an attacker
  could hold a session open indefinitely using requests it is not even allowed
  to make.
- Deadlines are evaluated **before** the incoming request is processed, so a
  request arriving too late cannot rescue the session it just missed.

## Negative response codes

Subset in use. Values follow published descriptions of ISO 14229-1; they have
not been checked against the paid standard document.

| NRC | Name | Raised when |
|---|---|---|
| `0x10` | generalReject | provider failed in an unclassified way |
| `0x11` | serviceNotSupported | unknown SID, or no provider registered for it |
| `0x12` | subFunctionNotSupported | unknown sub-function, unimplemented session |
| `0x13` | incorrectMessageLengthOrInvalidFormat | wrong request length |
| `0x14` | responseTooLong | value does not fit what the transport can emit |
| `0x22` | conditionsNotCorrect | key sent with no seed pending (replay) |
| `0x31` | requestOutOfRange | unknown identifier, unknown DTC group |
| `0x33` | securityAccessDenied | service needs an unlock |
| `0x35` | invalidKey | wrong key |
| `0x36` | exceedNumberOfAttempts | three consecutive wrong keys |
| `0x37` | requiredTimeDelayNotExpired | still locked out |
| `0x7F` | serviceNotSupportedInActiveSession | service needs the extended session |

## Memory

`uds_context_t` is 72 bytes. The response buffer belongs to the caller;
`UDS_MAX_RESPONSE_SIZE` defaults to 512 and is overridable at compile time.

## Not implemented

`0x2E` WriteDataByIdentifier, `0x31` RoutineControl, `0x34`/`0x36`/`0x37`
download services, `0x28` CommunicationControl, `0x85` ControlDTCSetting,
response-pending (`0x78`), functional addressing, and multiple identifiers per
`0x22` request.
