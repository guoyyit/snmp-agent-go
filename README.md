# SNMPv2c Agent (Go)

A loopback-only network management agent compatible with SNMPv2c
(RFC 3416 / RFC 3411). It maintains a local MIB, answers manager requests
over UDP, supports community-based access control, emits Traps and
acknowledged InformRequests, and persists writable state across restarts.

## Running

```sh
go run . -config snmp-agent.json
```

The agent binds to `127.0.0.1:1610` by default (loopback only) and writes
its state file to `./snmp-agent.json`. Override either via flags/config.

## Package Layout

| Package   | Responsibility |
|-----------|----------------|
| `oid`     | Dotted OID parsing, lexicographic ordering, BER OID codec. |
| `ber`     | ASN.1 BER TLV, integer/unsigned length codecs. |
| `snmp`    | SNMPv2c message/PDU/VarBind types, strict decoder, encoder. |
| `mib`     | Thread-safe local MIB, lexicographic traversal, atomic sets, Counter32/Gauge32 semantics, persistence snapshots. |
| `config`  | JSON configuration and atomic (temp-file + rename) persistence. |
| `trap`    | Trap / InformRequest sender with ack, timeout retransmit, latest-manager targeting. |
| `agent`   | UDP server, access control, PDU dispatch, GetBulk assembly, size limiting. |

## Data Model

Each managed object (`mib.Object`) has:

- `OID` — unique dotted identifier; objects are kept in lexicographic order.
- `Name` — human label.
- `Syntax` — one of `Integer32`, `OctetString`, `Counter32`, `Gauge32`.
- `Access` — `ReadOnly` or `ReadWrite`.
- `MaxOctets` — optional upper bound on octet-string length.

`Counter32` and `Gauge32` are distinct named Go types, so the two 32-bit
unsigned semantics can never be confused:

- **Counter32** — monotonically increasing; wraps to zero after `2^32-1`.
  Counters are **not writable** via SetRequest.
- **Gauge32** — a value that may go up or down; clamps at `2^32-1` and is
  writable where `Access == ReadWrite`.

Concurrency: the MIB holds an `sync.RWMutex`. A snapshot is taken under the
read lock, so a concurrent reader observes a complete pre-set or complete
post-set state, never a torn multi-varbind result.

## Protocol Behavior

- **GetRequest** — exact-match lookup. A missing object returns
  `noSuchName` with the 1-based `error-index` of the offending varbind.
- **GetNextRequest** — returns the lexicographically next object; walking
  the returned OIDs traverses the entire MIB in order. Past the last object
  it returns `noSuchName`.
- **GetBulkRequest** — `non-repeaters` bindings produce a single GetNext
  result each; remaining bindings repeat up to `max-repetitions` rounds in
  RFC 3416 row order. Results carry `endOfMibView` once a column is
  exhausted. An empty MIB deterministically yields one `endOfMibView` per
  requested binding (the non-repeaters plus one repeater round).
  Response varbinds are trimmed from the tail so the datagram never
  exceeds `MaxMessageSize` (1472 bytes, Ethernet-safe over loopback).
- **SetRequest** — every varbind is fully validated (existence, access,
  type, length) **before** any write: either the whole request commits or
  nothing changes. Errors map to `noSuchName`, `badValue`, `readOnly`, or
  `genErr` with the failing varbind's index. A successful set atomically
  persists writable state.
- **InformRequest** — acknowledged by echoing the request back as a
  Response.
- **Malformed packets** — any packet that fails strict decoding, carries a
  bad version/field, or an unknown PDU tag is silently dropped; a per-packet
  recovery guard ensures the server never crashes.

## Access Control

Two community tiers are configured (they must differ):

- read-only community (default `public`): Get / GetNext / GetBulk / Inform.
- read-write community (default `private`): everything above plus Set.

Unknown communities get **no response at all**. A read-only community
issuing a Set is also silently dropped (never an error PDU), so the
existence of objects is not leaked.

## Traps and Informs

`trap.Sender` sends SNMPv2c Trap PDUs (unacknowledged) and Inform PDUs
(acknowledged). For an Inform it waits for a matching Response
(community + request-id) and retransmits on timeout until the attempt
budget is exhausted. A duplicate acknowledgement cannot trigger a
duplicate report because the inform call has already returned; a stale ack
for an older request-id never satisfies a newer inform. The manager
address is re-read before every attempt, so retransmissions always target
the most recently configured manager. The agent automatically tracks the
source address of the most recent authorized request as the trap target.

## Persistence

Only the writable-object values and the configuration are persisted, as
JSON with hex-encoded raw values:

```json
{
  "ListenAddr": "127.0.0.1:1610",
  "ReadOnlyCommunity": "public",
  "ReadWriteCommunity": "private",
  "Values": {
    "1.3.6.1.2.1.1.1.0": { "Syntax": "OctetString", "Raw": "..." }
  }
}
```

Writes are atomic (`write temp file → fsync → rename`), so a crash leaves
either the old or the new file, never a torn state. On startup the config
is loaded and writable values are restored **before** the UDP socket is
opened; no request can be served or observe an intermediate MIB.

## Configuration Items

- `ListenAddr` — loopback UDP bind address.
- `ReadOnlyCommunity` — community allowed read operations (non-empty).
- `ReadWriteCommunity` — community allowed read + set (non-empty, distinct
  from the read-only community).
- `Values` — map of OID → `{Syntax, hex Raw}` for writable object state.

## Tests

```sh
go test -race ./...
```

Coverage includes:

- OID ordering, BER/integer boundaries, SNMP encode/decode and invalid
  packet rejection.
- Full-MIB GetNext traversal and end-of-MIB boundaries.
- GetBulk non-repeaters/max-repetitions, the size cap, and deterministic
  empty-MIB behavior.
- Atomic Set commit/rollback with error indexes, type/length validation.
- Counter32 wraparound and Gauge32 clamping with distinct types.
- Community access denial (no response) and read-only Set rejection.
- Inform ack, timeout/retransmit count, latest-manager retargeting, and
  duplicate/stale ack handling.
- End-to-end UDP flow and restart state recovery.
