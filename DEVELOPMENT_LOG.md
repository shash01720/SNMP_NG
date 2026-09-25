# Development log

A record of how NodeTree was designed and built in one long working session
(2026-09-21 to 2026-09-25), written for anyone who wants to know *why* the
protocol looks the way it does, not just what it does. It is a curated
summary of the decisions, measurements, dead ends and mistakes, not a
verbatim transcript. The code, `node.asn` and the READMEs describe the
current state; this file explains how it got there.

## What was built

NodeTree is a tree-structured network-management protocol, meant to reach
functional parity with SNMP, NETCONF and gNMI. The whole protocol is one
ASN.1 module ([`node.asn`](node.asn)); [`goimpl/`](goimpl/) is a Go reference
implementation over QUIC. Where it stands against the three reference
protocols is in [`CapabilityMatrix.md`](CapabilityMatrix.md).

## Phase 1: the data model and a first working protocol (Sep 21)

The starting point was a small ASN.1 sketch: a `Node` (key, value, first
child, next sibling) and a `NodePointer` to link them.

Decisions that stuck:

- **`NodePointer` is a CHOICE**: `absolute` (a match expression), `offset`
  (a list-position delta, meaningful only inside one response) and, added
  later, `none`. `none` is deliberately distinct from an offset of 0, so a
  client can say "clear this pointer" without overloading a sentinel.
- **Values are typed**, not opaque bytes: UTF8String/INTEGER at first,
  SNMP-style types later.
- **Addressing is a regex expression**, not an OID:
  `expression = 1*( ["/"] key-regexp ["=" value-regexp] ) ["@" resume-index]`,
  with `\` escaping `/`, `=` and `@`. Matching is server-side, so "every
  interface that is down" is one request rather than a walk plus a
  client-side filter.
- **A response is a flattened pre-order list** where `firstChild` and
  `nextSibling` are offsets into that list. Arrival order doesn't matter,
  because a node is reassembled by index.
- **Truncation with continuation.** A response that doesn't fit one datagram
  is cut, and any pointer reaching past the cut becomes an absolute
  `<expression>@<index>` continuation the client follows. Continuing by
  re-matching the cut-off node lost its siblings; resuming by index into the
  deterministic result is what worked. Several top-level matches are chained
  through `nextSibling` too, otherwise a match beyond the cut vanished
  silently.
- **JSON derives the tree**: object properties become keyed nodes, and arrays
  are transparent, so a repeated key is an array of siblings. No `Key`/
  `Value`/`Children` boilerplate in the data.

A gotcha worth recording: in ASN.1 a `--` inside a comment *closes* the
comment. An em-dash written as `--` in prose broke the parser
(`Expected Type, found 'when'`). It bit again in several later schema edits;
every schema edit since is checked with `asn1tools` before anything else.

## Phase 2: transport discussions (Sep 21-22)

Several design questions were worked through before any Go was written.

- **Streams or datagrams?** QUIC streams are reliable *and* strictly ordered.
  Node data doesn't need ordering, since each node is meaningful on its own
  and is placed by index. QUIC's DATAGRAM extension (RFC 9221) gives
  unordered delivery with congestion control and encryption but no
  retransmission. So the protocol runs on datagrams and adds its own
  reliability: every message carries a `sequenceNumber`, the receiver
  periodically sends a range-based `SummaryAck`, and the sender retransmits
  what isn't acknowledged.
- **Custom congestion/flow control** was explored as an idea. The
  implementation uses QUIC's own congestion controller, which already
  applies to datagrams.
- **QUIC + DATAGRAM versus Noise-based crypto** and a hand-rolled
  public-key session handshake were compared. QUIC won because one
  handshake gives encryption, congestion control and (with certificates)
  mutual authentication.
- **Adoption of RFC 9221** was checked before betting on it.

The schema was then extended for the QUIC design: `Set`, `Create`,
`Query`, `SummaryAck`, a structured `Response` (sequence numbers, an error
flag pointing at an error node) and typed values modelled on SNMP's SMI
(`Integer32`, `Unsigned32`, `Counter32`, `Counter64`, `TimeTicks`,
`OctetString`, plus `Real`).

- **`Real` is 8 raw IEEE-754 bytes in an OCTET STRING**, not ASN.1 `REAL`,
  because Go's standard `encoding/asn1` has no `REAL` support at all.
- **The BER codec is hand-written**, not built on `encoding/asn1` struct
  tags, which fight this schema's mix of implicit tags and explicitly-wrapped
  CHOICE fields. It is tested byte-for-byte against fixtures produced
  independently by `asn1tools` compiling `node.asn`.
- **Per-session server state lives in the tree itself**: staged nodes,
  errors and query results sit under
  `/Sessions/Connection-ID=<id>/{NewNodes,Errors,QueryResults}`. The id is
  server-generated, not the literal QUIC connection ID, which quic-go
  doesn't cleanly expose and which rotates on path migration anyway.

## Phase 3: real demo data and the Go implementation (Sep 22-23)

- **First Go failure**: `get "/Sessions"` died with `DATAGRAM frame too
  large`. The Go side had no truncation yet; it was ported next
  (`FitToSize`).
- **The demo data is real.** A local `snmpd` was run, walked with
  `snmpbulkwalk`, and the IF-MIB result turned into `ifmib_dump.json`
  (23 interfaces). Real hardware MAC addresses were caught in the raw
  capture before anything was committed; they are replaced with synthetic
  `02:00:00:xx:xx:xx` addresses, and the raw file is git-ignored.
- **Continuation redundancy (4.2x).** On a wide tree, one truncated batch
  can leave several continuation pointers dangling at once, and following
  each independently re-fetched the same nodes: 51 round trips and 1931
  nodes delivered for 460 unique. The client now keeps a queue that always
  fetches the smallest pending resume index first and skips any pointer a
  real response has already proven covered. Same fetch: 13 round trips, 483
  nodes.
- **`--max-datagram-size` was being silently overwritten** by the first real
  `DatagramTooLargeError`, pinning a session to quic-go's conservative
  startup size. Fixed, and the retest revealed the earlier "13 round trips
  under jumbo frames" claim had been measuring quic-go's ~1243-byte startup
  limit all along. That claim was retracted. A live jumbo-frame result isn't
  reachable on a short loopback connection: path-MTU discovery ramps up
  over time (observed 1243, 1329, 1393, then 1404 bytes across a dozen
  requests), so only the arithmetic ceiling (about 2 round trips) is a
  claim, not a measurement.

### Comparison with SNMP, measured

- Bytes per object: **23.4** for SNMP (from real packet captures) versus
  **31.3** for NodeTree (using the real encoder), about 1.34x. The gap is
  string keys versus numeric OID sub-identifiers, the forced explicit
  wrapping automatic tagging puts on CHOICE fields, and the embedded
  `firstChild`/`nextSibling` pointers that make each response
  self-describing.
- Round trips to fetch the same ~500 objects: `GETNEXT` 507; `GETBULK`
  with net-snmp's default `max-repetitions=10`, 51; tuned to 100, 6. net-snmp's
  agent caps its own response at roughly 1750-1850 bytes regardless of what
  is requested. NodeTree, budgeting by bytes and discovering the real limit,
  needed 12-13 under quic-go's loopback limit.
- Reliability is a protocol feature here (`SummaryAck`); classic SNMP leaves
  retries to the tooling.

## Phase 4: closing gaps against SNMP, NETCONF and gNMI (Sep 24-25)

A gap analysis (now [`CapabilityMatrix.md`](CapabilityMatrix.md)) drove the
rest of the work, largest gaps first.

- **`Query` `onChange`** (gNMI's ON_CHANGE). The mode field was an integer
  where `0` meant "once"; adding a third state to that would have meant more
  overloaded sentinels, so it became a `CollectionMode` CHOICE (`once`,
  `interval`, `onChange`). It is event-driven, not fast polling: the tree
  broadcasts on mutation and the query re-samples and diffs. The broadcast
  carries a generation counter, because a bare closed-and-replaced channel
  loses a mutation that lands between one wake-up and the next wait.
- **`Set` takes regex targets and several edits per request**, applied
  atomically: every target is resolved against the pre-request tree before
  anything is applied, and a conflict between structural edits rolls back
  everything already done. Building the rollback exposed a latent bug: the
  relink helpers never checked for a node no longer being in its parent, so
  a conflicting batch would have panicked with a negative slice index. Fixed
  and tested.
- **`Delete`** as its own message: the server works out the relink, matching
  is regex and multi-target, and a target that matches nothing is a no-op
  (needed for idempotent retries under at-least-once delivery).
- **Staging and commit.** `Create` can take a `parent`, building a nested
  subtree under the session's private `NewNodes`; `Set`'s new `newParent`
  attaches that subtree anywhere in live config, atomically. This covers
  NETCONF's candidate/commit for *new* subtrees only. Reusing
  `newFirstChild` for this wasn't an option: those primitives *truncate* (a
  delete-by-relink tool), and relaxing their ownership check would have
  either crashed or allowed unrestricted reparenting.
- **Long-lived connections.** quic-go's defaults are a 30-second idle
  timeout and no keep-alive, and the ack loop sends nothing when there is
  nothing to acknowledge, so a quiet `onChange` subscription would be dropped
  by QUIC itself. Both ends now set `MaxIdleTimeout`/`KeepAlivePeriod`
  (30s/10s), verified with a 40-second idle watch. Two per-session maps that
  were never pruned are now bounded.
- **Query cancellation without a new message.** Each query gets its own
  results node under `QueryResults`, and deleting it cancels the query.
  Detection is reachability-based, so deleting an ancestor works too. The
  first `IsReachable` was wrong: it walked the parent chain up to the root,
  which always succeeds because a removed node keeps its `Parent` pointer.
  A test written for the "ancestor deleted" case caught it immediately.
- **Access control.** Identity is the CommonName of a verified TLS client
  certificate; authorization is a per-identity policy plus a global
  read-only list, deny by default. Enforcement lives inside the tree
  operations on the nodes actually touched, because a request expression is
  a regex and checking its text would mean nothing. Consequences worth
  remembering: unreadable nodes are absent rather than "forbidden";
  value predicates are never tested against unreadable nodes (so they can't
  be used as an oracle); a relink needs `delete` on what it drops; sessions
  are isolated from one another. Verified over real QUIC with real
  certificates. A client with no or a foreign certificate is refused in
  ~0.4s (the client used to report only a timeout, which was fixed).

## Mistakes in the process, and what caught them

Recorded because the way they were caught is as useful as the fixes.

| Mistake | Caught by |
|---|---|
| `--` inside an ASN.1 comment | schema compile after every edit |
| "13 round trips under jumbo frames" | a debug log of the real discovered limit |
| `IsReachable` walking the parent chain | a unit test for the ancestor-deleted case |
| relink helpers indexing with `-1` | designing the atomic-rollback test |
| throwaway test helper passing the wrong sequence number, and an unescaped `=` in an expression | live runs whose output didn't match the expectation |
| leaked `snmpd` MAC addresses | reading the raw capture before committing |

## Things deliberately left open

See [`CapabilityMatrix.md`](CapabilityMatrix.md) for the full list. In
priority order: server-initiated notifications (nothing is sent unless a
client has a standing request), timestamps and a sync marker on pushes,
deletion reporting in `onChange`, staged edits to *existing* values,
certificate revocation and policy reload, and replace, locking, schema
validation and capability negotiation.

## Commit history (Go implementation onward)

| Commit | Date | Summary |
|---|---|---|
| `1eb1c3a` | 09-22 | Extend `node.asn` for QUIC: Set, Create, Query, typed values, SummaryAck |
| `c64fb87` | 09-22 | Go/QUIC implementation |
| `0efe228` | 09-22 | MSS truncation/continuation in the Go implementation |
| `6d373b9` | 09-23 | Real IF-MIB `snmpbulkwalk` capture as demo data |
| `7f95a30` | 09-23 | Dedup redundant continuation fetches |
| `506884a` | 09-23 | Stop the datagram-size override being clobbered |
| `f8f41d4` | 09-24 | `Query` ON_CHANGE |
| `3ae6ef0` | 09-24 | Regex/multi-target `Set`; `Delete` |
| `916453b` | 09-24 | Staged `Create`, `Set` `newParent` |
| `4d6b708` | 09-24 | Keep-alive; bounded session state |
| `d4597f5` | 09-24 | Cancel a query by deleting its results node |
| `d085339` | 09-24 | Apache-2.0 license and NOTICE |
| `d2e9ff5` | 09-24 | `CapabilityMatrix.md` |
| `e104460` | 09-25 | Mutual-TLS identity, access control, read-only paths |
| `e2a892b` | 09-25 | Module renamed to match the repository |
