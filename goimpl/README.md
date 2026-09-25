# NodeTree over QUIC (Go)

A Go implementation of the NodeTree protocol defined in
[`../node.asn`](../node.asn): `Get`, `Set`, `Delete`, `Create`, `Query`,
typed `NodeValue`s, and a reliable-but-**unordered** delivery layer built
on QUIC's unreliable DATAGRAM extension ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)).

## Why QUIC datagrams instead of streams

A QUIC stream is reliable *and* strictly ordered, like a TCP byte stream:
if a packet carrying stream bytes is lost, later bytes on that stream sit
unread in the receiver's buffer until the retransmission fills the gap.
Node data doesn't need that ordering -- each `Node` is independently
meaningful, and a `Response`'s nodes are reassembled by index via
`firstChild`/`nextSibling` pointers, not by arrival order. Paying for
strict ordering here would only add latency for no benefit.

QUIC's DATAGRAM extension gives unordered delivery with congestion control
and encryption, but explicitly *no* retransmission -- RFC 9221 datagrams
are "ack-eliciting" (QUIC tracks whether they were acknowledged) but the
retransmit decision is left to the application. `internal/reliability`
implements that missing piece: a fixed-interval retransmitter plus
`SummaryAck`, a compact range-based ack the receiver sends back
periodically. See `node.asn`'s SummaryAck docs for the full reasoning, and
the parent conversation's mTLS/DTLS/QUIC design discussion for how this
compares to the alternatives considered (DTLS, TLS+TCP, hand-rolled
Noise-based crypto).

## Layout

| Package | Purpose |
|---|---|
| `internal/wire` | Hand-written BER codec for every node.asn message type, verified against real `asn1tools`-encoded fixtures (`testdata_fixtures.json`) -- not `encoding/asn1` struct tags, which don't cleanly express this schema's mix of IMPLICIT/EXPLICIT-on-CHOICE tagging (see the package doc comment for why) |
| `internal/tree` | The in-memory Node tree, match-expression parser/evaluator, flattening, `Set`'s atomic multi-edit application (with rollback on a conflicting structural edit, including reparenting via `newParent`), `Delete`'s own relink-around-the-gap logic, `CreateStaged`'s nested-subtree-in-staging-space support, a change-notification primitive (`ChangedSince`) `Query`'s `onChange` mode blocks on, and `IsReachable` (is a node still attached to Root, used for delete-cancels-query) |
| `internal/reliability` | `SummaryAck`-based ack/retransmit over QUIC datagrams |
| `internal/query` | `Query`'s collect/aggregate/transfer pipeline (interval-polled or event-driven `onChange`) and aggregation math (min/max/mean/stdDev/percentile) |
| `internal/server` | Session management (one per QUIC connection), message dispatch, error-node generation, per-query cancellation (deleting a query's own results node stops it) |
| `internal/certs` | Throwaway self-signed TLS cert for the demo (QUIC mandates TLS 1.3) -- not a real mTLS story, see below |
| `cmd/server`, `cmd/client` | CLI binaries -- `cmd/server` also embeds and seeds a real IF-MIB dataset, see below |

## Running the demo

```bash
go run ./cmd/server
```

In another terminal:

```bash
go run ./cmd/client get "/users"
go run ./cmd/client get "/users/user=alice"
go run ./cmd/client set --value superadmin "/users/group=admin"
go run ./cmd/client create note "hello world"

# Set's target is a regex match expression, like Get's -- it can match (and
# update) more than one node in a single edit...
go run ./cmd/client set --value down "/interfaces/ifAdminStatus"

# ...and a single Set request can carry several distinct expressions,
# applied atomically (all of them, or none):
go run ./cmd/client set --value 60 "/config/timeout" "/config/retries"

# Delete: the server figures out the parent/sibling relink itself, so the
# client only needs to address the node it wants gone -- no more manual
# "set --next-sibling none" dance. Also regex-based and multi-target.
go run ./cmd/client delete "/config/retries"

# Staging + commit (NETCONF candidate/commit, for NEW subtrees): Create's
# default target is this session's own private staging area under
# NewNodes -- invisible from live config until explicitly attached.
# Because each `go run ./cmd/client ...` invocation opens its own fresh
# connection/session, actually seeing this requires staying on ONE
# connection (unlike the copy-pasteable examples above); find your own
# session first --
go run ./cmd/client get "/Sessions"
# -- then, reusing that connection: `create interface` (lands under
# NewNodes), `create --parent .../NewNodes/interface ifDescr eth9`
# (nests a child under the still-staged node -- an arbitrarily deep
# subtree can be built this way, one Create at a time), then commit the
# whole thing atomically with `set --new-parent /config
# .../NewNodes/interface`. /config/interface then exists with its
# ifDescr child attached, and NewNodes is empty again: the subtree
# moved, not copied.

# a query that runs once and returns immediately
go run ./cmd/client query --collection 0 --transfer 0 "/config/timeout"

# a recurring query: sample every 1s, aggregate (mean) every 3s,
# push accumulated results every 4s, watch for 9s
go run ./cmd/client query --collection 1 --agg-interval 3 --agg-method mean --transfer 4 --watch 9s "/config/timeout"

# an onChange query: no polling interval -- pushes an immediate baseline,
# then a fresh push only when a Set/Create actually changes a matched
# value. In another terminal while this is running, try:
#   go run ./cmd/client set --value 99 "/config/timeout"
go run ./cmd/client query --on-change --transfer 1 --watch 15s "/config/timeout"

# Per-query cancellation: no dedicated message -- every Query gets its own
# results subcontainer under QueryResults (see SESSION PATHS in node.asn),
# and deleting THAT node stops the query, the same as if the session had
# disconnected. Like the staging/commit demo above, this needs one
# connection (find your session, register a query, delete that query's
# own results node, all within it) -- not copy-pasteable across separate
# `go run` invocations.
```

Note: flags must come *before* the positional expression (Go's `flag`
package stops parsing at the first non-flag argument) --
`set --value X "/expr"`, not `set "/expr" --value X`.

A `--watch` on `query --on-change` is exactly the case that needs a
genuinely long-lived, mostly-quiet connection: both `cmd/server` and
`cmd/client` set `MaxIdleTimeout`/`KeepAlivePeriod` in their `quic.Config`
explicitly (30s/10s) so quic-go's own idle timeout doesn't silently drop a
connection sitting quietly between rare events -- without this, the
default `KeepAlivePeriod` is disabled, and a connection with nothing to
acknowledge in either direction for 30s is torn down by QUIC itself,
independent of anything at the application layer. Verified by watching a
genuinely idle connection (no `Set` calls at all) survive 40s.

### Real IF-MIB demo data

Alongside the toy `users`/`config` tree, the server seeds a second,
richer dataset under `/interfaces`: 23 records, one per network interface,
taken from a **real** `snmpbulkwalk` of IF-MIB's `ifTable` (RFC 2863) run
against a real, locally-started `snmpd` -- not fabricated. See
[`../parse_ifmib_dump.py`](../parse_ifmib_dump.py) for how the raw walk
was turned into [`../ifmib_dump.json`](../ifmib_dump.json) (embedded here
as `cmd/server/ifmib_dump.json`); the only thing not carried through
verbatim is `ifPhysAddress` -- real MAC addresses are replaced with
deterministic, clearly-synthetic ones (the `02:00:00:xx:xx:xx`
locally-administered range) rather than exposing this machine's actual
hardware addresses.

Each interface's fields are typed per real IF-MIB column semantics --
`Integer32` for `ifIndex`/`ifType`/`ifMtu`/`ifAdminStatus`/`ifOperStatus`,
`Unsigned32` for `ifSpeed` (`Gauge32` in the real MIB), `TimeTicks` for
`ifLastChangeTicks`, `Counter32` for every packet/octet/error counter,
`OctetString` for `ifDescr`/`ifPhysAddress` -- a good demonstration of the
typed `NodeValue` system beyond the toy demo's plain strings/ints:

```bash
go run ./cmd/client get "/interfaces/ifDescr=en0"
go run ./cmd/client get "/interfaces/ifDescr=.*"   # every interface name
```

`get "/interfaces"` (the whole table) is large enough that it naturally
triggers truncation/continuation on a real connection, no
`--max-datagram-size` override needed -- a good real-world exercise of
that mechanism alongside the forced demo below.

### Demoing truncation and continuations

A `Get` result that doesn't fit in one QUIC datagram is truncated, with `firstChild`/`nextSibling` pointers that
would reach past the cut rewritten to an absolute `<expression>@<index>`
continuation pointer (`tree.FitToSize`); `client.go`'s `followGet`
resolves them automatically. A `Query` push that doesn't fit is handled
differently: those nodes are independent results with no
`firstChild`/`nextSibling` relationships worth preserving (`sessionResultSink.DeliverResults`
always gives each one a trivial "none"/"none"), so `sendBatched` just
splits them across multiple `Response` messages instead of generating
continuation pointers -- no query-language concept to resume from is
needed there. `quic-go` has no proactive "max datagram size" query -- the
server discovers it reactively, from the `quic.DatagramTooLargeError` a
real oversized send returns -- so on a real network path the limit is far
larger than this demo's small tree would ever exceed. Force it low to see
`Get` truncation happen:

```bash
go run ./cmd/server --max-datagram-size 60
go run ./cmd/client get "/users"
```

```
get: 1 node(s)
    key="users" value=(none) firstChild=-> "/users@1" nextSibling=-> "/users@3"
get (continuation of "/users@1"): 1 node(s)
    key="user" value="alice" firstChild=none nextSibling=-> "/users@2"
...
```

### Continuation dedup: why fetching isn't naive FIFO

A truncated batch can dangle more than one pointer at once -- e.g. the
`/users` example above: the very first `Get` already returns a node with
*both* `firstChild` (`->/users@1`) *and* `nextSibling` (`->/users@3`)
pointing past the cut, simultaneously. On a wide/bushy tree this gets
expensive fast: `/interfaces` (23 sibling records, ~19 fields each) has,
for every truncation, one continuation resuming *mid-record* (the current
record's own field chain) and another resuming at the *start of the next
record* (the record's own parent's `nextSibling`, which sits earlier in
the same window). Fetching both independently, unaware that the smaller
one's own forward progress will eventually cover the larger one's data
too, means massively overlapping re-fetches.

Measured on the real IF-MIB data with jumbo frames (`--max-datagram-size
8900`, standing in for a 9000-byte-MTU path): naively following every
discovered continuation took **51 round trips** and delivered **1931**
total nodes for a tree with only **460** unique ones -- a ~4.2x
redundancy. `cmd/client/continuation.go`'s `continuationQueue` fixes
this: it always fetches the *smallest* pending resume index first per
base expression, and after each real response, records exactly which
index range it covered (`[resumeIndex, resumeIndex+len(nodes))`) --
skipping any other pending continuation whose index that range already
proves was delivered. This is safe (a continuation is only skipped once
an actual response has proven its data arrived, never on a guess) and
took the same fetch down to **13 round trips** (matching the theoretical
minimum, `ceil(460/~38 nodes-per-datagram)`) delivering **483** nodes --
essentially no redundancy left. `cmd/client/continuation_test.go` unit
tests this logic directly (including the exact `/interfaces@38` /
`/interfaces@42` scenario that was measured), independent of any network
I/O.

## Known gaps (honestly, not swept under the rug)

- **`Create`'s staging + `Set`'s `newParent` only cover PART of NETCONF's
  candidate/commit model.** They give a client an atomic way to introduce
  a whole NEW subtree (build it under NewNodes across several Create
  calls, attach it with one Set) -- but an ordinary Set targeting an
  EXISTING live node still applies immediately, not staged until some
  later commit, so there's no way to stage a batch of edits to values
  already in the tree. Discarding a staged subtree is just a Delete on
  it; left alone, it sits under NewNodes until the session ends.
- **No real mTLS.** `internal/certs` generates a throwaway self-signed
  certificate, and the client sets `InsecureSkipVerify`. See the parent
  conversation's mTLS design discussion (TCP+TLS vs. DTLS vs. QUIC's own
  TLS 1.3 handshake, optionally with RFC 7250 raw public keys for a
  Noise-like lightweight trust model) for what a real deployment needs.
- **No "delete by descendant" addressing**, documented in
  `internal/tree/tree_test.go`'s `TestSetDeleteFirstChildByRelink` and
  `TestDeleteAddressesTheNodeItself`: `Delete` closes the *mechanical*
  addressing gap this used to describe (a client no longer computes any
  relink itself -- see `Delete`, below), but not a deeper one. The demo
  tree's three `users` records are only distinguishable by their
  *children's* values, not their own key/value, so `delete
  "/users/user=alice"` removes just alice's `user` leaf, not the `users`
  container that holds it alongside her `group` node -- there's still no
  expression that addresses "the `users` node containing `user=alice`"
  itself. Closing that needs a genuinely richer query language
  (ancestor-of-a-matching-descendant predicates), not more server-side
  bookkeeping.
- **Fixed-interval retransmission**, not TCP-style adaptive RTO -- a
  reasonable simplification for a reference implementation, not a
  production congestion/loss-recovery strategy.
- **Session ID is server-generated, not the literal QUIC Connection ID**
  -- documented in `node.asn`'s SESSION PATHS section: quic-go's public
  API doesn't cleanly expose the wire-level CID outside its qlog Tracer
  hook, and the CID isn't stable across a connection's lifetime anyway
  (it rotates on path migration), so a server-generated id fills the same
  role more robustly.
- **`onChange` doesn't report deletions.** If a matched node stops
  existing (e.g. via `Delete`), its last known value simply stops
  updating -- there's no tombstone/removal concept in `QueryResults`,
  only additions. Closing this needs a deletion marker in the wire
  schema, not just server logic.

## Testing

```bash
go test ./...
```

`internal/wire`'s tests are the most important ones to trust: they check
this codec's output byte-for-byte against `testdata_fixtures.json`, which
`generate_fixtures.py` produces independently by compiling `node.asn`
directly with the Python `asn1tools` library (not via anything in this
Go module) -- not just that this package's own Marshal/Unmarshal agree
with each other, but that they match what `node.asn`'s AUTOMATIC TAGS
numbering actually produces.
