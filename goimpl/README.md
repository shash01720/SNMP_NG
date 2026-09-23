# NodeTree over QUIC (Go)

A from-scratch Go implementation of the extended NodeTree protocol defined
in [`../node.asn`](../node.asn): `Get`, `Set`, `Create`, `Query`, typed
`NodeValue`s, and a reliable-but-**unordered** delivery layer built on
QUIC's unreliable DATAGRAM extension ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)).

This is a distinct protocol version from the Python/UDP prototype that
proved out the core design before `node.asn` was extended (documented as
such in `node.asn`'s header comment) -- they were never wire-compatible,
and that prototype has since been removed as superseded. Several design
comments below still cite it by name (e.g. `common.py`) as provenance for
where a piece of this Go implementation's design came from.

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
| `internal/tree` | The in-memory Node tree, match-expression parser/evaluator, flattening, and `Set`'s delete-by-relink semantics -- a port of the design proven out in the (now-removed) Python prototype's `common.py` |
| `internal/reliability` | `SummaryAck`-based ack/retransmit over QUIC datagrams |
| `internal/query` | `Query`'s collect/aggregate/transfer pipeline and aggregation math (min/max/mean/stdDev/percentile) |
| `internal/server` | Session management (one per QUIC connection), message dispatch, error-node generation |
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

# delete /config/retries by relinking timeout's nextSibling to none
go run ./cmd/client set --next-sibling none "/config/timeout"

# a query that runs once and returns immediately
go run ./cmd/client query --collection 0 --transfer 0 "/config/timeout"

# a recurring query: sample every 1s, aggregate (mean) every 3s,
# push accumulated results every 4s, watch for 9s
go run ./cmd/client query --collection 1 --agg-interval 3 --agg-method mean --transfer 4 --watch 9s "/config/timeout"
```

Note: flags must come *before* the positional expression (Go's `flag`
package stops parsing at the first non-flag argument) --
`set --value X "/expr"`, not `set "/expr" --value X`.

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

Like the earlier Python/UDP prototype this design was proven out in, a
`Get` result that doesn't fit in one QUIC datagram is truncated, with `firstChild`/`nextSibling` pointers that
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

## Known gaps (honestly, not swept under the rug)

- **No real mTLS.** `internal/certs` generates a throwaway self-signed
  certificate, and the client sets `InsecureSkipVerify`. See the parent
  conversation's mTLS design discussion (TCP+TLS vs. DTLS vs. QUIC's own
  TLS 1.3 handshake, optionally with RFC 7250 raw public keys for a
  Noise-like lightweight trust model) for what a real deployment needs.
- **`Set`'s addressing gap**, documented in `internal/tree/tree_test.go`'s
  `TestSetDeleteFirstChildByRelink`: the demo tree's three `users` records
  are only distinguishable by their *children's* values, not their own
  key/value, so there's currently no expression that addresses "the
  `users` node containing `user=alice`" directly for a targeted delete.
  The delete-by-relink primitive itself is correct and tested; reaching
  the right parent node from a client is a query-language gap.
- **Fixed-interval retransmission**, not TCP-style adaptive RTO -- a
  reasonable simplification for a reference implementation, not a
  production congestion/loss-recovery strategy.
- **Session ID is server-generated, not the literal QUIC Connection ID**
  -- documented in `node.asn`'s SESSION PATHS section: quic-go's public
  API doesn't cleanly expose the wire-level CID outside its qlog Tracer
  hook, and the CID isn't stable across a connection's lifetime anyway
  (it rotates on path migration), so a server-generated id fills the same
  role more robustly.

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
