# NodeTree over QUIC (Go)

A from-scratch Go implementation of the extended NodeTree protocol defined
in [`../node.asn`](../node.asn): `Get`, `Set`, `Create`, `Query`, typed
`NodeValue`s, and a reliable-but-**unordered** delivery layer built on
QUIC's unreliable DATAGRAM extension ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)).

This is a distinct protocol version from the Python UDP reference
implementation at the repo root (`client.py`/`server.py`/`common.py`),
documented as such in `node.asn` -- they are not wire-compatible.

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
| `internal/tree` | The in-memory Node tree, match-expression parser/evaluator, flattening, and `Set`'s delete-by-relink semantics -- a port of the proven design in the repo's Python `common.py` |
| `internal/reliability` | `SummaryAck`-based ack/retransmit over QUIC datagrams |
| `internal/query` | `Query`'s collect/aggregate/transfer pipeline and aggregation math (min/max/mean/stdDev/percentile) |
| `internal/server` | Session management (one per QUIC connection), message dispatch, error-node generation |
| `internal/certs` | Throwaway self-signed TLS cert for the demo (QUIC mandates TLS 1.3) -- not a real mTLS story, see below |
| `cmd/server`, `cmd/client` | CLI binaries |

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

## Known gaps (honestly, not swept under the rug)

- **No MSS-based truncation/continuation.** The Python/UDP reference
  implementation (see the repo root README) splits an oversized `Response`
  across multiple datagrams with `<expression>@<index>` continuation
  pointers. That logic was *not* ported here -- a `Get`/`Query` result
  that doesn't fit in one QUIC datagram currently just fails to send
  (`DATAGRAM frame too large`, logged, retried up to `maxRetransmits`,
  then given up on -- confirmed by testing `get "/Sessions"` against a
  server that had accumulated many prior test sessions). This is a real,
  scoped-out gap, not a subtle bug: the same continuation-pointer design
  used on the UDP side would work here too and is the natural next step.
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
is generated independently by the Python/`asn1tools` reference
implementation (see the repo root's tooling) -- not just that this
package's own Marshal/Unmarshal agree with each other, but that they
match what `node.asn`'s AUTOMATIC TAGS numbering actually produces.
