# NodeTree GET protocol

A tree-structured key/value store and query/management protocol, defined
in ASN.1 ([node.asn](node.asn)) and implemented in Go over QUIC
([`goimpl/`](goimpl/) — see its README for setup, usage, and design
notes).

## Schema

[node.asn](node.asn) defines the wire protocol:

- **`Node`** — a tree node: a `key`, a typed `value` (`NodeValue`, modeled
  on SNMP's SMIv2 types — `Integer32`, `Unsigned32`, `Counter32`,
  `Counter64`, `TimeTicks`, `OctetString`, plus a `real` arm for
  aggregation results), and `firstChild`/`nextSibling` pointers.
- **`NodePointer`** — a `CHOICE` of `absolute` (a match-expression
  string), `offset` (a signed relative list position), or `none`.
- **`Get`** / **`Set`** / **`Create`** / **`Query`** — the request types;
  see their docs in `node.asn` for full detail (`Set`'s delete-by-relink
  convention, `Query`'s collect/aggregate/transfer pipeline, etc.).
- **`Response`** — carries a request's result, or an error reference.
- **`SummaryAck`** — the reliability layer's range-based ack, needed
  because the Go implementation deliberately uses QUIC's *unreliable*
  DATAGRAM extension rather than streams (Node data tolerates arbitrary
  reordering, so paying for a stream's strict ordering guarantee would
  only add latency for no benefit — see `goimpl/README.md`).

A `Get`'s `absolute` target is a path/regexp expression:

```
expression = 1*( ["/"] key-regexp ["=" value-regexp] ) ["@" resume-index]
```

e.g. `/users/alice`, `/users/.*=admin`, `/config/timeout`. A literal `/`,
`=`, or `@` inside a regexp is escaped as `\/`, `\=`, `\@`. The optional
`@<index>` suffix resumes a truncated result at a specific flattened
position — see `goimpl/README.md`'s truncation/continuation section.

## Running it

See [`goimpl/README.md`](goimpl/README.md).

## Demo data

[ifmib_dump.json](ifmib_dump.json) is a **real** `snmpbulkwalk` capture
of IF-MIB's `ifTable` (RFC 2863) — 23 network interfaces, taken by
actually running `snmpbulkwalk` against a real, locally-started `snmpd`
(Homebrew's net-snmp, no root needed), not fabricated. It's embedded into
the Go server (`goimpl/cmd/server/ifmib_dump.json`, `go:embed`) and
seeded under `/interfaces`, with every field typed per real IF-MIB column
semantics.

[parse_ifmib_dump.py](parse_ifmib_dump.py) is the script that produced
`ifmib_dump.json` from the raw walk. Its docstring documents the exact
capture commands, for reproducibility. One field isn't carried through
verbatim: real MAC addresses (`ifPhysAddress`) are replaced with
deterministic, clearly-synthetic ones (the `02:00:00:xx:xx:xx`
locally-administered range) rather than committing this machine's actual
hardware addresses. Everything else (interface name, type, MTU, speed,
admin/oper status, every packet/octet/error counter) is the genuine
captured value. The raw capture itself was never committed (it has real
MACs in plaintext before this script's anonymization step); regenerate
your own locally if you want to re-run the script end to end.

## Files

| File | Purpose |
|---|---|
| [node.asn](node.asn) | ASN.1 schema: the full wire protocol |
| [CapabilityMatrix.md](CapabilityMatrix.md) | Feature comparison against SNMP, NETCONF and gNMI, with remaining gaps |
| [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) | How the protocol was designed and built: decisions, measurements, dead ends and mistakes |
| [goimpl/](goimpl/) | The Go/QUIC implementation — see its README |
| [ifmib_dump.json](ifmib_dump.json) | Real IF-MIB capture, used as demo data |
| [parse_ifmib_dump.py](parse_ifmib_dump.py) | Turns a raw `snmpbulkwalk` capture into `ifmib_dump.json` (MAC-anonymized) |

## License

Copyright 2026 Shashidhar Srinivasa. Licensed under the
[Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE).
