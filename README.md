# NodeTree GET protocol

A small tree-structured key/value store and a GET protocol for querying
it, defined in ASN.1 ([node.asn](node.asn)) and implemented as a
reference UDP client/server in Python.

> **Status: this Python client/server is currently wire-incompatible with
> `node.asn`.** The schema was later extended (`Set`/`Create`/`Query`,
> typed `NodeValue`, a structured `Response`) for a separate Go/QUIC
> implementation ([`goimpl/`](goimpl/)), which *is* schema-current and
> actively maintained. `common.py`/`client.py`/`server.py` here were
> never migrated to match — `client.py get ...` currently fails with an
> encode error (`Get: Sequence member 'sequenceNumber' not found`). The
> demo data below (including the new `interfaces` section) is verified
> correct as *data* (loads cleanly via `demo_data.py`), but hasn't been
> exercised over the wire on this side since that schema change. See
> [`goimpl/README.md`](goimpl/README.md) for the maintained, working
> implementation.

## Schema

[node.asn](node.asn) defines:

- **`Node`** — a tree node: a `key` (UTF8String), an opaque `value`
  (OCTET STRING), and `firstChild`/`nextSibling` pointers.
- **`NodePointer`** — a `CHOICE` of `absolute` (a match-expression
  string) or `offset` (a signed integer, relative list position).
- **`Get`** — a request: a single `NodePointer` target.
- **`Response`** — a `SEQUENCE OF Node`: the flattened result of a
  `Get`.

A `Get`'s `absolute` target is a path/regexp expression:

```
expression = 1*( ["/"] key-regexp ["=" value-regexp] )
```

e.g. `/users/alice`, `/users/.*=admin`, `/config/timeout`. A literal
`/`, `=`, or `@` inside a regexp is escaped as `\/`, `\=`, `\@`.

The matched node(s) and their subtrees are flattened into pre-order and
returned as the `Response`. `firstChild`/`nextSibling` become `offset`
pointers (list-position deltas; `0` means "none"). If the full result
doesn't fit in one UDP datagram (see below), the response is truncated
and the pointer(s) that would have reached past the cut become
`absolute` **continuation** pointers of the form
`<original-expression>@<index>` — "re-run this same query and resume at
flattened position `<index>`". A client that follows every `absolute`
pointer it sees with a fresh `Get` ends up recovering the complete,
correctly-linked result across as many datagrams as it took.

## Setup

```bash
pip3 install -r requirements.txt
```

This installs [asn1tools](https://github.com/eerimoq/asn1tools), which
[common.py](common.py) uses to compile `node.asn` and BER-encode/decode
`Get`/`Response` values. (`asn1c`, the reference C compiler, is also
useful for validating the schema — see below — but isn't required to
run the demo.)

Validate the schema itself at any time with either tool:

```bash
# asn1c writes its generated C sources into the current directory, so
# run it somewhere scratch rather than in the repo root:
(cd "$(mktemp -d)" && asn1c -fcompound-names /path/to/node.asn)

python3 -c "import asn1tools; asn1tools.compile_files('node.asn', 'ber')"
```

## Running the demo

Start the server (listens on UDP `127.0.0.1:8514` by default):

```bash
python3 server.py
```

In another terminal, query it:

```bash
python3 client.py "/users"
python3 client.py "/users/user=alice"
python3 client.py "/config"
python3 client.py "/nonexistent"
```

### Demo data: plain JSON, tree derived from it

[demo_data.json](demo_data.json) is ordinary JSON — it has no idea of
"key"/"value"/"children" of its own:

```json
{
  "users": [
    {"user": "alice", "group": "admin"},
    {"user": "bob", "group": "user"},
    {"user": "carol", "group": "user"}
  ],
  "config": {
    "timeout": 30,
    "retries": 3
  }
}
```

[demo_data.py](demo_data.py) derives the `Node` tree from its structure
and attribute names alone (see its docstring for the full rule): an
object's properties each become a node keyed by the property name; an
array is *transparent* and adds no node of its own — each element
becomes node(s) reusing the array's own key, so an array of objects
becomes one sibling node per element (each with that element's own
properties as children), not one node listing them all. That turns the
JSON above into:

```
/
├── users
│   ├── user = "alice"
│   └── group = "admin"
├── users
│   ├── user = "bob"
│   └── group = "user"
├── users
│   ├── user = "carol"
│   └── group = "user"
└── config
    ├── timeout = "30"
    └── retries = "3"
```

The three `users` nodes are siblings of each other and of `config`, not
children of one shared "users" node — so `/users` matches all three
(and returns each one's full subtree), while `/users/user=alice`
matches only the `user` leaf of the first one.

### Real IF-MIB data under `/interfaces`

`demo_data.json` also carries a third, richer top-level key: `interfaces`,
23 records taken from a **real** `snmpbulkwalk` of IF-MIB's `ifTable`
(RFC 2863), run against a real, locally-started `snmpd` — not fabricated.
[`parse_ifmib_dump.py`](parse_ifmib_dump.py) turns the raw walk into
[`ifmib_dump.json`](ifmib_dump.json) (which is what got merged into
`demo_data.json`); its docstring documents the exact commands used, for
reproducibility. The only field not carried through verbatim is
`ifPhysAddress` — real MAC addresses are replaced with deterministic,
clearly-synthetic ones (the `02:00:00:xx:xx:xx` locally-administered
range) rather than exposing this machine's actual hardware addresses.
Every other field (interface name, type, MTU, speed, admin/oper status,
and every packet/octet/error counter) is the genuine captured value.

Since `demo_data.py`'s derivation is generic (driven entirely by JSON
structure and attribute names, not a fixed schema), this needed no new
code on the Python side — it's a good stress test of that design with
real-shaped data: 23 `interfaces` sibling nodes (one per network
interface), each with ~19 typed-looking fields as children (though on
this schema version every value is still an opaque string — see the
status note at the top of this README for where typed values live).

### Demoing truncation and continuations

The demo tree is small enough to fit in one datagram under any
real-world MSS, so truncation won't trigger on its own. Force a tiny
MSS on the server to see it in action:

```bash
python3 server.py --mss 90
python3 client.py "/users"
```

The client will show the response arriving in several batches, each one
following the continuation pointer from the last — here each batch
happens to be exactly one full user record (`users`, `user`, `group`):

```
-- response (3 node(s)) --
    key='users' value=b'' firstChild=+1 nextSibling=-> '/users@3'
    key='user' value=b'alice' firstChild=none nextSibling=+1
    key='group' value=b'admin' firstChild=none nextSibling=none
-- continuation of '/users@3' (3 node(s)) --
    key='users' value=b'' firstChild=+1 nextSibling=-> '/users@6'
    key='user' value=b'bob' firstChild=none nextSibling=+1
    key='group' value=b'user' firstChild=none nextSibling=none
-- continuation of '/users@6' (3 node(s)) --
    key='users' value=b'' firstChild=+1 nextSibling=none
    key='user' value=b'carol' firstChild=none nextSibling=+1
    key='group' value=b'user' firstChild=none nextSibling=none
```

Without `--mss`, the server tries to discover a real MSS from the
socket (`get_udp_mss()` in [common.py](common.py)): the path MTU via
`IP_MTU` where the OS exposes it (Linux), or a documented Ethernet-MTU
fallback where it doesn't (e.g. macOS, which has no UDP equivalent of
`IP_MTU`/`TCP_MAXSEG`).

### Reconstructing JSON and verifying the round trip

`client.py --json` collects every batch of a query (following every
continuation, however many it takes) and reconstructs a JSON value from
the resulting nodes — the inverse of the JSON -> Node derivation in
[demo_data.py](demo_data.py). Query `.*` to reconstruct the whole tree:

```bash
python3 client.py ".*" --json
```

`--compare` (which implies `--json`) additionally diffs that against a
reference JSON file, `demo_data.json` by default — a round-trip check
that what the server actually sent over the wire (however many
datagrams it took) reconstructs back to the source data:

```bash
python3 client.py ".*" --compare
# or, since --json/--compare default the expression to ".*":
python3 client.py --compare
```

```
MATCH: reconstructed JSON == demo_data.json (after stringifying its scalars -- the wire format carries no type tag)
```

This works even when the server had to split the response across many
datagrams — try it with `--mss 45` on the server, forcing a dozen-plus
round trips, and it still reconstructs and matches correctly.

Two things are worth knowing about the comparison:

- **The wire format has no type tag.** A `Node`'s `value` is an opaque
  `OCTET STRING`; a JSON number like `30` and the string `"30"` are
  indistinguishable once encoded. `--compare` accounts for this by
  stringifying the reference JSON's scalars the same way before
  diffing (`canonicalize_json_types()` in [common.py](common.py)), so
  a MISMATCH means an actual structural or value difference, not just
  a type difference.
- **A single-element array round-trips as a plain property**, since
  "this key occurred once" is all a flattened sibling list can convey
  — a real, inherent limitation of the derivation, not a bug (it
  doesn't affect the demo data: `users` always has 3 elements).

## On-the-wire packets

Both programs take `--pcap`, which prints a `tcpdump -X`-style hex dump
of each datagram's UDP payload as it's sent or received — the exact
bytes exchanged, in the exact order:

```bash
python3 server.py --mss 90 --pcap
python3 client.py "/users" --pcap
```

This is the **real captured output** from that exact command (the
sequence below is a `Get "/users"` truncated at `--mss 90` into three
request/response round trips, one user record per datagram):

```
19:43:52.416835 IP 127.0.0.1.58199 > 127.0.0.1.8514: UDP, length 12
	0x0000:  300a a008 8006 2f75 7365 7273            0...../users
19:43:52.417884 IP 127.0.0.1.8514 > 127.0.0.1.58199: UDP, length 81
	0x0000:  304f 301a 8005 7573 6572 7381 00a2 0381  0O0...users.....
	0x0010:  0101 a30a 8008 2f75 7365 7273 4033 3017  ....../users@30.
	0x0020:  8004 7573 6572 8105 616c 6963 65a2 0381  ..user..alice...
	0x0030:  0100 a303 8101 0130 1880 0567 726f 7570  .......0...group
	0x0040:  8105 6164 6d69 6ea2 0381 0100 a303 8101  ..admin.........
	0x0050:  00                                       .
19:43:52.417991 IP 127.0.0.1.58199 > 127.0.0.1.8514: UDP, length 14
	0x0000:  300c a00a 8008 2f75 7365 7273 4033       0...../users@3
19:43:52.418498 IP 127.0.0.1.8514 > 127.0.0.1.58199: UDP, length 78
	0x0000:  304c 301a 8005 7573 6572 7381 00a2 0381  0L0...users.....
	0x0010:  0101 a30a 8008 2f75 7365 7273 4036 3015  ....../users@60.
	0x0020:  8004 7573 6572 8103 626f 62a2 0381 0100  ..user..bob.....
	0x0030:  a303 8101 0130 1780 0567 726f 7570 8104  .....0...group..
	0x0040:  7573 6572 a203 8101 00a3 0381 0100       user..........
19:43:52.418572 IP 127.0.0.1.58199 > 127.0.0.1.8514: UDP, length 14
	0x0000:  300c a00a 8008 2f75 7365 7273 4036       0...../users@6
19:43:52.419018 IP 127.0.0.1.8514 > 127.0.0.1.58199: UDP, length 73
	0x0000:  3047 3013 8005 7573 6572 7381 00a2 0381  0G0...users.....
	0x0010:  0101 a303 8101 0030 1780 0475 7365 7281  .......0...user.
	0x0020:  0563 6172 6f6c a203 8101 00a3 0381 0101  .carol..........
	0x0030:  3017 8005 6772 6f75 7081 0475 7365 72a2  0...group..user.
	0x0040:  0381 0100 a303 8101 00                   .........
```

Decoding the first request (`30 0a a0 08 80 06 2f 75 73 65 72 73`) by
hand: `30 0a` is a `SEQUENCE` of 10 bytes (the `Get`). `a0 08` is
`Get.target`: context tag `[0]`, *explicit* (a `CHOICE`-typed field
can't be tagged implicitly, since it has no fixed tag of its own until
you know which alternative was picked) wrapping 8 bytes. Inside that,
`80 06 2f 75 73 65 72 73` is the `NodePointer` itself: context tag
`[0]`, *implicit* this time — the `absolute` alternative, 6 bytes:
`2f 75 73 65 72 73` = `/users`.

**Caveat:** this dump is the **UDP payload only**. It doesn't include
synthetic Ethernet/IP/UDP headers, because reconstructing those by hand
(checksums included) would be fabricated data presented as if
captured — this sandbox doesn't have BPF/raw-socket permission to
actually sniff the interface (`tcpdump: you don't have permission to
capture on that device`). For a real, full packet capture (with real IP
headers and checksums) on a machine where you do have that permission:

```bash
sudo tcpdump -i lo0 -n -X udp port 8514      # macOS loopback
sudo tcpdump -i lo -n -X udp port 8514       # Linux loopback
```

or capture to a file for Wireshark:

```bash
sudo tcpdump -i lo0 -n udp port 8514 -w nodetree.pcap
```

## Files

| File | Purpose |
|---|---|
| [node.asn](node.asn) | ASN.1 schema: `Node`, `NodePointer`, `Get`, `Response` |
| [common.py](common.py) | BER encode/decode, MSS discovery, expression parsing/matching, tree flattening, MSS-fit truncation, JSON reconstruction, pcap-style dump formatting |
| [demo_data.json](demo_data.json) | Sample data, as plain JSON (`users`/`config` toy data, plus a real IF-MIB `interfaces` capture) |
| [ifmib_dump.json](ifmib_dump.json) | The real IF-MIB capture on its own, as merged into `demo_data.json`'s `interfaces` key |
| [parse_ifmib_dump.py](parse_ifmib_dump.py) | Turns a raw `snmpbulkwalk` capture into `ifmib_dump.json` (MAC-anonymized); its docstring documents the exact capture commands |
| [demo_data.py](demo_data.py) | Derives the in-memory `Node` tree from `demo_data.json`'s structure and attribute names |
| [server.py](server.py) | UDP server: resolves `Get` requests against the demo tree |
| [client.py](client.py) | UDP client: sends a `Get`, follows continuation pointers, prints the result; `--json`/`--compare` reconstruct JSON and verify it against a reference file |
