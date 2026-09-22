# NodeTree GET protocol

A small tree-structured key/value store and a GET protocol for querying
it, defined in ASN.1 ([node.asn](node.asn)) and implemented as a
reference UDP client/server in Python.

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
python3 client.py "/users/alice"
python3 client.py "/users/.*=user"
python3 client.py "/config"
python3 client.py "/nonexistent"
```

The demo data ([demo_data.json](demo_data.json)) is:

```
root
├── users
│   ├── alice = "admin"
│   ├── bob   = "user"
│   └── carol = "user"
└── config
    ├── timeout = "30"
    └── retries = "3"
```

### Demoing truncation and continuations

The demo tree is small enough to fit in one datagram under any
real-world MSS, so truncation won't trigger on its own. Force a tiny
MSS on the server to see it in action:

```bash
python3 server.py --mss 45
python3 client.py "/users"
```

The client will show the response arriving in several batches, each one
following the continuation pointer from the last, e.g.:

```
-- response (1 node(s)) --
    key='users' value=b'' firstChild=-> '/users@1' nextSibling=none
-- continuation of '/users@1' (1 node(s)) --
    key='alice' value=b'admin' firstChild=none nextSibling=-> '/users@2'
-- continuation of '/users@2' (1 node(s)) --
    key='bob' value=b'user' firstChild=none nextSibling=-> '/users@3'
-- continuation of '/users@3' (1 node(s)) --
    key='carol' value=b'user' firstChild=none nextSibling=none
```

Without `--mss`, the server tries to discover a real MSS from the
socket (`get_udp_mss()` in [common.py](common.py)): the path MTU via
`IP_MTU` where the OS exposes it (Linux), or a documented Ethernet-MTU
fallback where it doesn't (e.g. macOS, which has no UDP equivalent of
`IP_MTU`/`TCP_MAXSEG`).

## On-the-wire packets

Both programs take `--pcap`, which prints a `tcpdump -X`-style hex dump
of each datagram's UDP payload as it's sent or received — the exact
bytes exchanged, in the exact order:

```bash
python3 server.py --mss 45 --pcap
python3 client.py "/users" --pcap
```

This is the **real captured output** from that exact command (the
sequence below is a `Get "/users"` truncated at `--mss 45` into four
request/response round trips):

```
19:22:26.099963 IP 127.0.0.1.59596 > 127.0.0.1.8514: UDP, length 12
	0x0000:  300a a008 8006 2f75 7365 7273            0...../users
19:22:26.100746 IP 127.0.0.1.8514 > 127.0.0.1.59596: UDP, length 30
	0x0000:  301c 301a 8005 7573 6572 7381 00a2 0a80  0.0...users.....
	0x0010:  082f 7573 6572 7340 31a3 0381 0100       ./users@1.....
19:22:26.100808 IP 127.0.0.1.59596 > 127.0.0.1.8514: UDP, length 14
	0x0000:  300c a00a 8008 2f75 7365 7273 4031       0...../users@1
19:22:26.101150 IP 127.0.0.1.8514 > 127.0.0.1.59596: UDP, length 35
	0x0000:  3021 301f 8005 616c 6963 6581 0561 646d  0!0...alice..adm
	0x0010:  696e a203 8101 00a3 0a80 082f 7573 6572  in........./user
	0x0020:  7340 32                                  s@2
19:22:26.101218 IP 127.0.0.1.59596 > 127.0.0.1.8514: UDP, length 14
	0x0000:  300c a00a 8008 2f75 7365 7273 4032       0...../users@2
19:22:26.101560 IP 127.0.0.1.8514 > 127.0.0.1.59596: UDP, length 32
	0x0000:  301e 301c 8003 626f 6281 0475 7365 72a2  0.0...bob..user.
	0x0010:  0381 0100 a30a 8008 2f75 7365 7273 4033  ......../users@3
19:22:26.101611 IP 127.0.0.1.59596 > 127.0.0.1.8514: UDP, length 14
	0x0000:  300c a00a 8008 2f75 7365 7273 4033       0...../users@3
19:22:26.101960 IP 127.0.0.1.8514 > 127.0.0.1.59596: UDP, length 27
	0x0000:  3019 3017 8005 6361 726f 6c81 0475 7365  0.0...carol..use
	0x0010:  72a2 0381 0100 a303 8101 00              r..........
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
| [common.py](common.py) | BER encode/decode, MSS discovery, expression parsing/matching, tree flattening, MSS-fit truncation, pcap-style dump formatting |
| [demo_data.json](demo_data.json) | Sample tree data |
| [demo_data.py](demo_data.py) | Loads `demo_data.json` into the in-memory tree structure |
| [server.py](server.py) | UDP server: resolves `Get` requests against the demo tree |
| [client.py](client.py) | UDP client: sends a `Get`, follows continuation pointers, prints the result |
