"""Shared plumbing for the NodeTree GET protocol client and server.

Wire format: each message is a single UDP datagram containing the BER
encoding of a `Get` or `Response` value from node.asn. UDP preserves
datagram boundaries, so no length prefix is needed -- but a `Response`
that doesn't fit in one datagram (see MSS below) has to be split, with
continuation NodePointers, rather than sent as one oversized packet.
"""
from pathlib import Path
import re
import socket
import time

import asn1tools

SPEC_PATH = Path(__file__).parent / "node.asn"
SPEC = asn1tools.compile_files(str(SPEC_PATH), "ber")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8514

# Practical upper bound for a UDP payload that won't be fragmented (and
# safely under the 65507-byte theoretical max for IPv4).
MAX_DATAGRAM_SIZE = 65507

IP_HEADER_SIZE = 20   # IPv4 header, no options
UDP_HEADER_SIZE = 8

# Used when the OS can't tell us a path MTU (see get_udp_mss): the
# ordinary Ethernet MTU, which is a reasonable, widely-safe assumption.
FALLBACK_MTU = 1500


# --- framing -----------------------------------------------------------

def encode_message(type_name, value):
    return SPEC.encode(type_name, value)


def decode_message(type_name, data):
    return SPEC.decode(type_name, data)


# --- packet-capture-style dumps (--pcap) ----------------------------------
#
# A tcpdump -X-style dump of one real UDP datagram, for eyeballing what's
# actually on the wire. This can only show the UDP *payload* (the BER
# bytes this process itself sent or received) -- it doesn't synthesize
# Ethernet/IP/UDP headers, since those would have to be fabricated
# without an OS-level capture (see README.md for a real tcpdump command).

def format_packet_dump(direction, local_addr, remote_addr, payload):
    src, dst = (local_addr, remote_addr) if direction == "send" else (remote_addr, local_addr)
    now = time.time()
    ts = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now * 1e6) % 1000000:06d}"
    lines = [f"{ts} IP {src[0]}.{src[1]} > {dst[0]}.{dst[1]}: UDP, length {len(payload)}"]
    for offset in range(0, len(payload), 16):
        chunk = payload[offset:offset + 16]
        pairs = [chunk[i:i + 2].hex() for i in range(0, len(chunk), 2)]
        hex_str = " ".join(pairs).ljust(39)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"\t0x{offset:04x}:  {hex_str}  {ascii_str}")
    return "\n".join(lines)


# --- MSS discovery ---------------------------------------------------------
#
# UDP has no MSS concept the way TCP does (there's no TCP_MAXSEG
# equivalent) -- the closest analogue is the path MTU minus the IP and
# UDP header sizes. Linux exposes the current path MTU for a connected
# socket via getsockopt(IPPROTO_IP, IP_MTU); most other platforms
# (including macOS) don't expose it via the socket API at all, so this
# falls back to FALLBACK_MTU on those.

def get_udp_mss(peer_addr):
    """Best-effort maximum Response payload size (bytes) for a peer."""
    mtu = None
    ip_mtu = getattr(socket, "IP_MTU", None)
    if ip_mtu is not None:
        family = socket.AF_INET6 if ":" in peer_addr[0] else socket.AF_INET
        probe = socket.socket(family, socket.SOCK_DGRAM)
        try:
            probe.connect(peer_addr)
            mtu = probe.getsockopt(socket.IPPROTO_IP, ip_mtu)
        except OSError:
            mtu = None
        finally:
            probe.close()

    if not mtu:
        mtu = FALLBACK_MTU

    mss = mtu - IP_HEADER_SIZE - UDP_HEADER_SIZE
    return max(min(mss, MAX_DATAGRAM_SIZE), 0)


# --- NodePointer match-expression parsing -------------------------------
#
#   expression = 1*( ["/"] key-regexp ["=" value-regexp] )
#
# "/" separates segments (a leading one is optional/ignored, since there
# is a single implicit root); "=" separates a segment's key regexp from
# its optional value regexp. A literal "/" or "=" inside a regexp is
# written "\/" or "\=".

def parse_expression(expression):
    segments = []
    for part in _split_unescaped(expression, "/"):
        if part == "":
            continue  # a leading (or doubled) "/" produces an empty part
        key_raw, has_value, value_raw = _split_first_unescaped(part, "=")
        key_re = re.compile(key_raw)
        value_re = re.compile(value_raw) if has_value else None
        segments.append((key_re, value_re))
    if not segments:
        raise ValueError("empty NodePointer expression")
    return segments


def _split_unescaped(s, delim):
    """Split s on unescaped occurrences of delim. "\\<delim>" and "\\\\"
    collapse to the literal character; any other backslash sequence
    (e.g. a regexp escape like "\\d") is passed through untouched."""
    parts = []
    buf = ""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in (delim, "\\"):
            buf += s[i + 1]
            i += 2
            continue
        if c == delim:
            parts.append(buf)
            buf = ""
            i += 1
            continue
        buf += c
        i += 1
    parts.append(buf)
    return parts


def _split_first_unescaped(s, delim):
    """Like _split_unescaped but stops at the first delim, returning
    (before, found, after)."""
    buf = ""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in (delim, "\\"):
            buf += s[i + 1]
            i += 2
            continue
        if c == delim:
            return buf, True, s[i + 1:]
        buf += c
        i += 1
    return buf, False, ""


# A request is `expression ["@" resume-index]`: the optional suffix names
# a zero-based index into `expression`'s own full, deterministic
# flattened result to resume from (used for continuations -- see
# build_response_for_mss). A literal "@" inside a regexp must be written
# "\@", same as "/" and "=".

def split_resume_suffix(raw_expression):
    before, found, after = _split_first_unescaped(raw_expression, "@")
    if found and after.isdigit():
        return before, int(after)
    return raw_expression, 0


# --- tree evaluation -----------------------------------------------------

def evaluate_pointer(root, segments):
    """Walk `root`'s children matching each segment in turn; returns the
    list of nodes matched by the final segment."""
    current = [root]
    for key_re, value_re in segments:
        nxt = []
        for node in current:
            for child in node["children"]:
                if not key_re.fullmatch(child["key"]):
                    continue
                if value_re is not None:
                    value_text = child["value"].decode("utf-8", "replace")
                    if not value_re.fullmatch(value_text):
                        continue
                nxt.append(child)
        current = nxt
    return current


# --- flattening matched subtrees into wire Nodes --------------------------
#
# Each matched node (with its full subtree) is flattened into pre-order
# and encoded as a run of Node values inside the Response SEQUENCE OF.
# firstChild/nextSibling become offset NodePointers: the signed distance
# (in list positions) to the target Node. An offset of 0 is a sentinel
# meaning "no child" / "no next sibling" (a self-referencing offset is
# otherwise meaningless).
#
# When an expression matches more than one top-level node (e.g. a
# wildcard key regexp), each match's own subtree is flattened
# independently and the match roots are then chained to each other via
# nextSibling, in match order -- even though they usually aren't real
# tree-siblings. Without this, a later match that gets left out by MSS
# truncation would have nothing pointing to it and would just silently
# go missing from the response instead of getting a continuation.

def flatten_matches(matches):
    wire_nodes = []
    block_starts = []
    for match in matches:
        block_starts.append(len(wire_nodes))
        wire_nodes.extend(_flatten_subtree(match))

    for i in range(len(block_starts) - 1):
        root_index = block_starts[i]
        next_root_index = block_starts[i + 1]
        wire_nodes[root_index]["nextSibling"] = ("offset", next_root_index - root_index)

    return wire_nodes


def _flatten_subtree(root):
    order = []
    parent_of = {}
    sibling_index = {}

    def visit(node, parent):
        order.append(node)
        parent_of[id(node)] = parent
        for idx, child in enumerate(node["children"]):
            sibling_index[id(child)] = idx
        for child in node["children"]:
            visit(child, node)

    visit(root, None)
    index_of = {id(node): i for i, node in enumerate(order)}

    wire_nodes = []
    for i, node in enumerate(order):
        if node["children"]:
            first_child_offset = index_of[id(node["children"][0])] - i
        else:
            first_child_offset = 0

        next_sibling_offset = 0
        parent = parent_of[id(node)]
        if parent is not None:
            pos = sibling_index[id(node)]
            siblings = parent["children"]
            if pos + 1 < len(siblings):
                next_sibling_offset = index_of[id(siblings[pos + 1])] - i

        wire_nodes.append({
            "key": node["key"],
            "value": node["value"],
            "firstChild": ("offset", first_child_offset),
            "nextSibling": ("offset", next_sibling_offset),
        })
    return wire_nodes


# --- fitting a Response into MSS bytes ------------------------------------
#
# `wire_nodes` is `base_expression`'s full, deterministic flatten -- the
# server recomputes exactly the same array on every request for the same
# base_expression, so a *position* in it (a resume index) is a stable,
# stateless cursor; nothing needs to be remembered between requests.
#
# Offsets are deltas (target index - current index) so they stay valid
# wherever a contiguous run of them ends up, but a node included in this
# response can point past the window actually sent. When that happens,
# that field is rewritten from an offset to an absolute continuation
# NodePointer: `base_expression@target_index`. Resuming there replays the
# same flatten and continues from exactly that position, so later
# siblings/children stay reachable across as many continuations as it
# takes -- unlike pointing at the target node alone, which would lose
# its siblings by re-matching it as a fresh, independent query.

def build_response_for_mss(wire_nodes, resume_index, mss, base_expression):
    """Return (response, truncated): the largest run of
    wire_nodes[resume_index:] (with dangling offsets rewritten to
    absolute continuation pointers) whose Response encoding fits in
    `mss` bytes."""
    window_total = len(wire_nodes) - resume_index
    for n in range(window_total, 0, -1):
        candidate = _fixup_window(wire_nodes, resume_index, n, base_expression)
        encoded = encode_message("Response", candidate)
        if len(encoded) <= mss:
            return candidate, n < window_total
    return [], window_total > 0


def _fixup_window(wire_nodes, resume_index, n, base_expression):
    end_global = resume_index + n
    included = [dict(node) for node in wire_nodes[resume_index:end_global]]
    for j, node in enumerate(included):
        i_global = resume_index + j
        for field in ("firstChild", "nextSibling"):
            ptr_type, offset = node[field]
            if ptr_type != "offset" or offset == 0:
                continue  # not a pointer, or the "none" sentinel
            target_global = i_global + offset
            if target_global >= end_global:
                node[field] = ("absolute", f"{base_expression}@{target_global}")
    return included


# --- reconstructing JSON from a fully-resolved flat node array -----------
#
# The client (see client.py --json/--compare) gathers every batch of a
# query -- following every continuation -- into `combined`: a dict
# mapping global flattened index -> wire node, with every firstChild/
# nextSibling now a plain in-range offset (no leftover absolute
# continuation pointers). unflatten() rebuilds real nested (key, value,
# children) node objects from that; reconstruct_json() then inverts
# demo_data.py's JSON -> Node derivation.

def unflatten(combined):
    """Rebuild nested node objects from `combined`. Returns the list of
    top-level sibling nodes (the chain starting at global index 0).

    A pointer here is either a plain ("offset", delta) -- resolved by
    arithmetic against its own index -- or a leftover ("absolute",
    "<base>@<target_idx>") continuation pointer that was never replaced
    with its resolved offset after fetching; that target_idx *is* the
    target's global index directly, so it's used as-is (as long as that
    index was actually fetched into `combined`)."""

    def resolve_target(idx, pointer):
        ptr_type, ptr_value = pointer
        if ptr_type == "offset":
            return idx + ptr_value if ptr_value != 0 else None
        _, target_idx = split_resume_suffix(ptr_value)
        if target_idx not in combined:
            raise ValueError(f"node {idx}: continuation target {target_idx} was never fetched")
        return target_idx

    def build(idx):
        wire = combined[idx]
        child_start = resolve_target(idx, wire["firstChild"])
        children = walk_siblings(child_start) if child_start is not None else []
        return {"key": wire["key"], "value": bytes(wire["value"]), "children": children}

    def walk_siblings(start):
        nodes = []
        idx = start
        while idx is not None:
            nodes.append(build(idx))
            idx = resolve_target(idx, combined[idx]["nextSibling"])
        return nodes

    return walk_siblings(0) if combined else []


def reconstruct_json(nodes):
    """Invert demo_data.py's JSON -> Node derivation over a list of
    sibling node objects (as produced by unflatten(), or a node's own
    "children"): a key occurring once becomes a plain property; a key
    occurring more than once becomes a JSON array -- the mirror image
    of an array of elements becoming repeated sibling nodes there.

    Every leaf value comes back as a *string*: the wire format's OCTET
    STRING carries no type tag, so a JSON number/boolean/null that went
    in comes back as its string form, not its original type. Use
    canonicalize_json_types() on a real JSON source before comparing it
    against this function's output.

    Also not recoverable: an array with exactly one element is
    indistinguishable from a plain scalar/object property (both look
    like "this key occurred once").
    """
    groups = {}
    order = []
    for node in nodes:
        key = node["key"]
        if node["children"]:
            value = reconstruct_json(node["children"])
        else:
            value = node["value"].decode("utf-8", "replace")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(value)
    return {key: (groups[key][0] if len(groups[key]) == 1 else groups[key]) for key in order}


def canonicalize_json_types(value):
    """Recursively stringify scalars the way the Node wire format does
    (see reconstruct_json's docstring), so a real JSON source can be
    compared against reconstructed output on equal terms."""
    if isinstance(value, dict):
        return {k: canonicalize_json_types(v) for k, v in value.items()}
    if isinstance(value, list):
        return [canonicalize_json_types(v) for v in value]
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
