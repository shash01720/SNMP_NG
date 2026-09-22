"""Shared plumbing for the NodeTree GET protocol client and server.

Wire format: each message is a 4-byte big-endian length prefix followed
by that many bytes of BER encoding of a `Get` or `Response` value from
node.asn.
"""
import re
import struct
from pathlib import Path

import asn1tools

SPEC_PATH = Path(__file__).parent / "node.asn"
SPEC = asn1tools.compile_files(str(SPEC_PATH), "ber")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8514


# --- framing -----------------------------------------------------------

def send_message(sock, type_name, value):
    encoded = SPEC.encode(type_name, value)
    sock.sendall(struct.pack(">I", len(encoded)) + encoded)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock, type_name):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    encoded = recv_exact(sock, length)
    return SPEC.decode(type_name, encoded)


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
# otherwise meaningless). Separate matches are flattened independently
# and never linked to each other, even if they happen to be siblings in
# the source tree.

def flatten_matches(matches):
    result = []
    for match in matches:
        result.extend(_flatten_subtree(match))
    return result


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
