#!/usr/bin/env python3
"""Regenerates testdata_fixtures.json from ../../../node.asn using the
project's Python/BER tooling (asn1tools) -- the independent reference
encoding that codec_test.go checks this Go codec's output against.

Run from anywhere; paths below are relative to this file.

    python3 generate_fixtures.py
"""
import json
import struct
from pathlib import Path

import asn1tools

HERE = Path(__file__).parent
NODE_ASN = HERE / ".." / ".." / ".." / "node.asn"
OUT = HERE / "testdata_fixtures.json"

spec = asn1tools.compile_files(str(NODE_ASN), "ber")


def real_bytes(f):
    return struct.pack(">d", f)


node = {
    "key": "alice",
    "value": ("octetString", b"admin"),
    "firstChild": ("none", None),
    "nextSibling": ("offset", 1),
}

cases = {
    "NodeValue_integer32": ("NodeValue", ("integer32", -42)),
    "NodeValue_unsigned32": ("NodeValue", ("unsigned32", 42)),
    "NodeValue_counter64": ("NodeValue", ("counter64", 18000000000000000000)),
    "NodeValue_octetString": ("NodeValue", ("octetString", b"hello")),
    "NodeValue_real": ("NodeValue", ("real", real_bytes(3.14159))),
    "NodeValue_noValue": ("NodeValue", ("noValue", None)),
    "NodePointer_none": ("NodePointer", ("none", None)),
    "NodePointer_absolute": ("NodePointer", ("absolute", "/users")),
    "NodePointer_offset": ("NodePointer", ("offset", 5)),
    "Node_alice": ("Node", node),
    "Get_1": ("Get", {"sequenceNumber": 1, "target": ("absolute", "/users")}),
    "Set_1": (
        "Set",
        {
            "sequenceNumber": 2,
            "target": ("absolute", "/users/user=alice"),
            "newValue": ("octetString", b"root"),
            "newFirstChild": ("none", None),
        },
    ),
    "Create_1": ("Create", {"sequenceNumber": 3, "key": "note", "value": ("octetString", b"hi")}),
    "Create_2": ("Create", {"sequenceNumber": 4, "key": "container"}),
    "AggregationMethod_percentile": ("AggregationMethod", ("percentile", 95)),
    "AggregationMethod_mean": ("AggregationMethod", ("mean", None)),
    "Query_1": (
        "Query",
        {
            "sequenceNumber": 5,
            "nodeExpression": "/config/timeout",
            "collectionMode": ("interval", 300),
            "aggregationInterval": 600,
            "aggregationMethod": ("mean", None),
            "transferInterval": 6000,
        },
    ),
    "Query_once": (
        "Query",
        {
            "sequenceNumber": 6,
            "nodeExpression": "/config/timeout",
            "collectionMode": ("once", None),
            "transferInterval": 0,
        },
    ),
    "Query_onChange": (
        "Query",
        {
            "sequenceNumber": 9,
            "nodeExpression": "/interfaces/ifOperStatus",
            "collectionMode": ("onChange", None),
            "transferInterval": 5,
        },
    ),
    "Response_ok": ("Response", {"sequenceNumber": 7, "inReplyTo": 1, "error": False, "nodes": [node]}),
    "Response_error": (
        "Response",
        {
            "sequenceNumber": 8,
            "inReplyTo": 2,
            "error": True,
            "errorNode": ("absolute", "/Sessions/Connection-ID\\=abc/Errors/NoSuchNode"),
            "nodes": [],
        },
    ),
    "SummaryAck_1": ("SummaryAck", {"received": [{"first": 0, "last": 5}, {"first": 8, "last": 8}]}),
    "NodeTreeMessage_get": ("NodeTreeMessage", ("get", {"sequenceNumber": 1, "target": ("absolute", "/users")})),
    "NodeTreeMessage_summaryAck": ("NodeTreeMessage", ("summaryAck", {"received": [{"first": 0, "last": 3}]})),
}

out = {}
for name, (type_name, value) in cases.items():
    enc = spec.encode(type_name, value)
    out[name] = {"type": type_name, "hex": enc.hex()}

with open(OUT, "w") as f:
    json.dump(out, f, indent=2)
print(f"wrote {len(out)} fixtures to {OUT}")
