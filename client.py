#!/usr/bin/env python3
"""Reference client for the NodeTree GET protocol (see node.asn).

Sends a `Get` datagram for the given NodePointer match expression over
UDP and prints the resulting `Response`. If a node's firstChild or
nextSibling comes back as an absolute NodePointer (rather than an
offset), that means the server's answer was too big for one datagram
and the pointer is a continuation: this client automatically issues a
follow-up Get for it and keeps going until no continuations remain.

--json reconstructs a JSON value from the collected nodes (inverting
demo_data.py's JSON -> Node derivation); --compare additionally checks
that against a reference JSON file (demo_data.json by default). Query
".*" to cover the whole tree, e.g.:

    python3 client.py ".*" --compare
"""
import argparse
import difflib
import json
import socket
from pathlib import Path

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_DATAGRAM_SIZE,
    canonicalize_json_types,
    decode_message,
    encode_message,
    format_packet_dump,
    reconstruct_json,
    split_resume_suffix,
    unflatten,
)

TIMEOUT_SECONDS = 5.0
MAX_FOLLOWUPS = 50  # loop guard against a cyclic/misbehaving server
DEFAULT_COMPARE_PATH = Path(__file__).parent / "demo_data.json"


def send_get(sock, addr, expression, timeout, pcap=False):
    request = encode_message("Get", {"target": ("absolute", expression)})
    local = sock.getsockname()
    if pcap:
        print(format_packet_dump("send", local, addr, request))

    sock.settimeout(timeout)
    sock.sendto(request, addr)
    try:
        data, _ = sock.recvfrom(MAX_DATAGRAM_SIZE)
    except socket.timeout:
        return None

    if pcap:
        print(format_packet_dump("recv", local, addr, data))
    return decode_message("Response", data)


def collect_responses(sock, addr, expression, timeout, pcap, on_batch):
    """Send `expression`, following every absolute continuation pointer
    found in each Response, calling on_batch(expr, start_index,
    response) for each batch as it arrives. Returns False if any
    request timed out (so the caller knows the result may be
    incomplete), True otherwise."""
    seen = {expression}
    queue = [expression]
    followups = 0
    complete = True

    while queue:
        expr = queue.pop(0)
        response = send_get(sock, addr, expr, timeout, pcap)
        if response is None:
            print(f"(no reply for {expr!r} from {addr[0]}:{addr[1]} within {timeout}s)")
            complete = False
            continue

        _, start_index = split_resume_suffix(expr)
        on_batch(expr, start_index, response)

        for node in response:
            for field in ("firstChild", "nextSibling"):
                ptr_type, ptr_value = node[field]
                if ptr_type != "absolute" or ptr_value in seen:
                    continue
                if followups >= MAX_FOLLOWUPS:
                    print(f"(hit MAX_FOLLOWUPS={MAX_FOLLOWUPS}, not following {ptr_value!r})")
                    continue
                seen.add(ptr_value)
                queue.append(ptr_value)
                followups += 1

    return complete


def print_batch(label, response):
    print(f"-- {label} ({len(response)} node(s)) --")
    for node in response:
        fc_type, fc = node["firstChild"]
        ns_type, ns = node["nextSibling"]
        fc_str = "none" if (fc_type == "offset" and fc == 0) else (
            f"+{fc}" if fc_type == "offset" else f"-> {fc!r}")
        ns_str = "none" if (ns_type == "offset" and ns == 0) else (
            f"+{ns}" if ns_type == "offset" else f"-> {ns!r}")
        print(f"    key={node['key']!r} value={bytes(node['value'])!r} "
              f"firstChild={fc_str} nextSibling={ns_str}")


def run_plain(sock, addr, args):
    total_nodes = 0

    def on_batch(expr, start_index, response):
        nonlocal total_nodes
        label = "response" if expr == args.expression else f"continuation of {expr!r}"
        print_batch(label, response)
        total_nodes += len(response)

    collect_responses(sock, addr, args.expression, args.timeout, args.pcap, on_batch)
    if total_nodes == 0:
        print("(no matches)")


def run_json(sock, addr, args):
    combined = {}

    def on_batch(expr, start_index, response):
        for offset, node in enumerate(response):
            combined[start_index + offset] = node

    complete = collect_responses(sock, addr, args.expression, args.timeout, args.pcap, on_batch)
    if not complete:
        print("(some requests timed out -- reconstruction may be missing data)")

    try:
        nodes = unflatten(combined)
    except ValueError as exc:
        print(f"(cannot reconstruct JSON: {exc})")
        return

    reconstructed = reconstruct_json(nodes)
    print(json.dumps(reconstructed, indent=2, sort_keys=True))

    if args.compare is not None:
        compare_path = Path(args.compare) if args.compare else DEFAULT_COMPARE_PATH
        with open(compare_path, "r", encoding="utf-8") as f:
            reference = json.load(f)
        # The wire format has no type tag: every scalar comes back as a
        # string, so numbers/booleans/null in the reference are
        # stringified the same way before comparing (see
        # canonicalize_json_types's docstring).
        canonical_reference = canonicalize_json_types(reference)

        print()
        if reconstructed == canonical_reference:
            print(f"MATCH: reconstructed JSON == {compare_path.name} "
                  f"(after stringifying its scalars -- the wire format "
                  f"carries no type tag)")
        else:
            print(f"MISMATCH vs {compare_path.name} (after stringifying its scalars):")
            reconstructed_lines = json.dumps(reconstructed, indent=2, sort_keys=True).splitlines(keepends=True)
            reference_lines = json.dumps(canonical_reference, indent=2, sort_keys=True).splitlines(keepends=True)
            diff = difflib.unified_diff(
                reference_lines, reconstructed_lines,
                fromfile=str(compare_path), tofile="reconstructed", lineterm="")
            for line in diff:
                print(line, end="" if line.endswith("\n") else "\n")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("expression", nargs="?",
                         help='NodePointer match expression, e.g. "/users/user=alice". '
                              'Defaults to ".*" (everything) when --json/--compare is used.')
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--pcap", action="store_true",
                         help="Print a tcpdump -X-style hex dump of each "
                              "datagram's UDP payload as it's sent/received.")
    parser.add_argument("--json", action="store_true",
                         help="Reconstruct and print a JSON value from the "
                              "collected nodes instead of listing them.")
    parser.add_argument("--compare", nargs="?", const="", default=None, metavar="PATH",
                         help="Reconstruct JSON (implies --json) and compare it "
                              "against PATH (default: demo_data.json next to this script).")
    args = parser.parse_args()

    if args.compare is not None:
        args.json = True
    if args.expression is None:
        if not args.json:
            parser.error("expression is required unless --json/--compare is given")
        args.expression = ".*"

    addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, 0))  # pin a concrete local port for --pcap output
    try:
        if args.json:
            run_json(sock, addr, args)
        else:
            run_plain(sock, addr, args)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
