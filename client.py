#!/usr/bin/env python3
"""Reference client for the NodeTree GET protocol (see node.asn).

Sends a `Get` datagram for the given NodePointer match expression over
UDP and prints the resulting `Response`.
"""
import argparse
import socket

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_DATAGRAM_SIZE,
    decode_message,
    encode_message,
)

TIMEOUT_SECONDS = 5.0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expression", help='NodePointer match expression, e.g. "/users/alice"')
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS)
    args = parser.parse_args()

    request = encode_message("Get", {"target": ("absolute", args.expression)})

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        sock.sendto(request, (args.host, args.port))
        try:
            data, _ = sock.recvfrom(MAX_DATAGRAM_SIZE)
        except socket.timeout:
            print(f"(no reply from {args.host}:{args.port} within {args.timeout}s)")
            return
    finally:
        sock.close()

    response = decode_message("Response", data)

    if not response:
        print("(no matches)")
        return

    for i, node in enumerate(response):
        _, fc_offset = node["firstChild"]
        _, ns_offset = node["nextSibling"]
        fc = "none" if fc_offset == 0 else f"+{fc_offset}"
        ns = "none" if ns_offset == 0 else f"+{ns_offset}"
        print(f"[{i}] key={node['key']!r} value={bytes(node['value'])!r} "
              f"firstChild={fc} nextSibling={ns}")


if __name__ == "__main__":
    main()
