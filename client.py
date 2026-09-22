#!/usr/bin/env python3
"""Reference client for the NodeTree GET protocol (see node.asn).

Sends a `Get` message for the given NodePointer match expression and
prints the resulting `Response`.
"""
import argparse
import socket

from common import DEFAULT_HOST, DEFAULT_PORT, recv_message, send_message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expression", help='NodePointer match expression, e.g. "/users/alice"')
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port)) as sock:
        send_message(sock, "Get", {"target": ("absolute", args.expression)})
        response = recv_message(sock, "Response")

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
