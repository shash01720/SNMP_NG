#!/usr/bin/env python3
"""Reference server for the NodeTree GET protocol (see node.asn).

Listens on a TCP socket, decodes a length-prefixed BER-encoded `Get`
message, evaluates its NodePointer match expression against an
in-memory node tree, and replies with a length-prefixed BER-encoded
`Response`.
"""
import argparse
import socketserver

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    evaluate_pointer,
    flatten_matches,
    parse_expression,
    recv_message,
    send_message,
)
from demo_data import DEMO_TREE


class GetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address
        try:
            get = recv_message(self.request, "Get")
        except EOFError as exc:
            print(f"[server] {peer}: {exc}")
            return

        pointer_type, pointer_value = get["target"]
        print(f"[server] {peer}: Get target={pointer_type}:{pointer_value!r}")

        if pointer_type != "absolute":
            print(f"[server] {peer}: offset pointers aren't resolvable "
                  f"from a client request; returning empty response")
            send_message(self.request, "Response", [])
            return

        try:
            segments = parse_expression(pointer_value)
            matches = evaluate_pointer(DEMO_TREE, segments)
        except ValueError as exc:
            print(f"[server] {peer}: bad expression: {exc}")
            send_message(self.request, "Response", [])
            return

        response = flatten_matches(matches)
        print(f"[server] {peer}: {len(matches)} match(es), "
              f"{len(response)} node(s) in response")
        send_message(self.request, "Response", response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((args.host, args.port), GetHandler) as server:
        print(f"[server] listening on {args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
