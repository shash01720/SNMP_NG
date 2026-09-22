#!/usr/bin/env python3
"""Reference server for the NodeTree GET protocol (see node.asn).

Listens on a UDP socket, decodes a BER-encoded `Get` datagram, evaluates
its NodePointer match expression against an in-memory node tree, and
replies with a BER-encoded `Response` datagram.
"""
import argparse
import socketserver

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_DATAGRAM_SIZE,
    decode_message,
    encode_message,
    evaluate_pointer,
    flatten_matches,
    parse_expression,
)
from demo_data import DEMO_TREE


class GetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        peer = self.client_address

        try:
            get = decode_message("Get", data)
        except Exception as exc:  # malformed datagram
            print(f"[server] {peer}: bad Get message: {exc}")
            return

        pointer_type, pointer_value = get["target"]
        print(f"[server] {peer}: Get target={pointer_type}:{pointer_value!r}")

        if pointer_type != "absolute":
            print(f"[server] {peer}: offset pointers aren't resolvable "
                  f"from a client request; returning empty response")
            sock.sendto(encode_message("Response", []), peer)
            return

        try:
            segments = parse_expression(pointer_value)
            matches = evaluate_pointer(DEMO_TREE, segments)
        except ValueError as exc:
            print(f"[server] {peer}: bad expression: {exc}")
            sock.sendto(encode_message("Response", []), peer)
            return

        response = flatten_matches(matches)
        encoded = encode_message("Response", response)
        if len(encoded) > MAX_DATAGRAM_SIZE:
            print(f"[server] {peer}: response too large for one datagram "
                  f"({len(encoded)} bytes); returning empty response")
            sock.sendto(encode_message("Response", []), peer)
            return

        print(f"[server] {peer}: {len(matches)} match(es), "
              f"{len(response)} node(s) in response")
        sock.sendto(encoded, peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    with socketserver.ThreadingUDPServer((args.host, args.port), GetHandler) as server:
        print(f"[server] listening on {args.host}:{args.port} (UDP)")
        server.serve_forever()


if __name__ == "__main__":
    main()
