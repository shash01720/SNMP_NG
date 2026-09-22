#!/usr/bin/env python3
"""Reference server for the NodeTree GET protocol (see node.asn).

Listens on a UDP socket, decodes a BER-encoded `Get` datagram, evaluates
its NodePointer match expression against an in-memory node tree, and
replies with a BER-encoded `Response` datagram sized to fit the peer's
MSS. If the full result doesn't fit in one datagram, the response is
truncated to as many nodes as fit, and the pointer(s) that would have
reached past the cut are rewritten to an absolute continuation
NodePointer ("<expression>@<index>") the client can GET to resume.
"""
import argparse
import socketserver

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    build_response_for_mss,
    encode_message,
    decode_message,
    evaluate_pointer,
    flatten_matches,
    get_udp_mss,
    parse_expression,
    split_resume_suffix,
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

        base_expression, resume_index = split_resume_suffix(pointer_value)

        try:
            segments = parse_expression(base_expression)
            matches = evaluate_pointer(DEMO_TREE, segments)
        except ValueError as exc:
            print(f"[server] {peer}: bad expression: {exc}")
            sock.sendto(encode_message("Response", []), peer)
            return

        # Recomputed fresh (and deterministically) on every request, so
        # resume_index is a stable cursor with no server-side session state.
        wire_nodes = flatten_matches(matches)

        if resume_index < 0 or resume_index > len(wire_nodes):
            print(f"[server] {peer}: resume index {resume_index} out of "
                  f"range for {len(wire_nodes)} node(s); returning empty response")
            sock.sendto(encode_message("Response", []), peer)
            return

        mss = self.server.mss_override or get_udp_mss(peer)
        response, truncated = build_response_for_mss(
            wire_nodes, resume_index, mss, base_expression)
        encoded = encode_message("Response", response)

        status = "truncated" if truncated else "complete"
        print(f"[server] {peer}: {len(matches)} match(es), sending "
              f"{len(response)}/{len(wire_nodes) - resume_index} remaining "
              f"node(s) from index {resume_index} "
              f"({status}, mss={mss}, {len(encoded)} bytes)")
        sock.sendto(encoded, peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--mss", type=int, default=None,
                         help="Override the auto-detected MSS (bytes); "
                              "mainly for testing/demoing truncation.")
    args = parser.parse_args()

    with socketserver.ThreadingUDPServer((args.host, args.port), GetHandler) as server:
        server.mss_override = args.mss
        print(f"[server] listening on {args.host}:{args.port} (UDP)"
              + (f", mss override={args.mss}" if args.mss else ""))
        server.serve_forever()


if __name__ == "__main__":
    main()
