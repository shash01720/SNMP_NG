#!/usr/bin/env python3
"""Reference client for the NodeTree GET protocol (see node.asn).

Sends a `Get` datagram for the given NodePointer match expression over
UDP and prints the resulting `Response`. If a node's firstChild or
nextSibling comes back as an absolute NodePointer (rather than an
offset), that means the server's answer was too big for one datagram
and the pointer is a continuation: this client automatically issues a
follow-up Get for it and keeps going until no continuations remain.
"""
import argparse
import socket

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_DATAGRAM_SIZE,
    decode_message,
    encode_message,
    format_packet_dump,
)

TIMEOUT_SECONDS = 5.0
MAX_FOLLOWUPS = 50  # loop guard against a cyclic/misbehaving server


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expression", help='NodePointer match expression, e.g. "/users/alice"')
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--pcap", action="store_true",
                         help="Print a tcpdump -X-style hex dump of each "
                              "datagram's UDP payload as it's sent/received.")
    args = parser.parse_args()
    addr = (args.host, args.port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, 0))  # pin a concrete local port for --pcap output
    try:
        seen = {args.expression}
        queue = [args.expression]
        total_nodes = 0
        followups = 0

        while queue:
            expression = queue.pop(0)
            response = send_get(sock, addr, expression, args.timeout, args.pcap)
            if response is None:
                print(f"(no reply for {expression!r} from "
                      f"{args.host}:{args.port} within {args.timeout}s)")
                continue

            label = "response" if expression == args.expression else f"continuation of {expression!r}"
            print_batch(label, response)
            total_nodes += len(response)

            for node in response:
                for field in ("firstChild", "nextSibling"):
                    ptr_type, ptr_value = node[field]
                    if ptr_type != "absolute":
                        continue
                    if ptr_value in seen:
                        continue
                    if followups >= MAX_FOLLOWUPS:
                        print(f"(hit MAX_FOLLOWUPS={MAX_FOLLOWUPS}, not "
                              f"following {ptr_value!r})")
                        continue
                    seen.add(ptr_value)
                    queue.append(ptr_value)
                    followups += 1

        if total_nodes == 0:
            print("(no matches)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
