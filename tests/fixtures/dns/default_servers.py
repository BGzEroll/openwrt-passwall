#!/usr/bin/env python3
"""UDP DNS fixtures: port 20531 answers 8.8.8.8, port 20532 answers 9.9.9.9.

Run on the HTTP_HOST test workstation for phase30-default-dns. Addresses are
synthetic response markers; no requests are sent to either public resolver.
"""

import selectors
import socket
import struct


def main():
    selector = selectors.DefaultSelector()
    for port, answer in [(20531, '8.8.8.8'), (20532, '9.9.9.9')]:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('0.0.0.0', port))
        selector.register(server, selectors.EVENT_READ, answer)

    while True:
        for key, _ in selector.select():
            packet, peer = key.fileobj.recvfrom(4096)
            end = 12
            while end < len(packet) and packet[end]:
                end += packet[end] + 1
            end += 1
            query_type, _ = struct.unpack('!HH', packet[end:end + 4])
            question = packet[12:end + 4]
            transaction = struct.unpack('!H', packet[:2])[0]
            response = struct.pack('!HHHHHH', transaction, 0x8180, 1, int(query_type == 1), 0, 0) + question
            if query_type == 1:
                response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(key.data)
            key.fileobj.sendto(response, peer)


if __name__ == '__main__':
    main()
