#!/usr/bin/env python3

import socket
import struct


def parse_ip(packet):
    header_length = (packet[0] & 0x0f) * 4
    header = packet[:header_length]
    data = packet[header_length:]

    (total_length, protocol, source_address, dest_address) = struct.unpack('!xxHxxxxxBxxII', header[:20])

    return header_length, header, data, total_length, protocol, source_address, dest_address


def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (source_port, dest_port, data_length, checksum) = struct.unpack('!HHHH', header)

    return source_port, dest_port, data_length, checksum, data



def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    while True:
        (packet, address) = s.recvfrom(65565)
        (ip_header_length, ip_header, ip_data, total_length, protocol, source_address, dest_address) = parse_ip(packet)
        (source_port, dest_port, data_length, checksum, data) = parse_udp(ip_data)
        source_ip = socket.inet_ntoa(struct.pack('!I', source_address))
        dest_ip = socket.inet_ntoa(struct.pack('!I', dest_address))

        print('Source Port: {}\nDestination Port: {}\n'
              'Data length: {}\nChecksum: {}'.format(
                  source_port, dest_port, data_length, checksum))
        print('Total length: {}\nProtocol: {}\nSource: {}\nDest: {}\n'.format(total_length, protocol, source_ip, dest_ip))

if __name__ == '__main__':
    main()
