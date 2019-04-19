#!/usr/bin/env python3

import socket
import struct


def parse_ethernet(packet):
    (dest1, dest2, source1, source2, type_code) = struct.unpack('!IHHIH', packet[:14])
    data = packet[14:]

    if type_code == 0x8100:
        type_code = struct.unpack_from('!H', packet, 16)
        data = packet[18:]

    dest = (dest1 << 16) | dest2
    source = (source1 << 32) | source2
    dest_bytes = dest.to_bytes(6, byteorder='big')
    source_bytes = source.to_bytes(6, byteorder='big')
    dest_mac = ':'.join('{:02x}'.format(b) for b in dest_bytes)
    source_mac = ':'.join('{:02x}'.format(b) for b in source_bytes)

    return data, dest_mac, source_mac, type_code


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
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        (packet, address) = s.recvfrom(65565)
        (ethernet_data, dest_mac, source_mac, type_code) = parse_ethernet(packet)

        print('[ethernet]')
        print('Source MAC: {}\nDest MAC: {}\nType code: {}'.format(source_mac, dest_mac, type_code))

        if type_code == 0x800:
            (ip_header_length, ip_header, ip_data, total_length, protocol, source_address, dest_address) = parse_ip(ethernet_data)
            source_ip = socket.inet_ntoa(struct.pack('!I', source_address))
            dest_ip = socket.inet_ntoa(struct.pack('!I', dest_address))

            print('[ip]')
            print('Total length: {}\nProtocol: {}\nSource address: {}\nDest address: {}'.format(total_length, protocol, source_ip, dest_ip))

            if protocol == 17:
                (source_port, dest_port, data_length, checksum, data) = parse_udp(ip_data)

                print('[udp]')
                print('Source Port: {}\nDestination Port: {}\n'
                      'Data length: {}\nChecksum: {}'.format(
                          source_port, dest_port, data_length, checksum))

        print()

if __name__ == '__main__':
    main()
