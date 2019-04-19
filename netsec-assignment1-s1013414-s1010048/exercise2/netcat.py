#!/usr/bin/env python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
stringbuf = ''
for i in range(0, 1000):
    stringbuf = stringbuf + 'spam' + str(i) + '\n'
buf = stringbuf.encode('utf-8')
s.sendto(buf, ('localhost', 42424))
s.sendto(bytes(0), ('localhost', 42424))
s.close()
