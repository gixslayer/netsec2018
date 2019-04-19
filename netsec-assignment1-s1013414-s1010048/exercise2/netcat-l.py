#!/usr/bin/env python3

import socket


def handlestring(datastring, length, delimiter):
    stringlist = datastring.split(sep=delimiter)
    filteredlist = []
    for string in stringlist:
        filteredlist.append(string[length:])
    filteredstring = delimiter.join(filteredlist)

    return filteredstring


def handle(passedconn):
    data = b''

    newdata = passedconn.recv(size)
    while newdata and len(newdata) != 0:
        data += newdata
        newdata = passedconn.recv(size)

    if data:
        datastring = data.decode('utf-8')
        print(handlestring(datastring, len('spam'), '\n'))


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))

    for i in range(3):
        handle(s)

    s.close()


if __name__ == '__main__':
    host = 'localhost'
    port = 42424
    size = 65536
    main()
