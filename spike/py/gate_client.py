#!/usr/bin/env python3
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10)
data = b""
while True:
    try:
        b = s.recv(65536)
    except socket.timeout:
        print("(timeout)"); break
    if not b: break
    data += b
print(data.decode(errors="replace"))
