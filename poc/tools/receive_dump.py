#!/usr/bin/env python3
"""Receive binary dump from PS4 via raw socket"""
import socket, struct, sys, os

HOST = "192.168.100.61"
PORT = 9026
SCRIPT = "/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/poc/send_binary.lua"
OUTPUT = "/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/dumps/libkernel.bin"

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data

def main():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    with open(SCRIPT, "rb") as f:
        lua_code = f.read()

    sock = socket.socket()
    sock.settimeout(60)
    sock.connect((HOST, PORT))
    print(f"[*] Connected to {HOST}:{PORT}")

    # Send script
    sock.sendall(struct.pack("<Q", len(lua_code)))
    sock.sendall(lua_code)
    print(f"[*] Sent {len(lua_code)} bytes of script")

    # Receive binary data
    result = b""
    done_marker = b"DONE_TRANSFER"
    buf = b""

    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        # Check for done marker
        if done_marker in buf:
            idx = buf.index(done_marker)
            result += buf[:idx]
            buf = buf[idx + len(done_marker):]
            print(f"[*] Transfer complete, received {len(result)} bytes")
            break
        else:
            # Check if buffer contains partial marker
            overlap = min(len(done_marker) - 1, len(buf))
            cutoff = len(buf) - overlap
            if cutoff > 0:
                result += buf[:cutoff]
                buf = buf[cutoff:]

    with open(OUTPUT, "wb") as f:
        f.write(result)
    print(f"[+] Saved to {OUTPUT}")
    sock.close()

if __name__ == "__main__":
    main()
