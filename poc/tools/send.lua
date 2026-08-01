#!/usr/bin/env python3
"""
PS4 Payload Sender
Sends Lua payloads to the Remote Lua Loader on PS4.

Usage:
    python3 send.lua <ps4_ip> <ps4_port> <lua_file>

Example:
    python3 send.lua 192.168.100.61 9026 poc/uaf_confirm.lua
"""

import socket
import sys
import os

def send_payload(ip, port, filepath):
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    with open(filepath, 'rb') as f:
        lua_code = f.read()
    
    # Protocol: [size:8bytes LE][lua_code]
    import struct
    size = struct.pack('<Q', len(lua_code))
    payload = size + lua_code
    
    print(f"[*] Sending {len(lua_code)} bytes from {filepath}")
    print(f"[*] Target: {ip}:{port}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((ip, port))
        print("[+] Connected")
        sock.sendall(payload)
        print("[+] Payload sent")
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        if response:
            print("[+] Response:")
            print(response.decode('utf-8', errors='replace'))
        else:
            print("[*] No response (timeout)")
    
    except ConnectionRefusedError:
        print("[-] Connection refused - is the Lua loader running?")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <ps4_ip> <ps4_port> <lua_file>")
        sys.exit(1)
    
    send_payload(sys.argv[1], int(sys.argv[2]), sys.argv[3])
