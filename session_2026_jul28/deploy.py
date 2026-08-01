#!/usr/bin/env python3
"""Deploy Lua script to PS4 remote loader and capture output"""
import sys, socket, struct, time, select

PS4 = "192.168.100.61"
PORT = 9026
TIMEOUT = 90

def deploy(script_path):
    with open(script_path, 'rb') as f:
        data = f.read()
    
    size = struct.pack('<Q', len(data))
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((PS4, PORT))
    sock.sendall(size + data)
    print(f"Sent {len(data)} bytes to {PS4}:{PORT}")
    
    buf = b''
    start = time.time()
    while time.time() - start < TIMEOUT:
        try:
            readable, _, _ = select.select([sock], [], [], 3.0)
            if readable:
                chunk = sock.recv(4096)
                if not chunk:
                    print("Connection closed by PS4")
                    break
                buf += chunk
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error: {e}")
            break
    
    sock.close()
    if buf:
        print("=== PS4 OUTPUT ===")
        print(buf.decode('latin-1', errors='replace'))
    else:
        print("No response")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: deploy.py <script.lua>")
        sys.exit(1)
    deploy(sys.argv[1])
