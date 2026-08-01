import sys
import select
import socket
import struct
import time

MAGIC_VALUE = struct.pack('<Q', 0x13371337)
MAGIC_VALUE_LEN = len(MAGIC_VALUE)
SIGNAL_LEN = 16
MCONTEXT_LEN = 0x100

signals = {
    4: "SIGILL",
    10: "SIGBUS",
    11: "SIGSEGV",
}

def print_mcontext(buffer):
    fmt = "<QQQQQQQQQQQQQQQQIHHQIHHQQQQQQ"
    struct_buf = buffer[:struct.calcsize(fmt)]
    struct_data = struct.unpack(fmt, struct_buf)
    regs_name = [
        "onstack", "rdi", "rsi", "rdx", "rcx", 
        "r8", "r9", "rax", "rbx", "rbp", "r10",
        "r11", "r12", "r13", "r14", "r15", "trapno",
        "fs", "gs", "addr", "flags", "es", "ds", "err",
        "rip", "cs", "rflags", "rsp", "ss"
    ]
    regs = list(zip(regs_name, struct_data))
    print()
    for i in range(1, len(regs), 2):
        print("%5s: %016x  %7s: %016x" % (regs[i][0], regs[i][1], regs[i+1][0], regs[i+1][1]))
    print()

def process_crash_data(prefix, magic_data, mcontext_data):
    crash_code_data, crash_address_data = struct.unpack("<QQ", magic_data)
    crash_code = signals.get(crash_code_data, f"Unknown signal code {crash_code_data}")
    crash_address = f"0x{crash_address_data:016x}"
    print(prefix.decode("latin-1"))
    print(f"{crash_code} at {crash_address}")
    print_mcontext(mcontext_data)

def process_buffer(buffer):
    while True:
        if len(buffer) < MAGIC_VALUE_LEN:
            break
        magic_index = buffer.find(MAGIC_VALUE)
        if magic_index == -1:
            break
        if len(buffer) < magic_index + MAGIC_VALUE_LEN + SIGNAL_LEN + MCONTEXT_LEN:
            break
        start_index = magic_index + MAGIC_VALUE_LEN
        magic_data = buffer[start_index:start_index + SIGNAL_LEN]
        mcontext_data = buffer[start_index + SIGNAL_LEN : start_index + SIGNAL_LEN + MCONTEXT_LEN]
        process_crash_data(buffer[:magic_index], magic_data, mcontext_data)
        buffer = buffer[start_index + SIGNAL_LEN + MCONTEXT_LEN:]
    
    magic_index = buffer.find(MAGIC_VALUE)
    if magic_index == -1:
        print(buffer.decode("latin-1"), end="")
        buffer = b""
    return buffer

def send_payload(ip, port, filepath, timeout=180):
    with open(filepath, "rb") as file:
        data = file.read()
    
    print(f"Sending {len(data)} bytes from {filepath}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        print("Connected!")
        
        size = struct.pack("<Q", len(data))
        sock.sendall(size + data)
        print("Payload sent, waiting for response...")
        
        start = time.time()
        buffer = b""
        while time.time() - start < timeout:
            try:
                readable, _, _ = select.select([sock], [], [], 2.0)
                if readable:
                    chunk = sock.recv(4096)
                    if not chunk:
                        print(f"\nConnection closed after {time.time()-start:.1f}s")
                        break
                    buffer += chunk
                    buffer = process_buffer(buffer)
            except socket.timeout:
                print(f"\nTimeout after {time.time()-start:.1f}s")
                break
            except Exception as e:
                print(f"\nError: {e}")
                break
        
        if buffer:
            print(buffer.decode("latin-1"), end="")

if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2])
    filepath = sys.argv[3]
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 180
    send_payload(ip, port, filepath, timeout)
