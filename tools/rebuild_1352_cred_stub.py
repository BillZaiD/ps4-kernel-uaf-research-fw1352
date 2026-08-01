#!/usr/bin/env python3
"""Reconstruct the embedded code stub that Poopsploit 13.52 writes into
kernel .text at base+0x415a43 (the 'ucred patcher'). The shellcode writes
overlapping/partial words, so we rebuild the byte image from the write
sequence, then disassemble it. r15 is the kernel cred pointer when this
stub is invoked (matches the 9.00-era public kstuff layout)."""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

img = bytearray(b"\x90" * 0x200)
base = 0x415a43

def w(off, data):
    for i, b in enumerate(data):
        img[off - base + i] = b

# word ptr [rcx+0x415a43], 0x6eb        -> eb 06
w(0x415a43, bytes([0xeb, 0x06]))
# qword [0x415a4b], 0x4a0bf8341         -> 41 83 bf a0 04 00 00 01  (cmp dword [r15+0x4a0],1)
w(0x415a4b, bytes.fromhex("4183bfa004000001"))
# dword [0x415a59]=0xd0878b49, word[0x415a5d]=4, byte[0x415a5f]=0
#   -> 49 8b 87 d0 04 00 00            = mov rax, [r15+0x4d0]
w(0x415a59, bytes.fromhex("498b87d0"))
w(0x415a5d, bytes([0x04, 0x00]))
w(0x415a5f, bytes([0x00]))
# dword [0x415a66]=0xb0b78b49, word[0x415a6a]=4, byte[0x415a6c]=0
#   -> 49 8b b7 b0 04 00 00            = mov rsi, [r15+0x4b0]
w(0x415a66, bytes.fromhex("498bb7b0"))
w(0x415a6a, bytes([0x04, 0x00]))
w(0x415a6c, bytes([0x00]))
# dword [0x415a7e]=0x40878b49, word[0x415a82]=5, byte[0x415a84]=0
#   -> 49 8b 87 40 05 00 00            = mov rax, [r15+0x540]
w(0x415a7e, bytes.fromhex("498b8740"))
w(0x415a82, bytes([0x05, 0x00]))
w(0x415a84, bytes([0x00]))
# dword [0x415a8b]=0x20b78b49, word[0x415a8f]=5, byte[0x415a91]=0
#   -> 49 8b b7 20 05 00 00            = mov rsi, [r15+0x520]
w(0x415a8b, bytes.fromhex("498bb720"))
w(0x415a8f, bytes([0x05, 0x00]))
w(0x415a91, bytes([0x00]))
# dword [0x415aa3]=0xc0bf8d49, word[0x415aa7]=0, byte[0x415aa9]=0
#   -> 49 8d bf c0 00 00 00            = lea rdi, [r15+0xc0]
w(0x415aa3, bytes.fromhex("498dbfc0"))
w(0x415aa7, bytes([0x00, 0x00]))
w(0x415aa9, bytes([0x00]))
# dword [0x415aaf]=0xe0bf8d49, word[0x415ab3]=0, byte[0x415ab5]=0
#   -> 49 8d bf e0 00 00 00            = lea rdi, [r15+0xe0]
w(0x415aaf, bytes.fromhex("498dbfe0"))
w(0x415ab3, bytes([0x00, 0x00]))
w(0x415ab5, bytes([0x00]))
# dword [0x415ac2]=0xbf8d49, word[0x415ac6]=1, byte[0x415ac8]=0
#   -> 49 8d bf 00 01 00 00            = lea rdi, [r15+0x100]
w(0x415ac2, bytes.fromhex("498dbf00"))
w(0x415ac6, bytes([0x01, 0x00]))
w(0x415ac8, bytes([0x00]))
# dword [0x415ace]=0x20bf8d49, word[0x415ad2]=1, byte[0x415ad4]=0
#   -> 49 8d bf 20 01 00 00            = lea rdi, [r15+0x120]
w(0x415ace, bytes.fromhex("498dbf20"))
w(0x415ad2, bytes([0x01, 0x00]))
w(0x415ad4, bytes([0x00]))
# word [0x415adf]=0x8b49, byte [0x415ae1]=0xff
#   -> 49 8b ff                         = mov rdi, r15
w(0x415adf, bytes([0x49, 0x8b]))
w(0x415ae1, bytes([0xff]))

md = Cs(CS_ARCH_X86, CS_MODE_64)
start = 0x415a43
print(f"Stub image @ base+0x415a43, {0x200} bytes (r15 = ucred)\n")
for i in md.disasm(bytes(img), start):
    if i.address >= start + 0x200:
        break
    print(f"{i.address:08x}: {i.mnemonic:8s} {i.op_str}")
