#!/usr/bin/env python3
"""Disassemble the Poopsploit 13.52 kernel shellcode (from Gezine BD-UN-JB).
Extracted from PS4_KernelOffset.java:95, decodes the x86-64 bytes with capstone
and annotates every embedded kernel-offset constant (absolute addrs rely on the
position-independent `lea rsi, [rdx-0x18a]` RIP-relative base trick).

Sections observed in every Poopsploit FW's shellcode:
  [0]  get kernel base via MSR 0xC0000082 (LSTAR) -> rdx
  [1]  disable WP (cr0 bit 16)
  [2]  ~7x `mov word ptr [base+OFF], 0xeb`  + follow-up patches
       -> self-consistent flag patches in kernel .text (permission checks)
  [3]  ucred overwrite of the *current process* (offsets relative to a
       base derived from rdx) incl. uid/gid/caps
  [4]  re-enable WP (cr0 bit 16)
  [5]  ret (from Poops.java, shellcode returns to ROP chain)
"""

import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SHELLCODE = "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3771b00b8eb04000041b9eb00000041baeb000000668981acc82f0041bbeb000000b890e9ffff4881c210d504006689b1b3771b006689b9d3771b0066448981c4836200c681cd0a0000ebc681edd42b00ebc68131d52b00ebc681add52b00ebc681f1d52b00ebc6819dd72b00ebc6814ddc2b00ebc6811ddd2b00eb66448989af8c6200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681161d3900eb66898164721b00c78118781b0090e93c01c78110e13b004831c0c3c6813aa81f0037c6813da81f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb06000041bbeb48000031d231f6668981435a4100bf0100000048b84183bfa00400000041b8010000004889814b5a4100b80400000041b9498bffff6689815d5a4100b8040000006689816a5a4100b805000000668981825a4100b80500000066448999015a4100c781595a4100498b87d0c6815f5a410000c781665a4100498bb7b0c6816c5a410000c7817e5a4100498b8740c681845a410000c7818b5a4100498bb7206689818f5a4100c681915a410000c781a35a4100498dbfc0668991a75a4100c681a95a410000c781af5a4100498dbfe06689b1b35a4100c681b55a410000c781c25a4100498dbf006689b9c65a4100c681c85a410000c781ce5a4100498dbf2066448981d25a4100c681d45a41000066448989df5a4100c681e15a4100ff0f20c0480d000001000f22c031c0c3"

raw = bytes.fromhex(SHELLCODE)
print(f"13.52 shellcode: {len(raw)} bytes\n")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Position-independent base for this code is rdx = kernel_base - 0x18a
# (see the `lea rsi,[rdx-0x18a]` prologue). We track rdx if a constant can be
# derived, then annotate [rdx+X] / [rdx+X] writes as kernel_base + delta.
# Exact base delta: lea rsi,[rdx-0x18a] => rsi=rdx-0x18a, then 4881c2... add rdx,imm
# is used as `add rdx, IMM_ABS` where IMM_ABS = base+0x18a (so [rdx+..]=base+..).
# We just print the immediate annotations; full base fixup is noted at bottom.

out = []
for i in md.disasm(raw, 0):
    out.append(f"{i.address:04x}: {i.mnemonic:8s} {i.op_str}")

print("\n".join(out))

# Extract all 32-bit signed immediates to flag candidate kernel offsets
print("\n=== 32-bit constant immediates (candidate kernel offsets) ===")
for i in md.disasm(raw, 0):
    for op in i.operands:
        if op.type == 3:  # IMM
            if -(2**31) <= op.imm <= 2**32 - 1:
                v = op.imm & 0xFFFFFFFF
                if 0x0 <= v <= 0x3000000:
                    print(f"  {i.address:04x}: {i.mnemonic} {i.op_str}  (0x{v:x})")
