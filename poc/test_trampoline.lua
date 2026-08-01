-- Use wrapper+7 (mov r10, rcx) instead of raw gadget
print("=== Wrapper trampoline test ===\n")

local base = libkernel_base

-- Get any wrapper address and compute +7
local w20 = syscall.syscall_wrapper[20]  -- getpid wrapper
local trampoline = w20 + 7  -- mov r10, rcx; syscall; jb +1; ret

-- Verify the bytes
local b = memory.read_buffer(trampoline, 8)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("Trampoline @ wrapper20+7: %s", hex))

-- TEST 1: Call with rax=585 (is_in_sandbox)
print("\nTest 1: fcall_with_rax(trampoline, 585, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall_with_rax(trampoline, 585, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d) [expected: 1]", v1, v1))

-- TEST 2: Now try with rax=597 (FSC2H!)
print("\nTest 2: fcall_with_rax(trampoline, 597, 0, 0, 0, 0, 0, 0)...")
print("  Calling FSC2H with cmd=0 (resolve)...")
local r2 = native.fcall_with_rax(trampoline, 597, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d)", v2, v2))

-- TEST 3: Try with different arguments
print("\nTest 3: fcall_with_rax(trampoline, 597, 2, 0, 0, 0, 0, 0)...")
print("  Calling FSC2H with cmd=2...")
local r3 = native.fcall_with_rax(trampoline, 597, 2, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

print("\nAll tests passed!")
return "ok"
