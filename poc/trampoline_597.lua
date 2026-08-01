-- Now try trampoline with different syscall numbers
print("=== Trampoline with various syscalls ===\n")

local tramp = syscall.syscall_wrapper[20] + 7

-- Test 1: syscall 585 (is_in_sandbox) via trampoline
print("Test 1: fcall_with_rax(trampoline, 585, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall_with_rax(tramp, 585, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d) [expected: 1]", v1, v1))

-- Test 2: syscall 596 via trampoline (returns 0 for arg=0)
print("\nTest 2: fcall_with_rax(trampoline, 596, 0, 0, 0, 0, 0, 0)...")
local r2 = native.fcall_with_rax(tramp, 596, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d) [expected: 0]", v2, v2))

-- Test 3: THE BIG ONE - syscall 597 (FSC2H) via trampoline
print("\nTest 3: fcall_with_rax(trampoline, 597, 0, 0, 0, 0, 0, 0)...")
print("  Calling FSC2H! cmd=0, all other args=0")
local r3 = native.fcall_with_rax(tramp, 597, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

-- Test 4: Try different cmd values
print("\nTest 4: fcall_with_rax(trampoline, 597, 2, 0, 0, 0, 0, 0)...")
print("  cmd=2, rest=0")
local r4 = native.fcall_with_rax(tramp, 597, 2, 0, 0, 0, 0, 0)
local v4 = (type(r4) == "table") and (r4.h * 4294967296 + r4.l) or (r4 or -1)
print(string.format("  Result: 0x%x (%d)", v4, v4))

-- Test 5: SC598 via trampoline for comparison
print("\nTest 5: fcall_with_rax(trampoline, 598, 0, 0, 0, 0, 0, 0)...")
local r5 = native.fcall_with_rax(tramp, 598, 0, 0, 0, 0, 0, 0)
local v5 = (type(r5) == "table") and (r5.h * 4294967296 + r5.l) or (r5 or -1)
print(string.format("  Result: 0x%x (%d)", v5, v5))

print("\nDone!")
return "ok"
