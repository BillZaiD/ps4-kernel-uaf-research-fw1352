-- Methodical test of trampoline
print("=== Methodical trampoline test ===\n")

local base = libkernel_base
local w20 = syscall.syscall_wrapper[20]
local tramp = w20 + 7

-- Test 1: native.fcall with FULL wrapper (known working)
print("Test 1: native.fcall(wrapper20, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall(w20, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d)", v1, v1))

-- Test 2: fcall_with_rax with wrapper and correct syscall
print("\nTest 2: fcall_with_rax(wrapper20, 20, 0, 0, 0, 0, 0, 0)...")
local r2 = native.fcall_with_rax(w20, 20, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d)", v2, v2))

-- Test 3: fcall_with_rax with TRAMPOLINE and SAME syscall (20)
print("\nTest 3: fcall_with_rax(trampoline, 20, 0, 0, 0, 0, 0, 0)...")
local r3 = native.fcall_with_rax(tramp, 20, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

print("\nDone!")
return "ok"
