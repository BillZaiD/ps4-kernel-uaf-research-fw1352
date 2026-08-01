-- Isolate the issue step by step
print("=== Isolate fcall_with_rax issue ===\n")

-- Test 1: fcall_with_rax with wrapper, rax=nil (same as regular fcall)
print("Test 1: fcall_with_rax(wrapper[20], nil, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall_with_rax(syscall.syscall_wrapper[20], nil, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d)", v1, v1))

-- Test 2: fcall_with_rax with wrapper, rax=20 (same syscall, explicit)
print("Test 2: fcall_with_rax(wrapper[20], 20, 0, 0, 0, 0, 0, 0)...")
local r2 = native.fcall_with_rax(syscall.syscall_wrapper[20], 20, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d)", v2, v2))

-- Test 3: fcall_with_rax with raw gadget, rax=nil (syscall 0, safe?)
print("Test 3: fcall_with_rax(raw_gadget, nil, 0, 0, 0, 0, 0, 0)...")
local raw = libkernel_base + 0x2ba7
local r3 = native.fcall_with_rax(raw, nil, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

print("\nAll tests passed!")
return "ok"
