-- Test wrapper[585] with explicit rax=585
print("=== Wrapper[585] explicit rax test ===\n")

local w585 = syscall.syscall_wrapper[585]

-- Test A: native.fcall (rax=nil, wrapper sets to 585)
print("Test A: native.fcall(w585, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall(w585, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d)", v1, v1))

-- Test B: fcall_with_rax with explicit rax=585 (wrapper OVERWRITES to 585)
print("\nTest B: fcall_with_rax(w585, 585, 0, 0, 0, 0, 0, 0)...")
local r2 = native.fcall_with_rax(w585, 585, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d)", v2, v2))

-- Test C: fcall_with_rax with rax=12345 (DIFFERENT from wrapper's 585)
print("\nTest C: fcall_with_rax(w585, 999, 0, 0, 0, 0, 0, 0)...")
print("  (rax=999 but wrapper overwrites with 585)")
local r3 = native.fcall_with_rax(w585, 999, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

-- Test D: Check what wrapper[20] + 7 does with rax=585 vs rax=20
local tramp = syscall.syscall_wrapper[20] + 7
print("\nTest D: fcall_with_rax(tramp, 20, 0, 0, 0, 0, 0, 0)...")
local r4 = native.fcall_with_rax(tramp, 20, 0, 0, 0, 0, 0, 0)
local v4 = (type(r4) == "table") and (r4.h * 4294967296 + r4.l) or (r4 or -1)
print(string.format("  Result: 0x%x (%d)", v4, v4))

print("\nDone!")
return "ok"
