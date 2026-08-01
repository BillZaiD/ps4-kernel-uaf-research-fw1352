-- Clean test step by step
print("=== Clean fcall_with_rax test ===\n")

-- Step 1: Verify basic fcall still works
print("Step 1: native.fcall with SC585...")
local r1 = native.fcall(syscall.syscall_wrapper[585], 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d)", v1, v1))

-- Step 2: Read the raw gadget and verify
print("\nStep 2: Read raw gadget...")
local raw_gadget = libkernel_base + 0x2ba7
local addr_num = raw_gadget.h * 4294967296 + raw_gadget.l
print(string.format("  libkernel_base: 0x%x", libkernel_base.h * 4294967296 + libkernel_base.l))
print(string.format("  raw_gadget @ 0x%x", addr_num))
print(string.format("  offset: 0x%x", addr_num - (libkernel_base.h * 4294967296 + libkernel_base.l)))

local b = memory.read_buffer(raw_gadget, 6)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("  bytes: %s", hex))

-- Step 3: Try fcall_with_rax with the GADGET address
-- This will skip the mov rax instruction and use RAX=585 from fcall_with_rax
print("\nStep 3: fcall_with_rax with raw gadget (SC585)...")
print("  (this uses the raw gadget at +0x2ba7, RAX=585)")
local r2 = native.fcall_with_rax(raw_gadget, 585, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("  Result: 0x%x (%d)", v2, v2))

-- Step 4: Try fcall_with_rax but WITH the wrapper address
-- This will set RAX=585 but then wrapper overwrites with 585 anyway
print("\nStep 4: fcall_with_rax with WRAPPER address...")
local w585 = syscall.syscall_wrapper[585]
local r3 = native.fcall_with_rax(w585, 585, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("  Result: 0x%x (%d)", v3, v3))

print("\nAll done!")
return "ok"
