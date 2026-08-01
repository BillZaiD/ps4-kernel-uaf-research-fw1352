-- Step 1: Test fcall_with_rax with safe syscall (SC585 = is_in_sandbox)
print("=== Step 1: Test fcall_with_rax mechanism ===\n")

local raw_gadget = libkernel_base + 0x2ba7  -- mov r10, rcx; syscall; ret

-- Verify the gadget
local b = memory.read_buffer(raw_gadget, 6)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("Gadget @ 0x%x: %s", tonumber(tostring(raw_gadget):sub(3), 16) or 0, hex))

-- Call SC585 (is_in_sandbox) with fcall_with_rax
print("\nCalling SC585 (is_in_sandbox) via fcall_with_rax...")
local ok, r1 = pcall(function()
    return native.fcall_with_rax(raw_gadget, 585, 0, 0, 0, 0, 0, 0)
end)

if ok then
    local v = 0
    if type(r1) == "table" then v = r1.h * 4294967296 + r1.l
    else v = r1 end
    print(string.format("  SC585 result: 0x%x (%d)", v, v))
    print("  Expected: 1 (we are in sandbox)")
else
    print("  SC585 FAILED, but fcall_with_rax might still work")
    print("  Error: " .. tostring(r1))
end

-- Try SC596 (which should return 0 for arg=0)
print("\nCalling SC596 via fcall_with_rax (arg=0)...")
local ok2, r2 = pcall(function()
    return native.fcall_with_rax(raw_gadget, 596, 0, 0, 0, 0, 0, 0)
end)
if ok2 then
    local v = 0
    if type(r2) == "table" then v = r2.h * 4294967296 + r2.l
    else v = r2 end
    print(string.format("  SC596(0) result: 0x%x (%d)", v, v))
    print("  Expected: 0")
end

-- Compare with native.fcall (should match)
print("\nCalling SC596 via native.fcall (for comparison)...")
local ok3, r3 = pcall(function()
    return native.fcall(syscall.syscall_wrapper[596], 0, 0, 0, 0, 0, 0)
end)
if ok3 then
    local v = 0
    if type(r3) == "table" then v = r3.h * 4294967296 + r3.l
    else v = r3 end
    print(string.format("  SC596(0) via fcall: 0x%x (%d)", v, v))
end

print("\nStep 1 complete!")
return "step1_ok"
