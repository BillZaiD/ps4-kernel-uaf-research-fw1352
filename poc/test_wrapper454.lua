-- Test raw gadget and wrapper at +0x2ba0 (NO pcalls)
print("=== Raw gadget debugging ===\n")

local base = libkernel_base

-- Wrapper at +0x2ba0 (syscall 454)
local wrapper454 = base + 0x2ba0
-- Raw gadget at +0x2ba7
local raw_gadget = base + 0x2ba7

print(string.format("libkernel_base: 0x%x", base.h * 4294967296 + base.l))

-- Read bytes
local bw = memory.read_buffer(wrapper454, 16)
local br = memory.read_buffer(raw_gadget, 8)
local function hex(b)
    local h = ""
    for i = 1, #b do h = h .. string.format("%02x", string.byte(b, i)) end
    return h
end
print(string.format("wrapper @ +0x2ba0: %s", hex(bw)))
print(string.format("raw @ +0x2ba7:    %s", hex(br)))

-- Test 1: native.fcall with wrapper at +0x2ba0 (syscall 454)
print("\nTest 1: native.fcall(wrapper454, 0, 0, 0, 0, 0, 0)...")
local r1 = native.fcall(wrapper454, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("  Result: 0x%x (%d)", v1, v1))

print("\nDone test 1!")
return "ok"
