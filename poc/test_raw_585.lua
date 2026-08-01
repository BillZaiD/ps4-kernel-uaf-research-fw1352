-- Test raw gadget with rax=585
print("=== Raw gadget with rax=585 ===\n")

local base = libkernel_base
local raw_gadget = base + 0x2ba7

-- Verify gadget
local br = memory.read_buffer(raw_gadget, 6)
local hex = ""
for i = 1, #br do hex = hex .. string.format("%02x", string.byte(br, i)) end
print(string.format("raw @ +0x2ba7: %s", hex))

-- Call with rax=585 (is_in_sandbox), should return 1
print("Calling fcall_with_rax(raw_gadget, 585, 0, 0, 0, 0, 0, 0)...")
local r = native.fcall_with_rax(raw_gadget, 585, 0, 0, 0, 0, 0, 0)
local v = (type(r) == "table") and (r.h * 4294967296 + r.l) or (r or -1)
print(string.format("Result: 0x%x (%d)", v, v))
print("Expected: 1 (is_in_sandbox)")

return "ok"
