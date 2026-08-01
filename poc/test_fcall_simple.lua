-- Test fcall_with_rax with SC585 (is_in_sandbox) - NO pcall
print("=== Test fcall_with_rax ===\n")

local raw_gadget = libkernel_base + 0x2ba7
local addr = raw_gadget.h * 4294967296 + raw_gadget.l
print(string.format("Gadget addr: 0x%x", addr))

print("Calling SC585 via fcall_with_rax...")
local r = native.fcall_with_rax(raw_gadget, 585, 0, 0, 0, 0, 0, 0)

local v = 0
if type(r) == "table" then v = r.h * 4294967296 + r.l else v = r end
print(string.format("SC585 result: 0x%x (%d)", v, v))

return "done"
