-- First dump fcall_with_rax and fcall implementations
print("=== Dump fcall_with_rax source ===\n")

-- Try to get the source code of the function
-- Check if we can see what fcall_with_rax does
print("native.fcall_with_rax availability:", type(native.fcall_with_rax))

-- Test with a VERY simple approach: just call the wrapper for SC585 normally
print("\nCalling SC585 via native.fcall (known working)...")
local r1 = native.fcall(syscall.syscall_wrapper[585], 0, 0, 0, 0, 0, 0)
print(string.format("SC585 result: type=%s", type(r1)))
if r1 ~= nil then
    local v = tonumber(tostring(r1:match("%d+"))) or (type(r1) == "table" and (r1.h * 4294967296 + r1.l) or r1)
    print(string.format("  value: %s", tostring(r1)))
    if type(r1) == "table" then
        print(string.format("  h=0x%x, l=0x%x", r1.h, r1.l))
    end
end

-- Now try: call the SAME wrapper through fcall_with_rax but with the wrapper's NATIVE syscall number
-- This tests if the ROP setup (setting all registers) works without RAX manipulation issues
print("\nCalling SC585 wrapper through fcall_with_rax (same syscall 585)...")
local wrapper_addr = syscall.syscall_wrapper[585]
local addr_num = wrapper_addr.h * 4294967296 + wrapper_addr.l
print(string.format("Wrapper address: 0x%x", addr_num))

-- Read the wrapper bytes
local b = memory.read_buffer(wrapper_addr, 16)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("Bytes: %s", hex))

-- Call fcall_with_rax with WRAPPER address (not raw gadget)
-- The wrapper starts with mov rax, 585, so even though we set RAX via fcall_with_rax,
-- the wrapper will OVERWRITE it with 585
local r2 = native.fcall_with_rax(wrapper_addr, 585, 0, 0, 0, 0, 0, 0)
print(string.format("fcall_with_rax result: type=%s", type(r2)))
if r2 ~= nil then
    if type(r2) == "table" then
        print(string.format("  h=0x%x, l=0x%x", r2.h, r2.l))
    end
    print(string.format("  raw: %s", tostring(r2)))
end

return "done"
