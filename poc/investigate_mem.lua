-- Investigate read_buffer vs write_buffer
-- alloc returns {h,l} = pointer
local buf = memory.alloc(0x40)
print(string.format("buf addr: %s (h=%d l=%d)", tostring(buf), buf.h, buf.l))

-- Create a Lua string manually
local test_str = "TESTDATA1234"
print(string.format("test_str len=%d", #test_str))

-- Write buffer: write_buffer(addr_table, offset, lua_string)
memory.write_buffer(buf, 0, test_str)
print("--- After write_buffer ---")

-- Read back
local rb = memory.read_buffer(buf, 12)
print(string.format("read_buffer(12): type=%s len=%d", type(rb), #rb))
if type(rb) == "string" then
    for i = 1, #rb do
        print(string.format("  [%d] = 0x%02x ('%s')", i, string.byte(rb, i), string.sub(rb, i, i)))
    end
end

-- Try reading_byte directly from pointer arithmetic
print("\n--- read_byte directly ---")
for i = 0, 3 do
    -- Manually construct address: buf + i
    local new_l = buf.l + i
    local new_h = buf.h
    if new_l >= 0x100000000 then
        new_l = new_l - 0x100000000
        new_h = new_h + 1
    end
    local addr_i = {h = new_h, l = new_l}
    local val = memory.read_byte(addr_i)
    if type(val) == "table" then
        print(string.format("  read_byte(buf+%d) = 0x%02x (h=%d l=%d)", i, val.l, val.h, val.l))
    else
        print(string.format("  read_byte(buf+%d) = %s", i, tostring(val)))
    end
end

print("Done!")
