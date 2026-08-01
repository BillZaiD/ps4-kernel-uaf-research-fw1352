-- figure out memory API return types
local buf = memory.alloc(0x20)
memory.write_byte(buf, 0, 0x41)
memory.write_byte(buf, 1, 0x42)
memory.write_byte(buf, 2, 0x43)

local b0 = memory.read_byte(buf, 0)
local b1 = memory.read_byte(buf, 1)
local qw = memory.read_qword(buf, 0)

print(string.format("buf type: %s", type(buf)))
print(string.format("read_byte type: %s", type(b0)))
print(string.format("read_qword type: %s", type(qw)))

if type(b0) == "table" then
    print(string.format("read_byte[0].h=%s .l=%s", tostring(b0.h), tostring(b0.l)))
end
if type(qw) == "table" then
    print(string.format("read_qword.h=%s .l=%s", tostring(qw.h), tostring(qw.l)))
end

-- Try tostring
local tstr = tostring(b0)
print(string.format("tostring(b0): %s", tstr))
print(string.format("tostring(buf): %s", tostring(buf)))

-- Check if read_buffer returns bytes or tables
local rbuf = memory.read_buffer(buf, 16)
print(string.format("read_buffer type: %s", type(rbuf)))
if type(rbuf) == "string" then
    local hex = ""
    for i = 1, #rbuf do
        hex = hex .. string.format("%02x", string.byte(rbuf, i))
    end
    print(string.format("read_buffer hex: %s", hex))
end

print("Done!")
