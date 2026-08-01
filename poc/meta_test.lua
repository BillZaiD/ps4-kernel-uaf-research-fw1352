-- Check metatable on allocated buffers
local buf = memory.alloc(0x40)
print(string.format("buf type=%s", type(buf)))
print(string.format("getmetatable(buf)=%s", tostring(getmetatable(buf))))

-- Check if there's a __tonumber or similar
local mt = getmetatable(buf)
if mt then
    for k, v in pairs(mt) do
        print(string.format("  mt[%s]=%s", tostring(k), type(v)))
    end
end

-- Create manual table and check
local manual = {h = buf.h, l = buf.l}
print(string.format("manual type=%s", type(manual)))
print(string.format("getmetatable(manual)=%s", tostring(getmetatable(manual))))

-- Try reading with manual table
local q_manual = memory.read_qword(manual, 0)
print(string.format("read_qword(manual): type=%s", type(q_manual)))

-- Check if tonumber exists as global
print(string.format("tonumber global: %s", tostring(tonumber)))

-- Try to call memory.read_qword with offset as second arg
local q_off = memory.read_qword(buf, 16)
print(string.format("read_qword(buf, 16): h=%d l=%d", q_off.h or -1, q_off.l or -1))

print("\nDone!")
