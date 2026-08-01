-- Test metatable arithmetic on memory objects
local buf = memory.alloc(0x80)
print(string.format("buf = %s", tostring(buf)))

-- Test buf + offset
local buf_plus = buf + 16
print(string.format("buf+16 = %s", tostring(buf_plus)))
print(string.format("type(buf+16) = %s", type(buf_plus)))
print(string.format("getmetatable(buf+16) = %s", tostring(getmetatable(buf_plus))))

-- Test read_qword with offset
local q = memory.read_qword(buf, 0)
print(string.format("read_qword(buf, 0): h=%d l=%d", q.h or 0, q.l or 0))

-- Test write then read via multiple_qwords
memory.write_qword(buf, 0, 0xDEADBEEF)
local q2 = memory.read_qword(buf, 0)
print(string.format("after write 0xDEADBEEF: h=%d l=%d (0x%x%08x)", q2.h or 0, q2.l or 0, q2.h or 0, q2.l or 0))

-- write at buf+8
memory.write_qword(buf, 8, 0xCAFEBABE)
local q3 = memory.read_qword(buf, 8)
print(string.format("read buf+8: h=%d l=%d", q3.h or 0, q3.l or 0))

-- Now test SC596 buffer write
local wt = syscall.syscall_wrapper
local buf2 = memory.alloc(0x100)

-- Fill with known pattern via write_qword
for i = 0, 7 do
    memory.write_qword(buf2, i * 8, 0xBBBBBBBBBBBBBBBB)
end

-- Verify fill
local v0 = memory.read_qword(buf2, 0)
print(string.format("Before SC596 buf2[0]: h=0x%x l=0x%x", v0.h or 0, v0.l or 0))

-- Call SC596
local ok, ret = pcall(native.fcall, wt[596], buf2, 0x100, 0, 0, 0, 0)
local ret_v = 0
if type(ret) == "table" then ret_v = ret.h * 4294967296 + ret.l end
print(string.format("SC596(buf2, 0x100): ret=0x%x", ret_v))

-- Read back
for i = 0, 3 do
    local v = memory.read_qword(buf2, i * 8)
    print(string.format("  buf2[%d]: h=0x%08x l=0x%08x", i, v.h or 0, v.l or 0))
end

-- Read as hex bytes
local hex = ""
for i = 0, 31 do
    local b = memory.read_byte(buf2, i)
    hex = hex .. string.format("%02x", b.l or 0)
end
print(string.format("  buf2 hex[0..31]: %s", hex))

print("\nDone!")
