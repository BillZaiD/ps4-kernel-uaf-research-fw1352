-- Test read_byte with offset vs address arithmetic
local buf = memory.alloc(0x40)

-- Write pattern using write_buffer (which exists)
memory.write_buffer(buf, 0, "ABCDEFGHIJKLMNOP")

-- Test read_byte(buf, offset) - does offset work?
local b0 = memory.read_byte(buf, 0)
local b1 = memory.read_byte(buf, 1)
print(string.format("read_byte(buf,0)=0x%02x", b0.l or 0))
print(string.format("read_byte(buf,1)=0x%02x", b1.l or 0))

-- Test read_byte(buf+offset) - address arithmetic
local b0a = memory.read_byte(buf + 0)
local b1a = memory.read_byte(buf + 1)
print(string.format("read_byte(buf+0)=0x%02x", b0a.l or 0))
print(string.format("read_byte(buf+1)=0x%02x", b1a.l or 0))

-- write_byte with address arithmetic
memory.write_byte(buf + 0, 0x41)
memory.write_byte(buf + 1, 0x42)
local wa0 = memory.read_byte(buf + 0)
local wa1 = memory.read_byte(buf + 1)
print(string.format("After write: buf[0]=0x%02x buf[1]=0x%02x", wa0.l or 0, wa1.l or 0))

-- Now test read/write buffer with offset
print("\n--- Buffer read/write with offset ---")
memory.write_qword(buf, 0, 0xAABBCCDD00112233)
local rq = memory.read_qword(buf, 0)
print(string.format("write_qword(buf, 0, 0xAABBCCDD00112233): read back = 0x%x%08x", rq.h or 0, rq.l or 0))

-- Test multiple qwords
print("\n--- Multiple qwords ---")
for i = 0, 3 do
    memory.write_qword(buf, i * 8, 0x100 + i)
end
local mq = memory.read_multiple_qwords(buf, 4)
for i = 1, 4 do
    local v = mq[i]
    if type(v) == "table" then
        print(string.format("  [%d] = 0x%x%08x", i-1, v.h or 0, v.l or 0))
    end
end

print("\nDone!")
