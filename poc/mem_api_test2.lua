-- Understand memory API
local buf = memory.alloc(0x20)
print(string.format("buf: %s", tostring(buf)))

-- Try different write_byte signatures
print("--- write_byte test ---")
memory.write_byte(buf, 0, 0x41)
local v = memory.read_byte(buf, 0)
print(string.format("after write_byte(buf,0,0x41): read=%s", tostring(v)))

-- clear and retry
local buf2 = memory.alloc(0x20)
memory.write_byte(buf2, 0x41)
local v2 = memory.read_byte(buf2, 0)
print(string.format("after write_byte(buf,0x41): read=%s", tostring(v2)))

-- Try memcpy: copy a pattern in
local src = memory.alloc(0x10)
print(string.format("src: %s", tostring(src)))

-- Write via write_buffer
local pattern = string.rep("A", 16)
memory.write_buffer(src, 0, pattern)
local buf3 = memory.read_buffer(src, 16)
print(string.format("write_buffer->read_buffer: '%s' (len=%d)", buf3, #buf3))

print("Done!")
