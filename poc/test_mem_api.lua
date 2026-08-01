-- Check memory API
print("--- memory object ---")
for k, v in pairs(memory) do
    print(string.format("  memory.%s = %s", k, type(v)))
end

-- check if there's a way to allocate+write
print("\n--- Test alloc + write8/read8 ---")
local buf = memory.alloc(0x40)
print(string.format("buf = 0x%x", buf))

-- write pattern byte by byte
for i = 0, 0x3f do
    pcall(memory.write8, buf + i, 0xBB)
end

-- read back
local ok = true
for i = 0, 0x3f do
    local v = memory.read8(buf + i)
    if v ~= 0xBB then ok = false; break end
end
print(string.format("write8/read8 verify: %s", tostring(ok)))

print("\nDone!")
