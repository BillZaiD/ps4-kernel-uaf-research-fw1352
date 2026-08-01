--[[
    dump_test.lua
    Test dump - just first 16KB
]]
local mem = rawget(_G, "memory")

local base = 0x81aee8000
local chunk_size = 0x1000

print("TEST_START\n")
for off = 0, 0x4000 - 1, chunk_size do
    local addr = base + off
    if check_memory_access(addr, chunk_size) then
        local chunk = mem.read_buffer(addr, chunk_size)
        print(string.format("PAGE 0x%x size %d", addr, #chunk))
    else
        print(string.format("UNMAPPED 0x%x", addr))
    end
end
print("TEST_END\n")
