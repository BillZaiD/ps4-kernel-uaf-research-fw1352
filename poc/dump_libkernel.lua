--[[
    dump_libkernel.lua
    Dump libkernel in small hex chunks via socket
]]
local mem = rawget(_G, "memory")

local function bin_to_hex(str)
    return (str:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

local base = 0x81aee8000
local chunk_size = 0x40  -- 64 bytes per chunk

print(string.format("DUMP_START\n"))

for off = 0, 0x100000, chunk_size do
    local addr = base + off
    if not check_memory_access(addr, chunk_size) then
        break
    end
    local chunk = mem.read_buffer(addr, chunk_size)
    if chunk and #chunk > 0 then
        print(string.format("%x|%s", addr, bin_to_hex(chunk)))
    end
end

print("DUMP_END\n")
