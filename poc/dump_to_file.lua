--[[
    dump_to_file.lua
    Dump libkernel to a file on PS4
]]
local mem = rawget(_G, "memory")

local base = 0x81aee8000
local chunk_size = 0x4000  -- 16KB chunks for writing
local output_path = WRITABLE_PATH .. "libkernel.bin"

print(string.format("[*] Dumping libkernel from 0x%x to %s\n", base, output_path))

-- Remove old file if exists
local fh = io.open(output_path, "wb")
if not fh then
    print("Failed to open output file\n")
    return
end

local total = 0
for off = 0, 0x100000, chunk_size do
    local addr = base + off
    if not check_memory_access(addr, chunk_size) then
        print(string.format("[*] Unmapped at offset 0x%x\n", off))
        break
    end
    local chunk = mem.read_buffer(addr, chunk_size)
    if chunk and #chunk > 0 then
        fh:write(chunk)
        total = total + #chunk
    end
end

fh:close()
print(string.format("[OK] Dumped %d bytes to %s\n", total, output_path))
