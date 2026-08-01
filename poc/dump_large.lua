-- dump libkernel with larger chunks
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local base = tonn(libkernel_base)
local chunk = 0x4000  -- 16KB per read
local f = io.open(WRITABLE_PATH .. "lk.bin", "wb")
local total = 0
for off = 0, 0x100000, chunk do
    local addr = base + off
    if not check_memory_access(addr, chunk) then break end
    local data = mem.read_buffer(addr, chunk)
    if data and #data > 0 then
        f:write(data)
        total = total + #data
    end
end
f:close()
print("SAVED:" .. total)
