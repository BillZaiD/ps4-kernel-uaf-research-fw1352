-- dump libkernel using dynamic base
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local base = tonn(libkernel_base)
local f = io.open(WRITABLE_PATH .. "lk.bin", "wb")
local total = 0
for off = 0, 0x100000, 0x1000 do
    if not check_memory_access(base + off, 0x100) then break end
    local chunk = mem.read_buffer(base + off, 0x100)
    f:write(chunk)
    total = total + #chunk
end
f:close()
print("SAVED:" .. total)
