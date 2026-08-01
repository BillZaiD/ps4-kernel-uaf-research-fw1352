-- dump libkernel in 4KB chunks
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local base = tonn(libkernel_base)
local total = 0
local f = io.open(WRITABLE_PATH .. "lk.bin", "wb")

for off = 0, 0x100000, 0x1000 do
    local addr = base + off
    if not check_memory_access(addr, 0x100) then break end
    local data = mem.read_buffer(addr, 0x1000)
    if data and #data > 0 then
        f:write(data)
        total = total + #data
        if total % 0x10000 == 0 then
            -- progress indicator
            print("P:" .. total)
        end
    end
end
f:close()
print("DONE:" .. total)
