-- map libkernel memory regions
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local base = tonn(libkernel_base)
local wrapper = tonn(rawget(_G, "syscall").syscall_wrapper[454])

print("BASE:" .. base)
print("WRAPPER:" .. wrapper)

-- Scan in 4KB steps, report mapped/unmapped transitions
local last_state = true
for off = 0, 0x200000, 0x1000 do
    local addr = base + off
    local ok = check_memory_access(addr, 4)
    if ok ~= last_state then
        if ok then
            print("MAP_AT:" .. off)
        else
            print("UNMAP_AT:" .. off)
        end
        last_state = ok
    end
end
print("SCAN_DONE")
