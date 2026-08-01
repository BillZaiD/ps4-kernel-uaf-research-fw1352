local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

-- Read a precise 8-byte value using individual byte reads
local function read_u64_le(addr)
    local v = 0
    for i = 0, 7 do
        local b = tonn(mem.read_byte(addr + i))
        v = v + b * (256 ^ i)
    end
    return v
end

-- Check if value is in kernel range
local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v <= 0xFFFFFFFFFFFFFFFF
end

local wrapper = toaddr(S.syscall_wrapper[454])

-- Scan and collect precise kernel pointers
local kptrs = {}
for off = 0, 0x10000, 8 do
    local v = read_u64_le(wrapper + off)
    if is_kptr(v) then
        table.insert(kptrs, {off = off, val = v})
        if #kptrs <= 20 then
            print(string.format("+%05x: %016x", off, v))
        end
    end
end

print(string.format("total: %d", #kptrs))

-- Check page alignment
local aligned = 0
for _, p in ipairs(kptrs) do
    if p.val % 4096 == 0 then aligned = aligned + 1 end
end
print(string.format("page-aligned: %d/%d", aligned, #kptrs))

-- Find min/max to estimate kernel base range
if #kptrs >= 2 then
    local min_v = kptrs[1].val
    local max_v = kptrs[1].val
    for _, p in ipairs(kptrs) do
        if p.val < min_v then min_v = p.val end
        if p.val > max_v then max_v = p.val end
    end
    print(string.format("min: %016x", min_v))
    print(string.format("max: %016x", max_v))
end

print("ok")
