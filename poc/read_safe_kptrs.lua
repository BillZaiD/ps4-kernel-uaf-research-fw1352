--[[
    read_safe_kptrs.lua
    Read kernel pointers only at offsets known to be safe
]]

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

-- Reconstruct 64-bit value from 8 bytes
local function read_u64(addr)
    local v = 0
    for i = 0, 7 do
        v = v + tonn(mem.read_byte(addr + i)) * (256 ^ i)
    end
    return v
end

local wrapper = toaddr(S.syscall_wrapper[454])
print(string.format("w=0x%x", wrapper))

-- Only read at the known-safe offsets
local safe_offsets = {
    0x1b8, 0x238, 0x248, 0x280, 0x348, 0x3a8,
    0x5e0, 0x618, 0xaf8, 0xb18
}

for _, off in ipairs(safe_offsets) do
    local v = read_u64(wrapper + off)
    local str = string.format("+%05x %016x", off, v)
    if v >= 0xFFFF800000000000 then
        print(str .. " K")
    else
        print(str)
    end
end

-- Compute common high bits
local kptrs = {}
for _, off in ipairs(safe_offsets) do
    local v = read_u64(wrapper + off)
    if v >= 0xFFFF800000000000 then
        table.insert(kptrs, v)
    end
end

if #kptrs >= 2 then
    -- Check top 32 bits
    local t32 = {}
    for _, v in ipairs(kptrs) do
        table.insert(t32, v / 4294967296)
    end
    local same = true
    for i = 2, #t32 do
        if t32[i] ~= t32[1] then same = false end
    end
    print(string.format("same_top32=%s count=%d", tostring(same), #kptrs))
end

print("ok")
