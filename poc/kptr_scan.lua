--[[
    kptr_scan.lua
    Safe forward-only scan for kernel pointers near wrapper
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

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

local wrapper = toaddr(S.syscall_wrapper[454])
local total = 0
local kptrs = 0
local last_print = 0

for off = 0, 0x200000, 8 do  -- 2MB forward
    local v = tonn(mem.read_qword(wrapper + off))
    total = total + 1
    if is_kptr(v) then
        kptrs = kptrs + 1
        if kptrs <= 10 then
            print(string.format("k+%x: %x", off, v))
        end
    end
end
print(string.format("tot=%d k=%d", total, kptrs))
print("ok")
