--[[
    analyze_kptrs.lua
    Analyze the kernel-pointer-looking values in game memory
    WITHOUT attempting to read from them (to avoid crash)
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

local wrapper = toaddr(S.syscall_wrapper[454])
print(string.format("wrapper=0x%x", wrapper))

-- Scan forward for kernel addresses, just COLLECT them (don't dereference)
local kptrs = {}
local total_scan = 0
for off = 0, 0x10000, 8 do
    local v = tonn(mem.read_qword(wrapper + off))
    total_scan = total_scan + 1
    
    -- Check if looks like a kernel pointer
    if v >= 0xFFFF800000000000 and v <= 0xFFFFFFFFFFFFFFFF then
        if #kptrs < 30 then
            table.insert(kptrs, {off = off, val = v})
        end
    end
    

end

print(string.format("\ntotal scanned: %d", total_scan))
print(string.format("total kptrs found: %d", #kptrs))

-- Show first 20
print("\nFirst 20 kernel pointers:")
for i = 1, math.min(#kptrs, 20) do
    local p = kptrs[i]
    local aligned = (p.val % 4096 == 0) and " (page-aligned)" or ""
    print(string.format("  +%x: 0x%x%s", p.off, p.val, aligned))
end

-- Check page alignment
if #kptrs > 0 then
    local aligned = 0
    for _, p in ipairs(kptrs) do
        if p.val % 4096 == 0 then aligned = aligned + 1 end
    end
    print(string.format("  Page-aligned: %d/%d", aligned, #kptrs))
end

print("\ndone")
