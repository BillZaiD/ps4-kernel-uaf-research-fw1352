-- Targeted fuzzing: only interesting non-standard returns
local wt = syscall.syscall_wrapper

local function try_sc(num, a1, a2, a3)
    local w = wt[num]
    if not w then return end
    
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, 0, 0, 0)
    if not ok then return "CRASH" end
    
    local v = 0
    if type(ret) == "table" then v = ret.h * 4294967296 + ret.l end
    if v == 0 then return "0"
    elseif v == 0xFFFFFFFFFFFFFFFF then return "-1"
    else return string.format("0x%x", v) end
end

-- Test all Sony syscalls with various arg patterns
-- Pattern: various size values as 2nd/3rd args
print("=== Sony syscalls: size/len patterns ===\n")

for n = 585, 677 do
    if wt[n] then
        local results = {}
        -- Test with a buffer + various size args
        local buf = memory.alloc(0x100)
        local sizes = {0, 1, 0x40, 0x100, 0x1000, -1, 0x80000000}
        
        local interesting = false
        for _, s in ipairs(sizes) do
            local r = try_sc(n, buf, s, 0)
            if r and r ~= "-1" and r ~= "0" then
                interesting = true
                results[#results + 1] = string.format("size=0x%x:%s", s, r)
            end
        end
        
        if interesting then
            print(string.format("SC%03d: %s", n, table.concat(results, " ")))
        end
    end
end

-- Test with negative/out-of-range args
print("\n--- Negative/overlarge args ---")
for n = 585, 610 do
    if wt[n] then
        local r1 = try_sc(n, 0xFFFFFFFFFFFFFFFF, 0, 0) -- -1 as 64-bit
        local r2 = try_sc(n, 0, 0xFFFFFFFFFFFFFFFF, 0)
        local r3 = try_sc(n, 0x8000000000000000, 0, 0) -- min int64
        local r4 = try_sc(n, 0x7FFFFFFFFFFFFFFF, 0, 0) -- max int64
        
        local interesting = false
        for _, r in ipairs({r1, r2, r3, r4}) do
            if r and r ~= "-1" and r ~= "0" then interesting = true end
        end
        
        if interesting then
            print(string.format("SC%03d: -1=%s 0,FF=%s min64=%s max64=%s",
                n, r1 or "?", r2 or "?", r3 or "?", r4 or "?"))
        end
    end
end

-- Test high range (630-677) which we haven't fully tested
print("\n--- High range: 630-677 ---")
for n = 630, 677 do
    if wt[n] then
        local r0 = try_sc(n, 0, 0, 0)
        local r1 = try_sc(n, 1, 0, 0)
        local r2 = try_sc(n, 0x40, 0x40, 0)
        
        local interesting = false
        for _, r in ipairs({r0, r1, r2}) do
            if r and r ~= "-1" then interesting = true end
        end
        
        if interesting then
            print(string.format("SC%03d: zero=%s a1=1=%s a1=0x40,a2=0x40=%s",
                n, r0 or "?", r1 or "?", r2 or "?"))
        end
    end
end

print("\nDone!")
