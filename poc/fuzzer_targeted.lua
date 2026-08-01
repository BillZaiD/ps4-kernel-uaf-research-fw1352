-- targeted fuzzing on syscalls that return 0
print("=== Targeted Analysis ===\n")

local wt = syscall.syscall_wrapper
local mem = rawget(_G, "memory")

local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "ERR" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

local test_syscalls = {596, 599, 602, 606, 617, 620}

-- Test with various argument patterns
for _, num in ipairs(test_syscalls) do
    print(string.format("--- SC%03d ---", num))
    
    -- zero args
    print(string.format("  zero: %s", sc(num, 0,0,0,0,0,0)))
    
    -- one arg variations
    print(string.format("  a1=0x41: %s", sc(num, 0x41,0,0,0,0,0)))
    print(string.format("  a1=-1: %s", sc(num, -1,0,0,0,0,0)))
    print(string.format("  a1=heap: %s", sc(num, mem.alloc(0x100),0,0,0,0,0)))
    
    -- two arg variations
    print(string.format("  a1=heap,a2=0x100: %s", sc(num, mem.alloc(0x100), 0x100, 0,0,0,0)))
    print(string.format("  a1=0,a2=0x41: %s", sc(num, 0, 0x41, 0,0,0,0)))
end

print("\nDone!")
