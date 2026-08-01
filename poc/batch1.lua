-- Batch 1: syscalls 585-620 with simple patterns
print("=== Batch 1: 585-620 ===\n")

local wt = syscall.syscall_wrapper

local function test_sc(num, a1, a2)
    local w = wt[num]
    if not w then return end
    
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, 0, 0, 0, 0)
    if not ok then
        print(string.format("SC%03d: CRASH", num))
        return
    end
    
    local v = 0
    if type(ret) == "table" then v = ret.h * 4294967296 + ret.l end
    
    if v == 0 then
        print(string.format("SC%03d: 0", num))
    elseif v ~= 0xFFFFFFFFFFFFFFFF then
        print(string.format("SC%03d: 0x%x", num, v))
    end
end

print("--- a1=0 ---")
for n = 585, 620 do test_sc(n, 0, 0) end

print("--- a1=buf ---")
local buf = memory.alloc(0x40)
for n = 585, 620 do test_sc(n, buf, 0) end

print("--- a1=1 ---")
for n = 585, 620 do test_sc(n, 1, 0) end

print("--- a1=buf, a2=size ---")
for n = 585, 620 do test_sc(n, buf, 0x40) end

print("Done!")
