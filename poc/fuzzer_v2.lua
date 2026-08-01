-- comprehensive fuzzer for Sony custom syscalls 585-677
print("=== Sony Syscall Fuzzer ===\n")

local wt = syscall.syscall_wrapper

-- helper to call a syscall and get string result
local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_WRAP" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "LUA_ERR" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "RET_-1"
    elseif rh == 0 and rl == 0 then return "RET_0"
    else return string.format("0x%x%08x", rh, rl) end
end

-- Test all with zero args
print("--- Zero args ---")
for num = 585, 677 do
    local w = wt[num]
    if w then
        local r = sc(num, 0, 0, 0, 0, 0, 0)
        print(string.format("  SC%03d: %s", num, r))
    end
end

-- Test non-zero args on ALL (not just interesting ones)
print("\n--- Non-zero args ---")
for num = 585, 610 do
    local w = wt[num]
    if w then
        -- pattern: {arg1, mode} where mode helps identify function
        local r = sc(num, 0x41, 0, 0, 0, 0, 0)
        print(string.format("  SC%03d: zero+1byte=%s", num, r))
        local r2 = sc(num, 0, 0x41, 0, 0, 0, 0)
        if r2 ~= r then
            print(string.format("         zero+2byte=%s", r2))
        end
    end
end

print("\nDone!")
