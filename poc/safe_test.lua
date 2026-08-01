-- Safe single syscall test
local wt = syscall.syscall_wrapper
local mem = memory

local function sc(num, ...)
    local w = wt[num]
    if not w then return "NO_W" end
    local args = {...}
    local ok, ret = pcall(native.fcall, w, args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0)
    if not ok then return "CRASH" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

print("--- Re-verify zero-arg tests ---\n")
local targets = {596, 599, 602, 606, 617, 620}
for _, n in ipairs(targets) do
    local r = sc(n)
    print(string.format("SC%03d zero-arg: %s", n, r))
end

-- Now test each with a BUFFER pointer (might be info syscalls)
print("\n--- Buffer test (alloc 0x40, pass ptr) ---\n")
for _, n in ipairs(targets) do
    local buf = mem.alloc(0x40)
    mem.fill(buf, 0x40, 0xBB)
    local r = sc(n, buf)
    -- Check if buffer was written to
    local changed = false
    for i = 0, 0x3f do
        if mem.read8(buf + i) ~= 0xBB then changed = true; break end
    end
    print(string.format("SC%03d buf=0x%x: ret=%s buf_changed=%s", n, buf, r, tostring(changed)))
    mem.free(buf)
end

print("\n--- PID-like test ---")
-- Check if any syscall returns a changing value (like PID)
print(string.format("SC596 first: %s", sc(596)))
print(string.format("SC596 second: %s", sc(596)))
print(string.format("SC599 first: %s", sc(599)))
print(string.format("SC599 second: %s", sc(599)))

print("\nDone!")
