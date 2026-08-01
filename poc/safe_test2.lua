local wt = syscall.syscall_wrapper

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

-- Helper to convert uint64 table to number for printing
local function to_num(t)
    if type(t) ~= "table" then return 0 end
    return (t.h or 0) * 0x100000000 + (t.l or 0)
end

print("--- Buffer test ---\n")
local targets = {596, 599, 602, 606, 617, 620}

-- Write pattern via write_byte
local function fill_buf(buf, size, val)
    for i = 0, size - 1 do
        memory.write_byte(buf, i, val)
    end
end

-- Check if any byte differs
local function buf_changed(buf, size, orig)
    for i = 0, size - 1 do
        if memory.read_byte(buf, i) ~= orig then return true end
    end
    return false
end

for _, n in ipairs(targets) do
    local buf = memory.alloc(0x40)
    local buf_num = to_num(buf)
    fill_buf(buf, 0x40, 0xBB)
    
    local r = sc(n, buf_num)
    local changed = buf_changed(buf, 0x40, 0xBB)
    
    print(string.format("SC%03d buf=0x%x: ret=%s buf_changed=%s", n, buf_num, r, tostring(changed)))
    
    if changed then
        print("  Contents:")
        for i = 0, 7 do
            local v = memory.read_qword(buf, i * 8)
            print(string.format("    [%d]=0x%x", i, v or 0))
        end
    end
end

print("\nDone!")
