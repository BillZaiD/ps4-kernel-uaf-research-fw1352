local wt = syscall.syscall_wrapper

local function sc(num, ...)
    local w = wt[num]
    if not w then return "NO_W" end
    local args = {...}
    local ok, ret = pcall(native.fcall, w, args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0)
    if not ok then return "CRASH" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh = ret.h or 0; rl = ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

local function to_num(t)
    if type(t) ~= "table" then return t or 0 end
    return (t.h or 0) * 0x100000000 + (t.l or 0)
end

local function read_qword_num(buf, off)
    local v = memory.read_qword(buf, off)
    return to_num(v)
end

print("--- SC596 buffer contents ---\n")
local targets = {596, 599, 602, 606, 617, 620}

for _, n in ipairs(targets) do
    local buf = memory.alloc(0x80)
    local buf_n = to_num(buf)
    
    -- Zero out buffer
    for i = 0, 0x7f do memory.write_byte(buf, i, 0) end
    
    local r = sc(n, buf_n)
    
    print(string.format("SC%03d buf=0x%x ret=%s", n, buf_n, r))
    
    -- Read first 32 bytes as hex
    local hex = ""
    for i = 0, 31 do
        local b = memory.read_byte(buf, i)
        hex = hex .. string.format("%02x", b or 0)
    end
    print(string.format("  hex[0..31]: %s", hex))
    
    -- Read as qwords
    for i = 0, 3 do
        local v = read_qword_num(buf, i * 8)
        print(string.format("  qword[%d]: 0x%x", i, v))
    end
    
    print("")
end

print("Done!")
