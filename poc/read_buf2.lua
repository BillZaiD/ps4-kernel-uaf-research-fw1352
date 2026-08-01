-- Now properly test SC596 buffer contents
local wt = syscall.syscall_wrapper

local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "CRASH" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh = ret.h or 0; rl = ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

local function read_buf_hex(buf, len)
    local s = memory.read_buffer(buf, len)
    if type(s) ~= "string" then return "bad_type:" .. type(s) end
    local hex = ""
    for i = 1, len do
        local c = string.byte(s, i)
        hex = hex .. string.format("%02x", c)
    end
    return hex
end

local targets = {596, 599, 602, 606, 617, 620}

for _, n in ipairs(targets) do
    local buf = memory.alloc(0x40)
    
    -- Write known pattern via write_buffer
    memory.write_buffer(buf, 0, string.rep("\xBB", 0x40))
    
    local r = sc(n, tostring(buf):sub(3)) -- strip "0x" to make number
    
    -- Actually need to convert string to number
    -- tostring(buf) returns "0x..."
    
    -- Let me just use tonumber
    local buf_num = tonumber(tostring(buf):sub(3), 16)
    
    -- Redo with proper number
    local buf2 = memory.alloc(0x40)
    memory.write_buffer(buf2, 0, string.rep("\xBB", 0x40))
    local buf2_num = tonumber(tostring(buf2):sub(3), 16)
    
    r = sc(n, buf2_num)
    
    local hex = read_buf_hex(buf2, 0x28)
    print(string.format("SC%03d: ret=%s", n, r))
    print(string.format("  buf[0..39]: %s", hex))
end

print("Done!")
