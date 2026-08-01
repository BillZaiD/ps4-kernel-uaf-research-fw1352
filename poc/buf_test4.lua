-- Proper buffer test: memory.read_buffer returns raw string
local wt = syscall.syscall_wrapper
local function add_off(addr, off)
    -- addr is a table {h,l}, add offset and return new table
    local new_l = addr.l + off
    local new_h = addr.h
    if new_l >= 0x100000000 then
        new_l = new_l - 0x100000000
        new_h = new_h + 1
    end
    return {h = new_h, l = new_l}
end

local function sc(num, a1)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, 0, 0, 0, 0, 0)
    if not ok then return "CRASH" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh = ret.h or 0; rl = ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

local function buf_hex(buf_ptr, len)
    local s = memory.read_buffer(buf_ptr, len)
    if type(s) ~= "string" then return "ERR:"..type(s) end
    local hex = ""
    for i = 1, len do
        hex = hex .. string.format("%02x", string.byte(s, i))
    end
    return hex
end

print("--- SC596 buffer contents ---\n")

local buf = memory.alloc(0x80)
print(string.format("buf = %s", tostring(buf)))

-- Write test pattern via write_buffer at offset 0
memory.write_buffer(buf, 0, string.rep("\xBB", 0x80))

-- Verify write
local verify = buf_hex(buf, 16)
print(string.format("After fill: %s ...", verify:sub(1, 32)))

-- SC596 with buf address 
-- native.fcall expects numeric args. For 64-bit pointer, need 2 args (lo, hi)?
-- Let's try passing the table as arg
print("\nCalling SC596...")
local r = sc(596, buf)
print(string.format("SC596 ret = %s", r))

-- Read back
local contents = buf_hex(buf, 0x40)
print(string.format("After SC596 buf[0..63]: %s", contents))

-- Also try with size arg
print("\n--- SC596 with size ---")
local buf2 = memory.alloc(0x80)
memory.write_buffer(buf2, 0, string.rep("\xCC", 0x80))
r = sc(596, buf2)
print(string.format("SC596 ret = %s", r))
local c2 = buf_hex(buf2, 0x40)
print(string.format("buf2[0..63]: %s", c2))

print("\nDone!")
