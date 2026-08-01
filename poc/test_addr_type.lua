-- Check if memory.* works with table (uint64) or number
local buf = memory.alloc(0x40)
print(string.format("buf tostring: %s", tostring(buf)))
print(string.format("buf type: %s", type(buf)))
print(string.format("buf.h=%s buf.l=%s", tostring(buf.h), tostring(buf.l)))

-- Convert to number
local buf_num = buf.h * 4294967296 + buf.l
print(string.format("buf as number: %d (0x%x)", buf_num, buf_num))

-- read_buffer with table
memory.write_buffer(buf, 0, "ABCDEFGH")
local s1 = memory.read_buffer(buf, 8)
print(string.format("read_buffer(table): '%s'", s1))

-- read_buffer with number
local s2 = memory.read_buffer(buf_num, 8)
print(string.format("read_buffer(number): '%s'", s2))

-- Now try SC596 with table address
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

-- SC596 with table address (b pass buf directly)
local buf2 = memory.alloc(0x40)
memory.write_buffer(buf2, 0, string.rep("\xBB", 0x40))
print("\nSC596 with table address:")
local r = sc(596, buf2.l, buf2.h)  -- pass l=lo, h=hi as separate args
print(string.format("  ret=%s", r))
local s = memory.read_buffer(buf2, 0x20)
local hex = ""
for i = 1, #s do hex = hex .. string.format("%02x", string.byte(s, i)) end
print(string.format("  buf: %s", hex))

print("\nDone!")
