-- Try SC596 with size + various arg combinations
local wt = syscall.syscall_wrapper

local function fcall(w, ...)
    local args = {...}
    local ok, ret = pcall(native.fcall, w, args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0)
    if not ok then return nil, "CRASH" end
    if type(ret) == "table" then return ret.h * 4294967296 + ret.l end
    if type(ret) == "number" then return ret end
    return nil, "BAD_RET"
end

-- Use read_buffer + write_buffer
print("--- SC596 with various arg patterns ---\n")

local buf = memory.alloc(0x100)
memory.write_buffer(buf, 0, string.rep("\xEB", 0x100))

-- SC596 with size=0x100 as 2nd arg
local r = fcall(wt[596], buf, 0x100, 0, 0, 0, 0)
print(string.format("SC596(buf, 0x100): ret=0x%x", r or -1))

-- Read back and show as hex
local s = memory.read_buffer(buf, 0x40)
local hex = ""
for i = 1, #s do hex = hex .. string.format("%02x", string.byte(s, i)) end
print(string.format("buf[0..63]: %s", hex))

-- Now try with different sizes
print("\n--- SC596 with different sizes ---")
for _, size in ipairs({0, 1, 4, 8, 16, 32, 64, 0x100, 0x400}) do
    local b = memory.alloc(0x400)
    memory.write_buffer(b, 0, string.rep("\xEB", 0x400))
    local r = fcall(wt[596], b, size, 0, 0, 0, 0)
    local s = memory.read_buffer(b, 16)
    local hex = ""
    for i = 1, #s do hex = hex .. string.format("%02x", string.byte(s, i)) end
    print(string.format("size=0x%04x: ret=0x%x buf[0..15]=%s", size, r or -1, hex))
end

-- Try SC596 with process id as arg
print("\n--- SC596 with PID ---")
local pid = 186  -- from getpid earlier
local b = memory.alloc(0x100)
memory.write_buffer(b, 0, string.rep("\xEB", 0x100))
local r = fcall(wt[596], pid, b, 0x100, 0, 0, 0)
local s = memory.read_buffer(b, 16)
local hex = ""
for i = 1, #s do hex = hex .. string.format("%02x", string.byte(s, i)) end
print(string.format("SC596(pid, buf, size): ret=0x%x buf=%s", r or -1, hex))

print("\nDone!")
