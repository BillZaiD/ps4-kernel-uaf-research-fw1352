-- Proper memory tests using buf+offset arithmetic
local wt = syscall.syscall_wrapper

-- Write qword using {h,l} format
local function wq(addr, off, val64)
    local h = math.floor(val64 / 4294967296)
    local l = val64 % 4294967296
    memory.write_qword(addr, off, {h = h, l = l})
end

local function rq(addr, off)
    local v = memory.read_qword(addr, off)
    if type(v) ~= "table" then return 0 end
    return (v.h or 0) * 4294967296 + (v.l or 0)
end

local function rb(addr, off)
    local v = memory.read_byte(addr + off)
    if type(v) ~= "table" then return 0 end
    return v.l or 0
end

local function wb(addr, off, val)
    memory.write_byte(addr + off, val)
end

-- Verify basic memory R/W works
print("=== Verify memory R/W ===\n")
local buf = memory.alloc(0x40)

-- Write via address arithmetic
wb(buf, 0, 0x41)  -- 'A'
wb(buf, 1, 0x42)  -- 'B'
wb(buf, 2, 0x43)  -- 'C'

-- Read back
local v0 = rb(buf, 0)
local v1 = rb(buf, 1)
local v2 = rb(buf, 2)
print(string.format("buf[0..2] = 0x%02x 0x%02x 0x%02x", v0, v1, v2))

-- Write qword
wq(buf, 8, 0xDEADBEEFCAFEBABE)
local rv = rq(buf, 8)
print(string.format("qword at buf+8 = 0x%x", rv))
print(string.format("  expected = 0x%x", 0xDEADBEEFCAFEBABE))

-- Now scan SYSTEM MEMORY near libkernel to find string patterns
print("\n=== SC596 buffer test ===\n")
local buf2 = memory.alloc(0x100)

-- Fill with 0xEB pattern via byte writes
for i = 0, 0xff do wb(buf2, i, 0xEB) end

-- Verify fill
local fill_ok = true
for i = 0, 15 do if rb(buf2, i) ~= 0xEB then fill_ok = false; break end end
print(string.format("fill verify: %s", tostring(fill_ok)))

-- Call SC596
local ok, ret = pcall(native.fcall, wt[596], buf2, 0x100, 0, 0, 0, 0)
local ret_v = 0
if type(ret) == "table" then ret_v = ret.h * 4294967296 + ret.l end
print(string.format("SC596 ret = 0x%x", ret_v))

-- Read back and show
local changed = false
local hex = ""
for i = 0, 63 do
    local b = rb(buf2, i)
    hex = hex .. string.format("%02x", b)
    if b ~= 0xEB then changed = true end
end
print(string.format("buf[0..63]: %s", hex))
print(string.format("changed: %s", tostring(changed)))

-- Print as qwords
for i = 0, 3 do
    local qv = rq(buf2, i * 8)
    print(string.format("  qword[%d]: 0x%016x", i, qv))
end

-- Also dump as ASCII where printable
local ascii = ""
for i = 0, 63 do
    local b = rb(buf2, i)
    if b >= 0x20 and b < 0x7f then ascii = ascii .. string.char(b)
    else ascii = ascii .. "." end
end
print(string.format("  ascii: %s", ascii))

print("\nDone!")
