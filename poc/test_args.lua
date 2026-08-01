-- Check how native.fcall handles 64-bit args
-- by testing with a known function: getpid = syscall 20
local wt = syscall.syscall_wrapper

-- syscall 20 (getpid) returns PID, no args
local ok, ret = pcall(native.fcall, wt[20], 0, 0, 0, 0, 0, 0)
print(string.format("getpid raw: type=%s value=%s", type(ret), tostring(ret)))

-- Try with various arg formats
print("\n--- Test passing addresses to SC599 ---")

-- SC599 returns 0 with zero args. Let's pass buf as table, number, etc.
local buf = memory.alloc(0x80)
print(string.format("buf type=%s", type(buf)))
print(string.format("buf.h=%d buf.l=%d", buf.h, buf.l))

-- Method 1: pass buf table directly
local ok1, r1 = pcall(native.fcall, wt[599], buf, 0, 0, 0, 0, 0)
print(string.format("buf table: ret=%s", tostring(r1)))

-- Method 2: pass lo, hi as separate args 
local ok2, r2 = pcall(native.fcall, wt[599], buf.l, buf.h, 0, 0, 0, 0)
print(string.format("lo,hi: ret=%s", tostring(r2)))

-- Method 3: pass as concatenated number
local addr_num = buf.h * 4294967296 + buf.l
local ok3, r3 = pcall(native.fcall, wt[599], addr_num, 0, 0, 0, 0, 0)
print(string.format("number: ret=%s", tostring(r3)))

-- Now test SC596 with a known function that writes to buffer
-- Let's verify all 3 methods actually write to buf
print("\n--- SC596 write test ---")

for method, a1 in ipairs({{buf, 0}, {buf.l, buf.h}, {addr_num, 0}}) do
    local tbuf = memory.alloc(0x40)
    memory.write_buffer(tbuf, 0, string.rep("\xDD", 0x40))
    
    local ok, r = pcall(native.fcall, wt[596], a1[1], a1[2], 0, 0, 0, 0)
    if ok then
        local s = memory.read_buffer(tbuf, 8)
        local hex = ""
        for i = 1, #s do hex = hex .. string.format("%02x", string.byte(s, i)) end
        print(string.format("method %d: ret=%s buf[0..7]=%s", method, tostring(r), hex))
    else
        print(string.format("method %d: CRASH", method))
    end
end

print("\nDone!")
