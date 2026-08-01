-- SC624 deep analysis
print("=== SC624: Return 0xdee ===\n")

local wt = syscall.syscall_wrapper

local function run_sc(num, a1, a2, a3, a4)
    local w = wt[num]
    if not w then return -999 end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, 0, 0)
    if not ok then return -999 end
    local v = 0
    if type(ret) == "table" then v = ret.h * 4294967296 + ret.l end
    return v
end

-- Test arg patterns
print("--- arg patterns ---")
print(string.format("zero:        0x%x", run_sc(624, 0, 0, 0, 0)))
print(string.format("a1=1:        0x%x", run_sc(624, 1, 0, 0, 0)))
print(string.format("a1=-1:       0x%x", run_sc(624, -1, 0, 0, 0)))
print(string.format("a1=buf:      0x%x", run_sc(624, memory.alloc(0x40), 0, 0, 0)))
print(string.format("a1=1,a2=1:   0x%x", run_sc(624, 1, 1, 0, 0)))
print(string.format("a1=buf,a2=0x100: 0x%x", run_sc(624, memory.alloc(0x100), 0x100, 0, 0)))
print(string.format("a1=0xdee:    0x%x", run_sc(624, 0xdee, 0, 0, 0)))
print(string.format("neg:         0x%x", run_sc(624, -65536, 0, 0, 0)))

-- Is it returning a pointer?
-- 0xdee = 3566. Too small for a pointer.
-- Maybe it's a handle or ID?

-- Check consistency
print("\n--- consistency ---")
for i = 1, 5 do
    print(string.format("  call %d: 0x%x", i, run_sc(624, 0, 0, 0, 0)))
end

-- Try calling with NO args at all (native.fcall with no extra args)
print("\n--- native.fcall direct ---")
local w = wt[624]
if w then
    local ok, ret = pcall(native.fcall, w, 0, 0, 0, 0, 0, 0)
    if ok and type(ret) == "table" then
        print(string.format("  6 zero args: 0x%x%08x", ret.h or 0, ret.l or 0))
    end
end

-- Try SC638 with size=0
print("\n--- SC638 with size=0 ---")
print(string.format("buf,0:    0x%x", run_sc(638, memory.alloc(0x40), 0, 0, 0)))
print(string.format("buf,1:    0x%x", run_sc(638, memory.alloc(0x40), 1, 0, 0)))
print(string.format("buf,0x40: 0x%x", run_sc(638, memory.alloc(0x40), 0x40, 0, 0)))

-- Try SC657 with size=0
print("\n--- SC657 with size=0 ---")
print(string.format("buf,0:    0x%x", run_sc(657, memory.alloc(0x40), 0, 0, 0)))
print(string.format("buf,1:    0x%x", run_sc(657, memory.alloc(0x40), 1, 0, 0)))
print(string.format("buf,0x40: 0x%x", run_sc(657, memory.alloc(0x40), 0x40, 0, 0)))

-- Test SC624 with buffer to see if it writes data
print("\n--- SC624 buffer write test ---")
local test_buf = memory.alloc(0x40)
memory.write_byte(test_buf, 0x41)
local r = run_sc(624, test_buf, 0x40, 0, 0)
print(string.format("ret = 0x%x", r))
local b = memory.read_byte(test_buf)
print(string.format("buf[0] after = 0x%x", b.l or 0))

-- Try SC624 with buffer at offset
local test_buf2 = memory.alloc(0x100)
for i = 0, 15 do memory.write_byte(test_buf2 + i, 0xBB) end
local r = run_sc(624, test_buf2, 0x100, 0, 0)
print(string.format("ret = 0x%x", r))
local changed = false
for i = 0, 15 do 
    local b = memory.read_byte(test_buf2 + i)
    if b.l ~= 0xBB then changed = true end
end
print(string.format("buffer changed: %s", tostring(changed)))

-- Could 0xdee be an error code? 
-- 0xdee in decimal: 3566
-- Let's check common PS4 error codes
print(string.format("\n0xdee = %d decimal", 0xdee))

print("\nDone!")
