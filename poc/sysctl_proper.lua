-- Proper sysctl test with correct API
print("=== Proper sysctl test ===\n")

local wt = syscall.syscall_wrapper
local w202 = wt[202]

-- Build MIB in memory: {CTL_KERN=1, KERN_OSTYPE=1}
local mib = memory.alloc(16)
memory.write_dword(mib, 1)     -- mib[0] = CTL_KERN
memory.write_dword(mib + 4, 1) -- mib[1] = KERN_OSTYPE

-- Output buffer
local oldp = memory.alloc(256)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, 0x100)  -- oldlen = 256

-- syscall(mib, 2, oldp, oldlenp, NULL, 0)
print("--- sysctl kern.ostype ---")
local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local ret = 0
    if type(r) == "table" then ret = r.h * 4294967296 + r.l end
    print(string.format("ret = 0x%x", ret))
    
    -- Read oldlen back
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    print(string.format("result len = %d", len))
    
    -- Read the string
    local s = ""
    for i = 0, len - 1 do
        local b = memory.read_byte(oldp + i)
        if b.l == 0 then break end
        s = s .. string.char(b.l)
    end
    print(string.format("value = '%s'", s))
end

-- kern.version = 1, 4
print("\n--- sysctl kern.version ---")
memory.write_dword(oldlenp, 0x100)
memory.write_dword(mib, 1)     -- CTL_KERN
memory.write_dword(mib + 4, 4) -- KERN_VERSION

local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    local s = ""
    for i = 0, math.min(len, 511) do
        local b = memory.read_byte(oldp + i)
        if b.l == 0 then break end
        s = s .. string.char(b.l)
    end
    print(string.format("value = '%s'", s))
end

-- Try to get HW info
print("\n--- sysctl hw.model ---")
memory.write_dword(oldlenp, 0x100)
memory.write_dword(mib, 6)      -- CTL_HW
memory.write_dword(mib + 4, 2)  -- HW_MODEL

local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local ret = 0
    if type(r) == "table" then ret = r.h * 4294967296 + r.l end
    local len_v = memory.read_qword(oldlenp)
    local s = ""
    for i = 0, 255 do
        local b = memory.read_byte(oldp + i)
        if b.l == 0 then break end
        s = s .. string.char(b.l)
    end
    print(string.format("ret=0x%x len=%d val='%s'", ret, len_v.l or 0, s))
end

-- Try reading physical memory info
print("\n--- sysctl hw.physmem ---")
memory.write_dword(oldlenp, 8)
memory.write_dword(mib, 6)      -- CTL_HW
memory.write_dword(mib + 4, 5)  -- HW_PHYSMEM

local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local val = memory.read_qword(oldp)
    print(string.format("physmem = 0x%x%08x", val.h or 0, val.l or 0))
end

-- Try debug sysctls
print("\n--- sysctl debug ---")
memory.write_dword(oldlenp, 0x100)
memory.write_dword(mib, 6)     -- debug = 6? No...
-- Let me try various CTL prefixes
-- CTL_DEBUG = 5
memory.write_dword(mib, 5)      -- CTL_DEBUG
memory.write_dword(mib + 4, 0)

local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local ret = 0
    if type(r) == "table" then ret = r.h * 4294967296 + r.l end
    print(string.format("debug (5,0): ret=0x%x", ret))
end

print("\nDone!")
