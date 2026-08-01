-- Advanced sysctl exploration
print("=== Advanced sysctl ===\n")

local wt = syscall.syscall_wrapper
local w202 = wt[202]

-- Helper
local function sysctl_mib(mib_vals, oldlen_val)
    local mib = memory.alloc(#mib_vals * 4 + 4)
    for i, v in ipairs(mib_vals) do
        memory.write_dword(mib + (i-1)*4, v)
    end
    local oldp = memory.alloc(4096)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, oldlen_val or 4096)
    
    local ok, r = pcall(native.fcall, w202, mib, #mib_vals, oldp, oldlenp, 0, 0)
    if not ok then return nil end
    
    local ret = 0
    if type(r) == "table" then ret = r.h * 4294967296 + r.l end
    if ret ~= 0 then return nil, ret end
    
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    if len == 0 then return "", 0 end
    
    -- Read string
    local s = ""
    for i = 0, math.min(len, 4095) do
        local b = memory.read_byte(oldp + i)
        if b.l == 0 then break end
        s = s .. string.char(b.l)
    end
    return s, len
end

local function sysctl_int(mib_vals)
    local mib = memory.alloc(#mib_vals * 4 + 4)
    for i, v in ipairs(mib_vals) do
        memory.write_dword(mib + (i-1)*4, v)
    end
    local oldp = memory.alloc(8)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, 8)
    
    local ok, r = pcall(native.fcall, w202, mib, #mib_vals, oldp, oldlenp, 0, 0)
    if not ok then return nil end
    
    local ret = 0
    if type(r) == "table" then ret = r.h * 4294967296 + r.l end
    if ret ~= 0 then return nil end
    
    -- For integers, read based on oldlen
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    
    if len == 4 then
        local v = memory.read_dword(oldp)
        return v.l or 0
    elseif len == 8 then
        local v = memory.read_qword(oldp)
        return v.h * 4294967296 + v.l
    end
    return nil
end

-- Kernel version (already got)
-- r228995/release_branches/release_13.520 Jun 11 2026 05:25:24

-- Try to find kernel base: kern.boottime returns timeval struct
-- CTL_KERN=1, KERN_BOOTTIME=21
print("--- kern.boottime (1,21) ---")
local s, l = sysctl_mib({1, 21}, 16)
if s then
    print(string.format("str='%s' len=%d", s, l))
else
    print("error or binary data")
end

-- kern.clockrate (1,12) - returns clockinfo struct
print("\n--- kern.clockrate (1,12) ---")
local s, l = sysctl_mib({1, 12}, 32)
if s then
    print(string.format("str='%s' len=%d", s, l))
else
    print("binary struct (non-string)")
end

-- kern.consdev (1,18)
print("\n--- kern.consdev (1,18) ---")
local s, l = sysctl_mib({1, 18}, 256)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- Try to find kernel pointers via sysctl
-- vm.keg (VM related)
print("\n--- vm.stats (2,1) ---")
local s, l = sysctl_mib({2, 1}, 4096)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- kern.proc - try to get process list
print("\n--- kern.proc (1, 14, 0, 0, 0) ---")
local s, l = sysctl_mib({1, 14, 0, 0, 0}, 4096)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- kern.proc with PID arg (1, 14, PID, 0)
print("\n--- kern.proc.pid 186 (1, 14, 186, 0) ---")
local s, l = sysctl_mib({1, 14, 186, 0}, 4096)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- Try to read kern.sched.topology for CPU info
print("\n--- kern.sched.topology_spec (1, 56) ---")
local s, l = sysctl_mib({1, 56}, 4096)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- vm.kvm_size (2, 5) - size of virtual memory
print("\n--- vm.kvm_size (2,5) ---")
-- This returns a size_t
local int_val = sysctl_int({2, 5})
print(string.format("int: %s", tostring(int_val)))
if int_val then
    print(string.format("kvm_size = 0x%x (%d GB)", int_val, int_val / (1024*1024*1024)))
end

-- vm.kvm_free (2, 6)
print("\n--- vm.kvm_free (2,6) ---")
local int_val = sysctl_int({2, 6})
print(string.format("kvm_free = 0x%x", int_val or -1))

-- Try machdep info
print("\n--- machdep.physical_address_size (44, 1) ---")
local int_val = sysctl_int({44, 1})
print(string.format("phys_addr_size = 0x%x", int_val or -1))

-- Try reading kern.features
print("\n--- kern.features (1, 57) ---")
local s, l = sysctl_mib({1, 57}, 4096)
print(string.format("str='%s' len=%d", s or "nil", l or 0))

-- kern.conftxt (1, 40) - kernel configuration
print("\n--- kern.conftxt (1, 40) ---")
local s, l = sysctl_mib({1, 40}, 4096)
if s and #s > 0 then
    print(s:sub(1, 1000))
    print("...(total " .. #s .. " chars)")
end

print("\nDone!")
