-- Check available syscalls and try sysctl (202)
print("=== Available Syscalls ===\n")

-- Print the count of syscall wrappers
local count = 0
local max_num = 0
local min_num = 999
for k, v in pairs(syscall.syscall_wrapper) do
    if type(k) == "number" then
        count = count + 1
        if k > max_num then max_num = k end
        if k < min_num then min_num = k end
    end
end
print(string.format("Total wrappers: %d, range: %d-%d", count, min_num, max_num))

-- Check specific interesting syscall numbers
local interesting = {
    3,    -- read
    4,    -- write
    5,    -- open
    6,    -- close
    9,    -- mmap
    10,   -- mprotect
    11,   -- munmap
    20,   -- getpid
    24,   -- getuid
    54,   -- ioctl
    85,   -- swapon
    88,   -- reboot
    140,  -- kldload
    202,  -- sysctl
    203,  -- sysctlbyname
    302,  -- cap_fcntls_limit
    304,  -- cap_ioctls_limit
    305,  -- cap_ioctls_get
    311,  -- kldsym
    410,  -- kldunload
    431,  -- kldstat
    443,  -- procctl
    462,  -- __sysctl
    575,  -- modfind
    576,  -- modnext
    577,  -- modstat
}

print("\n--- Checking specific syscalls ---")
for _, num in ipairs(interesting) do
    local w = syscall.syscall_wrapper[num]
    if w then
        print(string.format("  syscall %3d: AVAILABLE", num))
    end
end

-- Now try sysctl (202) to read kernel info
print("\n--- Testing sysctl (202) ---")
local w202 = syscall.syscall_wrapper[202]
if w202 then
    -- MIB for kern.ostype = {1, 1}
    -- Need to construct MIB in memory
    local mib = memory.alloc(0x100)
    memory.write_dword(mib, 0, 1)  -- CTL_KERN
    memory.write_dword(mib, 1, 1)  -- KERN_OSTYPE
    
    local oldp = memory.alloc(0x100)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, 0, 0x100)
    
    -- sysctl(mib, 2, oldp, oldlenp, NULL, 0)
    local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
    if ok then
        local ret_val = 0
        if type(r) == "table" then ret_val = r.h * 4294967296 + r.l end
        print(string.format("  ret = 0x%x", ret_val))
        
        local len = memory.read_qword(oldlenp, 0)
        print(string.format("  oldlen = %d", len.l or 0))
        
        -- Read the string
        local s = ""
        for i = 0, (len.l or 0) - 1 do
            local b = memory.read_byte(oldp + i)
            if b.l == 0 then break end
            s = s .. string.char(b.l)
        end
        print(string.format("  value = '%s'", s))
    else
        print(string.format("  ERROR: %s", tostring(r)))
    end
    
    -- Try kern.version (1, 4)
    print("\n--- Testing sysctl kern.version ---")
    memory.write_dword(mib, 0, 1)  -- CTL_KERN
    memory.write_dword(mib, 1, 4)  -- KERN_VERSION
    memory.write_qword(oldlenp, 0, 0x100)
    
    local ok, r = pcall(native.fcall, w202, mib, 2, oldp, oldlenp, 0, 0)
    if ok then
        local len = memory.read_qword(oldlenp, 0)
        local s = ""
        for i = 0, (len.l or 0) - 1 do
            local b = memory.read_byte(oldp + i)
            if b.l == 0 then break end
            s = s .. string.char(b.l)
        end
        print(string.format("  value = '%s'", s))
    end
end

print("\nDone!")
