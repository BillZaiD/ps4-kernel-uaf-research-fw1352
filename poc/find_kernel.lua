-- Find kernel file on disk, check libkernel_base, and dump binary sysctls
print("=== Find kernel + binary sysctl dump ===\n")

-- Check libkernel_base
print(string.format("libkernel_base = %s", tostring(libkernel_base)))
if type(libkernel_base) == "table" then
    print(string.format("  h=0x%x l=0x%x", libkernel_base.h, libkernel_base.l))
end

-- Check libc_base
print(string.format("libc_base = %s", tostring(libc_base)))

-- Check eboot_base
print(string.format("eboot_base = %s", tostring(eboot_base)))

-- Search for kernel files
print("\n--- Searching for kernel files ---")
local search_paths = {
    "/boot/kernel",
    "/boot/kernel/kernel",
    "/boot/kernel.elf",
    "/system/common/kernel",
    "/system/kernel",
    "/kernel",
    "/kernel.elf",
    "/system/common/module/kernel",
    "/system/common/module/libkernel.sprx",
    "/system/common/lib/libSceSysmodule.sprx",
}

for _, p in ipairs(search_paths) do
    local exists = file_exists(p)
    if exists then
        print(string.format("  FOUND: %s", p))
        -- Try reading first 32 bytes
        local ok, f = pcall(io.open, p, "r")
        if ok and f then
            local h = f:read(32)
            f:close()
            local hex = ""
            for i = 1, #h do hex = hex .. string.format("%02x", string.byte(h, i)) end
            print(string.format("    header: %s", hex))
        end
    else
        print(string.format("  NOT FOUND: %s", p))
    end
end

-- Dump binary sysctl kern.boottime as raw bytes
print("\n--- kern.boottime raw dump ---")
local wt = syscall.syscall_wrapper
local mib = memory.alloc(16)
memory.write_dword(mib, 1)     -- CTL_KERN
memory.write_dword(mib + 4, 21) -- KERN_BOOTTIME
local oldp = memory.alloc(64)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, 64)

local ok, r = pcall(native.fcall, wt[202], mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    print(string.format("returned len = %d", len))
    
    -- Hex dump
    local hex = ""
    for i = 0, len - 1 do
        local b = memory.read_byte(oldp + i)
        hex = hex .. string.format("%02x", b.l)
    end
    print(string.format("hex: %s", hex))
    
    -- Try int interpretation
    if len >= 8 then
        local tv_sec = memory.read_qword(oldp)
        print(string.format("tv_sec = 0x%x%08x", tv_sec.h or 0, tv_sec.l or 0))
        local tv_usec = memory.read_qword(oldp + 8)
        print(string.format("tv_usec = 0x%x%08x", tv_usec.h or 0, tv_usec.l or 0))
    end
end

-- Dump kern.conftxt
print("\n--- kern.conftxt raw dump ---")
memory.write_dword(mib, 1)     -- CTL_KERN
memory.write_dword(mib + 4, 40) -- KERN_CONFTXT
memory.write_qword(oldlenp, 4096)

local ok, r = pcall(native.fcall, wt[202], mib, 2, oldp, oldlenp, 0, 0)
if ok then
    local len_v = memory.read_qword(oldlenp)
    local len = len_v.l or 0
    print(string.format("returned len = %d", len))
    
    -- Print as string (first 2000 chars)
    local s = ""
    for i = 0, math.min(len - 1, 1999) do
        local b = memory.read_byte(oldp + i)
        if b.l >= 0x20 and b.l < 0x7f then
            s = s .. string.char(b.l)
        elseif b.l == 10 then
            s = s .. "\n"
        elseif b.l == 0 then
            break
        else
            s = s .. "."
        end
    end
    print(s)
    if len > 2000 then print("...(truncated " .. len .. " total)") end
end

print("\nDone!")
