--[[
    pipe_kernel_read.lua
    Use pipe check_memory_access technique to probe kernel addresses
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

print("[+] Pipe-based Kernel Probe\n")

-- First confirm check_memory_access works
local test_addr = 0x81aee8000 -- libkernel_base
local cm_ok1 = check_memory_access(test_addr, 8)
print(string.format("  libkernel_base readable: %s\n", tostring(cm_ok1)))

-- Test a known kernel address from our earlier scan
-- We found addresses with patterns like 0xFFFFFFxx
-- But for pipe write, the address must be in the process's address space
-- Kernel addresses are NOT in user space

-- The kernel addresses we found (0xFFFFFFxx) are likely NOT accessible via pipe
-- because they're in kernel space, not mapped in user space

-- But the SCE libraries (libkernel, libc, etc.) ARE in user space
-- Let's probe libkernel's mapped region
print("[*] Probing libkernel mappings...\n")

local base = 0x81aee8000
-- Calculate wrapper address
local wrapper_addr = tonumber(tostring(S.syscall_wrapper[454]))

-- Probe various regions around libkernel
local probes = {
    {"base", base},
    {"base+0x1000", base + 0x1000},
    {"base+0x100000", base + 0x100000},
    {"wrapper", wrapper_addr},
    {"wrapper-0x1000", wrapper_addr - 0x1000},
    {"wrapper-0x2000", wrapper_addr - 0x2000},
    {"wrapper-0x3000", wrapper_addr - 0x3000},
    {"wrapper+0x1000", wrapper_addr + 0x1000},
    {"wrapper+0x100000", wrapper_addr + 0x100000},
}

for _, p in ipairs(probes) do
    local ok = check_memory_access(p[2], 8)
    print(string.format("  %s (0x%x) = %s", p[1], p[2], tostring(ok)))
end

-- Now try to FIND the end of mapped kernel/user memory
-- Scan around libkernel to find all mapped pages
print("\n[*] Mapping libkernel size...\n")

local page_size = 0x1000
-- Search forward
for off = 0, 0x100000, page_size do
    local addr = wrapper_addr + off
    if not check_memory_access(addr, 1) then
        print(string.format("  unmapped at wrapper+0x%x (0x%x)", off, addr))
        break
    end
end

-- Search backward
for off = 0, -0x100000, -page_size do
    local addr = wrapper_addr + off
    if not check_memory_access(addr, 1) then
        print(string.format("  unmapped at wrapper%d (0x%x)", off, addr))
        break
    end
end

-- Try reading from ELF header if we know base is readable
print("\n[*] Reading ELF header...\n")
if check_memory_access(base, 16) then
    local b0 = tonumber(tostring(mem.read_byte(base)))
    local b1 = tonumber(tostring(mem.read_byte(base + 1)))
    local b2 = tonumber(tostring(mem.read_byte(base + 2)))
    local b3 = tonumber(tostring(mem.read_byte(base + 3)))
    print(string.format("  Bytes at base: %02x %02x %02x %02x\n", b0, b1, b2, b3))
    if b0 == 0x7F and b1 == 0x45 then
        print("  [OK] libkernel_base IS valid ELF!\n")
    end
end

-- More importantly: try to find if ANY kernel addresses are readable
-- In the process's page tables, there might be some kernel addresses mapped
-- especially GPU-related or shared memory

print("\n[*] Scanning for kernel-range readable memory...\n")
-- Scan specific ranges where kernel might be mapped
-- On PS4/Orbis, kernel is typically mapped at fixed offsets

-- The kernel addresses we found were all 0xFFFFFFxx
-- Let's see if the dmap region is accessible
-- dmap (direct map) is where kernel maps physical memory into kernel space
-- On PS4, this might be accessible for GPU-related operations

-- Try common dmap base candidates
local dmap_candidates = {
    0xFFFFC10000000000, -- PS5-like
    0xFFFFFF0000000000, -- generic
    0xFFFF800000000000, -- kernel space start
}

for _, dmap in ipairs(dmap_candidates) do
    local ok = check_memory_access(dmap, 8)
    print(string.format("  dmap @ 0x%x: %s", dmap, tostring(ok)))
end

-- Try to read the kernel addresses we found earlier using pipe
-- These were found near syscall_wrapper[454]
local known_kaddrs = {
    {off=0x01b8, val=0xffffffe181c18800},
    {off=0x0348, val=0xfffffcb0e8c93000},
    {off=0x0e50, val=0xfffffeb7850f0000},
}

for _, ka in ipairs(known_kaddrs) do
    local ok = check_memory_access(ka.val, 8)
    print(string.format("  kaddr+0x%x (0x%x): %s", ka.off, ka.val, tostring(ok)))
end

print("\n[+] Done")
