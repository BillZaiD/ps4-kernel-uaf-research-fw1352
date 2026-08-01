--[[
    examine_kernel_tools2.lua
    Examine kernel tools - avoid assert functions
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

print("[+] Kernel Tools Examination v2\n")

print(string.format("  FW_VERSION = %s\n", tostring(FW_VERSION)))
print(string.format("  PLATFORM = %s\n", tostring(PLATFORM)))
print(string.format("  game_name = %s\n", tostring(game_name)))
print(string.format("  WRITABLE_PATH = %s\n", tostring(WRITABLE_PATH)))
print(string.format("  is_kernel_rw_available() = %s\n", tostring(is_kernel_rw_available())))
print(string.format("  is_jailbroken() = %s\n", tostring(is_jailbroken())))

-- Examine kernel_offset table
print("\n[*] kernel_offset table:\n")
for k, v in pairs(kernel_offset) do
    print(string.format("  %s = %s", k, tostring(v)))
end

-- Examine libkernel_base
print("\n[*] libkernel_base:\n")
if type(libkernel_base) == "table" then
    for k, v in pairs(libkernel_base) do
        print(string.format("  %s = %s", k, tostring(v)))
    end
else
    print(string.format("  = %s", tostring(libkernel_base)))
end

-- Examine eboot_base (game binary)
print("\n[*] eboot_base:\n")
if type(eboot_base) == "table" then
    for k, v in pairs(eboot_base) do
        print(string.format("  %s = %s", k, tostring(v)))
    end
else
    print(string.format("  = %s", tostring(eboot_base)))
end

-- Examine kernel table (key functions)
print("\n[*] kernel table:\n")
for k, v in pairs(kernel) do
    if type(v) == "function" then
        print(string.format("  kernel.%s()", k))
    end
end

-- Check get_kernel_offset
print("\n[*] Kernel offsets via get_kernel_offset:\n")
local test_names = {"kernel_base", "allproc", "curproc", "vmspace", "pmap", "cr3"}
for _, name in ipairs(test_names) do
    local ok, val = pcall(get_kernel_offset, name)
    if ok then
        print(string.format("  get_kernel_offset('%s') = %s", name, tostring(val)))
    else
        print(string.format("  get_kernel_offset('%s') = proc %s", name, tostring(val):sub(1, 50)))
    end
end

-- Check ps4_kernel_offset_list  
print("\n[*] ps4_kernel_offset_list entries:\n")
for k, v in pairs(ps4_kernel_offset_list) do
    if type(v) == "table" then
        print(string.format("  %s = table (size=%d)", k, #v))
    else
        print(string.format("  %s = %s", k, tostring(v)))
    end
end

-- Get process info
print("\n[*] Process:\n")
local pid_ok, pid = pcall(S.getpid)
if pid_ok then print(string.format("  PID = %s", tostring(pid))) end

local vm_ok, vm = pcall(get_curproc_vmid)
if vm_ok then print(string.format("  VMID = %s", tostring(vm))) end

-- Try virt_to_phys on a known address
local wrapper_addr = tostring(S.syscall_wrapper[454])
print(string.format("\n[*] Address translation:\n"))
print(string.format("  wrapper[454] = %s\n", wrapper_addr))

local v2p_ok, phys = pcall(virt_to_phys, wrapper_addr)
if v2p_ok then
    print(string.format("  virt_to_phys(0x%s) = 0x%s\n", wrapper_addr, tostring(phys)))
else
    print(string.format("  virt_to_phys failed: %s\n", tostring(phys):sub(1, 60)))
end

-- Check dlsym
print("[*] dlsym tests:\n")
local libs = {"libkernel", "libc", "SceLibc", "libkernel_sys"}
for _, lib in ipairs(libs) do
    local ok, res = pcall(dlsym, {lib, "getpid"})
    if ok then
        print(string.format("  dlsym('%s', 'getpid') = %s", lib, tostring(res)))
    end
end

-- Check get_kernel_offset for version-specific offsets
print("\n[*] get_ps4_kernel_offset:\n")
for _, name in ipairs(test_names) do
    local ok, val = pcall(get_ps4_kernel_offset, name)
    if ok and val ~= nil then
        print(string.format("  '%s' = %s", name, tostring(val)))
    end
end

print("\n[*] Memory check functions:\n")
local chk_ok, chk = pcall(check_memory_access)
if chk_ok then
    print(string.format("  check_memory_access() = %s", tostring(chk)))
end

print("\n[+] Done")
