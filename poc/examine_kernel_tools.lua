--[[
    examine_kernel_tools.lua
    Examine the kernel R/W tools built into the environment
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

print("[+] Kernel Tools Examination\n")

-- Check kernel R/W availability
print("[*] Kernel R/W status:\n")
print(string.format("  is_kernel_rw_available() = %s\n", tostring(is_kernel_rw_available())))
print(string.format("  is_jailbroken() = %s\n", tostring(is_jailbroken())))
print(string.format("  check_jailbroken() = %s\n", tostring(check_jailbroken())))
print(string.format("  FW_VERSION = %s\n", tostring(FW_VERSION)))
print(string.format("  PLATFORM = %s\n", tostring(PLATFORM)))
print(string.format("  game_name = %s\n", tostring(game_name)))

-- Examine kernel_offset table
print("[*] kernel_offset table:\n")
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

-- Examine kernel table
print("\n[*] kernel table:\n")
for k, v in pairs(kernel) do
    local t = type(v)
    if t == "function" then
        print(string.format("  kernel.%s()", k))
    elseif t == "table" then
        print(string.format("  kernel.%s = table", k))
    else
        print(string.format("  kernel.%s = %s", k, tostring(v)))
    end
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

-- Examine libc_base
print("\n[*] libc_base:\n")
if type(libc_base) == "table" then
    for k, v in pairs(libc_base) do
        print(string.format("  %s = %s", k, tostring(v)))
    end
else
    print(string.format("  = %s", tostring(libc_base)))
end

-- Examine gadgets table
print("\n[*] gadgets table:\n")
if type(gadgets) == "table" then
    for k, v in pairs(gadgets) do
        if type(v) == "table" then
            print(string.format("  %s = table", k))
        else
            print(string.format("  %s = %s", k, tostring(v)))
        end
    end
end

-- Check ps4_kernel_offset_list
print("\n[*] ps4_kernel_offset_list:\n")
if type(ps4_kernel_offset_list) == "table" then
    for k, v in pairs(ps4_kernel_offset_list) do
        print(string.format("  %s = %s", k, tostring(v)))
    end
end

-- Check get_kernel_offset function
print("\n[*] get_kernel_offset:\n")
local test_offsets = {"kernel_base", "allproc", "vmspace", "curproc", "pmap", "cr3"}
for _, name in ipairs(test_offsets) do
    local ok, val = pcall(get_kernel_offset, name)
    if ok then
        print(string.format("  get_kernel_offset('%s') = %s", name, tostring(val)))
    else
        print(string.format("  get_kernel_offset('%s') = ERROR: %s", name, tostring(val)))
    end
end

-- Check get_ps4_kernel_offset
print("\n[*] get_ps4_kernel_offset:\n")
for _, name in ipairs(test_offsets) do
    local ok, val = pcall(get_ps4_kernel_offset, name)
    if ok then
        print(string.format("  get_ps4_kernel_offset('%s') = %s", name, tostring(val)))
    else
        print(string.format("  get_ps4_kernel_offset('%s') = ERROR: %s", name, tostring(val)))
    end
end

-- Check if we can get proc info
print("\n[*] Process info:\n")
local pid_ok, pid = pcall(S.getpid)
if pid_ok then
    print(string.format("  getpid() = %s\n", tostring(pid)))
end

-- Try get_curproc_vmid
local vm_ok, vm = pcall(get_curproc_vmid)
if vm_ok then
    print(string.format("  get_curproc_vmid() = %s\n", tostring(vm)))
end

-- Try get_proc_cr3
local cr3_ok, cr3 = pcall(get_proc_cr3)
if cr3_ok then
    print(string.format("  get_proc_cr3() = 0x%x\n", tonumber(tostring(cr3))))
end

-- Try check_memory_access
print("\n[*] Memory access check:\n")
local mem_ok, mem_result = pcall(check_memory_access)
if mem_ok then
    print(string.format("  check_memory_access() = %s\n", tostring(mem_result)))
end

-- Try initialize_kernel_rw
print("\n[*] Attempting initialize_kernel_rw...\n")
local init_ok, init_result = pcall(initialize_kernel_rw)
if init_ok then
    print(string.format("  initialize_kernel_rw() = %s\n", tostring(init_result)))
    print(string.format("  is_kernel_rw_available() now = %s\n", tostring(is_kernel_rw_available())))
else
    print(string.format("  initialize_kernel_rw() FAILED: %s\n", tostring(init_result)))
end

-- Check the str_hacky_list
print("\n[*] str_hacky_list:\n")
if type(str_hacky_list) == "table" then
    for k, v in pairs(str_hacky_list) do
        print(string.format("  %s = %s", k, tostring(v)))
    end
end

-- Check fcall table
print("\n[*] fcall table:\n")
if type(fcall) == "table" then
    for k, v in pairs(fcall) do
        if type(v) == "function" then
            print(string.format("  fcall.%s()", k))
        else
            print(string.format("  fcall.%s = %s", k, tostring(v)))
        end
    end
end

print("\n[+] Done")
