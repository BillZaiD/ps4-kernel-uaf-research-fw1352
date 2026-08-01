--[[
    try_kernel_rw.lua
    Attempt to initialize kernel R/W and then use kernel tools
]]
local S = rawget(_G, "syscall")

print("[+] Kernel R/W Initialization Attempt\n")

-- Read libkernel_base properly
local function uint64_to_num(v)
    if type(v) ~= "table" then return tonumber(tostring(v)) or 0 end
    local h = tonumber(tostring(v.h)) or 0
    local l = tonumber(tostring(v.l)) or 0
    if h == 0 then return l end
    return h * 4294967296 + l
end

print(string.format("  FW_VERSION = %s\n", tostring(FW_VERSION)))
print(string.format("  PLATFORM = %s\n", tostring(PLATFORM)))
print(string.format("  is_kernel_rw_available() = %s\n", tostring(is_kernel_rw_available())))
print(string.format("  is_jailbroken() = %s\n", tostring(is_jailbroken())))

-- Get libkernel base
print(string.format("  libkernel_base = 0x%x\n", uint64_to_num(libkernel_base)))
print(string.format("  eboot_base = 0x%x\n", uint64_to_num(eboot_base)))

-- Try to call initialize_kernel_rw
print("\n[*] Attempting initialize_kernel_rw()...\n")
local ok, result = pcall(initialize_kernel_rw)
if ok then
    print(string.format("  Result: %s\n", tostring(result)))
    print(string.format("  is_kernel_rw_available() now: %s\n", tostring(is_kernel_rw_available())))
    print(string.format("  is_jailbroken() now: %s\n", tostring(is_jailbroken())))
else
    print(string.format("  FAILED: %s\n", tostring(result)))
end

-- Check memory access
print("\n[*] Memory access:\n")
local cm_ok, cm = pcall(check_memory_access)
if cm_ok then
    print(string.format("  check_memory_access() = %s\n", tostring(cm)))
end

-- If kernel R/W is available, test it
local krw = is_kernel_rw_available()
print(string.format("\n  Kernel R/W available: %s\n", tostring(krw)))

if krw then
    print("[*] Testing kernel read...\n")
    local w454 = uint64_to_num(S.syscall_wrapper[454])
    
    -- Try kernel.read_qword on a kernel address
    local kbase = get_kernel_offset("kernel_base")
    if kbase then
        local kb_num = uint64_to_num(kbase)
        print(string.format("  kernel_base = 0x%x\n", kb_num))
        local kread_ok, kread = pcall(kernel.read_qword, kb_num)
        if kread_ok then
            print(string.format("  kernel.read_qword(0x%x) = 0x%x\n", kb_num, uint64_to_num(kread)))
        else
            print(string.format("  kernel.read_qword failed: %s\n", tostring(kread)))
        end
    end
    
    -- Try to read allproc
    local allproc = get_kernel_offset("allproc")
    if allproc then
        local ap_num = uint64_to_num(allproc)
        print(string.format("  allproc = 0x%x\n", ap_num))
    end
else
    print("[*] Kernel R/W not available - trying alternative initialization...\n")
    
    -- Check if there's a run_with_ps5_syscall_enabled
    local ps5_ok, ps5 = pcall(run_with_ps5_syscall_enabled)
    if ps5_ok then
        print(string.format("  run_with_ps5_syscall_enabled() = %s\n", tostring(ps5)))
    end
    
    -- Check find_proc_by_name
    local fp_ok, fp = pcall(find_proc_by_name, "SceSystemService")
    if fp_ok then
        print(string.format("  find_proc_by_name('SceSystemService') = %s\n", tostring(fp)))
    end
    
    -- Try reading /savedata0/misc.lua to understand exploit chain
    print("\n[*] Attempting to read misc.lua header...\n")
    local fok, fh = pcall(io.open, "/savedata0/misc.lua", "r")
    if fok and fh then
        print("  File opened successfully!\n")
        local line = fh:read("*l")
        local count = 0
        while line and count < 20 do
            print(string.format("  %s", line))
            line = fh:read("*l")
            count = count + 1
        end
        fh:close()
    else
        print(string.format("  io.open failed: %s\n", tostring(fh)))
    end
    
    -- Try file_read function
    local fr_ok, fr = pcall(file_read, "/savedata0/misc.lua")
    if fr_ok then
        print(string.format("  file_read returned type: %s\n", type(fr)))
    else
        print(string.format("  file_read failed: %s\n", tostring(fr)))
    end
end

-- Print the options table
print("\n[*] options table:\n")
if type(options) == "table" then
    for k, v in pairs(options) do
        if type(v) == "table" then
            print(string.format("  %s = table", k))
        elseif type(v) == "function" then
            print(string.format("  %s = function", k))
        else
            print(string.format("  %s = %s", k, tostring(v)))
        end
    end
end

-- Check is_in_sandbox
local sandbox_ok, sandbox = pcall(S.is_in_sandbox)
if sandbox_ok then
    print(string.format("\n  is_in_sandbox() = %s\n", tostring(sandbox)))
end

print("\n[+] Done")
