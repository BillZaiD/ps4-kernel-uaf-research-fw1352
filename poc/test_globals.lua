-- Test available power functions
print("=== Testing globals ===\n")

-- 1. sysctlbyname
print("--- sysctlbyname ---")
local function try_sysctl(name)
    local ok, r = pcall(sysctlbyname, name)
    if ok then
        print(string.format("%s = %s", name, tostring(r)))
    else
        print(string.format("%s = ERROR: %s", name, tostring(r)))
    end
end

try_sysctl("kern.ostype")
try_sysctl("kern.osrelease")
try_sysctl("kern.version")
try_sysctl("hw.machine")
try_sysctl("hw.model")
try_sysctl("hw.ncpu")
try_sysctl("kern.boottime")
try_sysctl("vm.vmtotal")

-- 2. dlsym
print("\n--- dlsym ---")
local ok, r = pcall(dlsym, "libkernel", "sysctl")
print(string.format("dlsym(libkernel, sysctl): %s", tostring(r)))

-- Try various handles
for _, h in ipairs({"libkernel.sprx", "libkernel", "SceLibkernel", "libSceLibkernelInternal"}) do
    local ok, r = pcall(dlsym, h, "sysctl")
    if ok then
        print(string.format("dlsym(%s, sysctl): %s", h, tostring(r)))
    end
end

-- 3. find_mod_by_name
print("\n--- find_mod_by_name ---")
local ok, r = pcall(find_mod_by_name, "libkernel")
if ok then
    print(string.format("find_mod_by_name(libkernel): %s", tostring(r)))
else
    print(string.format("find_mod_by_name: ERROR: %s", tostring(r)))
end

-- 4. get_proc_cr3
print("\n--- get_proc_cr3 ---")
local ok, r = pcall(get_proc_cr3)
if ok and type(r) == "table" then
    print(string.format("CR3 = 0x%x%08x", r.h or 0, r.l or 0))
else
    print(string.format("get_proc_cr3: %s", tostring(r)))
end

-- 5. get_curproc_vmid
print("\n--- get_curproc_vmid ---")
local ok, r = pcall(get_curproc_vmid)
print(string.format("VMID = %s", tostring(r)))

-- 6. os.execute
print("\n--- os.execute ---")
local ok, r = pcall(os.execute, "id")
print(string.format("os.execute(id): %s", tostring(r)))

-- 7. virt_to_phys
print("\n--- virt_to_phys ---")
local buf = memory.alloc(0x1000)
local ok, r = pcall(virt_to_phys, buf)
if ok and type(r) == "table" then
    print(string.format("virt_to_phys(buf) = 0x%x%08x", r.h or 0, r.l or 0))
else
    print(string.format("virt_to_phys: %s", tostring(r)))
end

-- 8. phys_to_dmap
if ok and type(r) == "table" then
    local paddr = r
    local ok2, r2 = pcall(phys_to_dmap, paddr)
    if ok2 and type(r2) == "table" then
        print(string.format("phys_to_dmap = 0x%x%08x", r2.h or 0, r2.l or 0))
    end
end

-- 9. check_jailbroken
print("\n--- jailbroken check ---")
local ok, r = pcall(check_jailbroken)
print(string.format("check_jailbroken: %s", tostring(r)))

local ok, r = pcall(is_jailbroken)
print(string.format("is_jailbroken: %s", tostring(r)))

local ok, r = pcall(is_kernel_rw_available)
print(string.format("is_kernel_rw_available: %s", tostring(r)))

print("\nDone!")
