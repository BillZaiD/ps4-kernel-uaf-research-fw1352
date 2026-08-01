--[[
    enumerate_modules.lua
    Enumerate modules and find ELF headers safely
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[+] Module Enumeration\n")

-- List modules to check
local module_names = {
    "libc", "libkernel", "libkernel_sys", "libSceLibcInternal",
    "libSceWebKit", "libSceVideoOut", "libSceAudioOut",
    "libScePad", "libSceSysmodule", "libSceSystemService",
    "libSceNet", "libSceSaveData", "libSceLibc",
    "libSceGnmDriver", "libSceDiscMap",
}

print("[*] Resolved module bases:\n")
for _, name in ipairs(module_names) do
    local ok, mod = pcall(find_mod_by_name, name)
    if ok and mod then
        local base_num = tonn(mod.base_addr)
        print(string.format("  %-30s = 0x%x (handle=0x%x)", name, base_num, tonn(mod.handle)))
    end
end

-- Find ELF headers by scanning mapped memory backward from known bases
print("\n[*] Searching for ELF headers...\n")

-- Use check_memory_access + read_byte to scan safely
local function find_elf_base(name, known_addr)
    if not known_addr or known_addr == 0 then return end
    print(string.format("  Scanning %s at 0x%x...", name, known_addr))
    -- Scan backward page by page
    for off = 0, -0x100000, -0x1000 do
        local addr = known_addr + off
        if not check_memory_access(addr, 4) then break end
        local b0 = tonn(mem.read_byte(addr))
        local b1 = tonn(mem.read_byte(addr + 1))
        local b2 = tonn(mem.read_byte(addr + 2))
        local b3 = tonn(mem.read_byte(addr + 3))
        if b0 == 0x7F and b1 == 0x45 and b2 == 0x4C and b3 == 0x46 then
            print(string.format("    -> ELF at 0x%x (offset -0x%x)", addr, -off))
            break
        end
    end
end

local lb = tonn(libkernel_base)
find_elf_base("libkernel", lb)

local eb = tonn(eboot_base)
find_elf_base("game", eb)

local lc = tonn(libc_base)
find_elf_base("libc", lc)

-- Now try to find kernel module info
-- First, let's try using sysctlbyname to get kernel info
print("\n[*] Kernel info via sysctlbyname:\n")
local buf = memory.alloc(0x100)
local size = memory.alloc(0x8)
memory.write_qword(size, 0x100)

-- Try kern.proc.pathname
local ok = sysctlbyname("kern.proc.pathname", buf, size, 0, 0)
if ok then
    local path = memory.read_buffer(buf, tonn(memory.read_qword(size)))
    print(string.format("  kern.proc.pathname = %s", path))
end

-- Try hw.machine
memory.write_qword(size, 0x100)
ok = sysctlbyname("hw.machine", buf, size, 0, 0)
if ok then
    local val = memory.read_buffer(buf, tonn(memory.read_qword(size)))
    print(string.format("  hw.machine = %s", val))
end

-- Try kern.ostype
memory.write_qword(size, 0x100)
ok = sysctlbyname("kern.ostype", buf, size, 0, 0)
if ok then
    local val = memory.read_buffer(buf, tonn(memory.read_qword(size)))
    print(string.format("  kern.ostype = %s", val))
end

-- Try kern.osrelease
memory.write_qword(size, 0x100)
ok = sysctlbyname("kern.osrelease", buf, size, 0, 0)
if ok then
    local val = memory.read_buffer(buf, tonn(memory.read_qword(size)))
    print(string.format("  kern.osrelease = %s", val))
end

-- Try getting current process path
memory.write_qword(size, 0x100)
ok = sysctlbyname("kern.proc.args", buf, size, 0, 0)
if ok then
    local val = memory.read_buffer(buf, tonn(memory.read_qword(size)))
    print(string.format("  kern.proc.args = %s", val))
end

-- List all available modules using the syscall table
-- Count how many modules we can enumerate
print("\n[*] Libkernel addrofs (function offsets):\n")
if type(libc_addrofs) == "table" then
    for k, v in pairs(libc_addrofs) do
        print(string.format("  libc.%s", k))
    end
end

if type(eboot_addrofs) == "table" then
    local count = 0
    for k, _ in pairs(eboot_addrofs) do
        count = count + 1
    end
    print(string.format("\n  eboot has %d resolved functions", count))
end

-- Check if we can access /dev/ entries
print("\n[*] Checking /dev/ entries...\n")
local dev_entries = {"gc", "pci", "mem", "kmem", "port", "dri"}
for _, name in ipairs(dev_entries) do
    local fd = tonn(S.open("/dev/" .. name, 0))
    if fd >= 0 then
        print(string.format("  /dev/%-10s = fd %d", name, fd))
        S.close(fd)
    end
end

print("\n[+] Done")
