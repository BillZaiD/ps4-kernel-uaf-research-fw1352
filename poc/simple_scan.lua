local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

local wrapper = toaddr(S.syscall_wrapper[454])
print("wrapper=0x" .. string.format("%x", wrapper))

-- Read 16 dwords from wrapper to see what's there
for i = 0, 15 do
    local v = tonn(mem.read_dword(wrapper + i * 4))
    print(string.format("+%d: 0x%08x", i * 4, v))
end

-- Check if we can find the game base by scanning backward
local found = 0
for off = 0, 0x400000, 4096 do
    local addr = wrapper - off
    local magic = tonn(mem.read_dword(addr))
    if magic == 0x464C457F then
        print(string.format("ELF at 0x%x (offset -0x%x)", addr, off))
        found = addr
        break
    end
end

if found == 0 then
    print("no ELF found")
end

-- Scan forward from wrapper for kernel pointers
local kc = 0
for off = 0, 0x20000, 8 do
    local v = tonn(mem.read_qword(wrapper + off))
    if is_kptr(v) and kc < 5 then
        kc = kc + 1
        print(string.format("kptr +%d: 0x%x", off, v))
    end
end
print(string.format("kptrs: %d", kc))
