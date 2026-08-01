--[[
    explore_gpu.lua
    Explore GPU-related functionality
]]
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[+] GPU Exploration\n")

-- Examine GPU globals
print("[*] GPU globals:\n")
print(string.format("  GPU_RW = 0x%x\n", tonn(GPU_RW)))
print(string.format("  GPU_READ = 0x%x\n", tonn(GPU_READ)))
print(string.format("  GPU_WRITE = 0x%x\n", tonn(GPU_WRITE)))

-- Examine gpu table
print("[*] gpu table:\n")
for k, v in pairs(gpu) do
    local t = type(v)
    if t == "function" then
        print(string.format("  gpu.%s()", k))
    elseif t == "table" then
        print(string.format("  gpu.%s = table", k))
    else
        print(string.format("  gpu.%s = %s", k, tostring(v)))
    end
end

-- Examine GPU_PDE tables
print("\n[*] GPU PDE:\n")
print("  GPU_PDE_SHIFT:")
for k, v in pairs(GPU_PDE_SHIFT) do
    print(string.format("    %s = %s", k, tostring(v)))
end
print("  GPU_PDE_MASKS:")
for k, v in pairs(GPU_PDE_MASKS) do
    print(string.format("    %s = %s", k, tostring(v)))
end
print(string.format("  GPU_PDE_ADDR_MASK = %s\n", tostring(GPU_PDE_ADDR_MASK)))

-- Try GPU functions
print("[*] Testing GPU functions...\n")

local ok, gvm = pcall(get_gvmspace)
if ok and gvm then
    print(string.format("  get_gvmspace() = 0x%x\n", tonn(gvm)))
else
    print(string.format("  get_gvmspace() = %s\n", tostring(gvm)))
end

-- Try alloc_main_dmem
local ok2, dmem = pcall(alloc_main_dmem, 0x1000)
if ok2 and dmem then
    print(string.format("  alloc_main_dmem(0x1000) = 0x%x\n", tonn(dmem)))
end

-- Check get_pdb2_addr
local ok3, pdb2 = pcall(get_pdb2_addr)
if ok3 and pdb2 then
    print(string.format("  get_pdb2_addr() = 0x%x\n", tonn(pdb2)))
end

-- Check get_ptb_entry_of_relative_va
local ok4, ptbe = pcall(get_ptb_entry_of_relative_va, 0x81aee8000)
if ok4 and ptbe then
    print(string.format("  get_ptb_entry_of_relative_va(0x81aee8000) = 0x%x\n", tonn(ptbe)))
end

-- Try virt_to_phys on a known userspace address
print("\n[*] Address translation:\n")
local test_addrs = {0x81aee8000, 0x67c00000, 0x107744000}
for _, addr in ipairs(test_addrs) do
    local ok5, phys = pcall(virt_to_phys, addr)
    if ok5 and phys then
        print(string.format("  virt_to_phys(0x%x) = 0x%x", addr, tonn(phys)))
    else
        print(string.format("  virt_to_phys(0x%x) = %s", addr, tostring(phys)))
    end
end

-- Check check_memory_access on the dmap address of our known phys
print("\n[*] Phys-to-dmap test:\n")
if ok5 and phys then
    local dmap = phys_to_dmap(phys)
    print(string.format("  dmap(0x%x) = 0x%x", tonn(phys), tonn(dmap)))
    local readable = check_memory_access(tonn(dmap), 8)
    print(string.format("  dmap readable: %s\n", tostring(readable)))
end

-- List all GPU-related functions
print("[*] All gpu_* functions:\n")
for k, v in pairs(_G) do
    if type(k) == "string" and string.sub(k, 1, 3) == "gpu" then
        print(string.format("  %s = %s", k, type(v)))
    end
end

-- Check for GPU-related strings
print("\n[*] GPU memory constants:\n")
local gpu_consts = {"GPU_PAGE_SIZE", "GPU_VA_SIZE", "GC_HANDLE", "gcn", "pm4"}
for _, name in ipairs(gpu_consts) do
    if _G[name] ~= nil then
        print(string.format("  %s = %s", name, tostring(_G[name])))
    end
end

print("\n[+] Done")
