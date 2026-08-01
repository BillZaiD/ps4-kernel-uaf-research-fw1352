--[[
    find_base.lua
    Find libkernel base via wrapper table analysis
]]
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

print("[+] Find libkernel Base\n")

S.resolve({close=6, getpid=20})

-- Read ALL wrapper addresses for syscalls 0-660
local waddr = {}
local count = 0
for sc = 0, 700 do
    local addr = toaddr(S.syscall_wrapper[sc])
    if addr ~= 0 and addr < 0xFFFFFFFFFFFF then
        waddr[sc] = addr
        count = count + 1
    end
end

print(string.format("Found %d wrapper addresses\n", count))

-- Find min/max
local min_a = 0xFFFFFFFFFFFFFFFF
local max_a = 0
for sc, addr in pairs(waddr) do
    if addr < min_a then min_a = addr end
    if addr > max_a then max_a = addr end
end

print(string.format("Wrapper range: 0x%x - 0x%x\n", min_a, max_a))
print(string.format("Page aligned min: 0x%x\n", min_a - (min_a % 4096)))

-- For key syscalls, show address
local key_sc = {0, 1, 2, 3, 4, 5, 10, 20, 33, 60, 200, 454, 500, 600, 660}
for _, sc in ipairs(key_sc) do
    if waddr[sc] then
        print(string.format("  [%3d] = 0x%x", sc, waddr[sc]))
    end
end

-- Calculate estimated base: wrapper[0] is near start of .text
-- ELF header + phdrs typically < 0x1000 before .text
if waddr[0] then
    local est_base = waddr[0] - (waddr[0] % 4096)
    print(string.format("\nEstimated base from wrapper[0]: 0x%x (page of wrapper[0])", est_base))
    -- Try base candidates
    for page_off = 0, 10 do
        local candidate = est_base - page_off * 4096
        local byte0 = tonn(mem.read_byte(candidate))
        local byte1 = tonn(mem.read_byte(candidate + 1))
        if byte0 == 0x7F and byte1 == 0x45 then
            print(string.format("  ELF at 0x%x (base - %d pages)", candidate, page_off))
        end
    end
end

-- Also check if page at estimated base has ELF magic
local est = min_a - (min_a % 4096)
print(string.format("\nMin wrapper page: 0x%x", est))

local byte0 = tonn(mem.read_byte(est))
local byte1 = tonn(mem.read_byte(est + 1))
local byte2 = tonn(mem.read_byte(est + 2))
local byte3 = tonn(mem.read_byte(est + 3))
print(string.format("  Bytes: %02x %02x %02x %02x %s", byte0, byte1, byte2, byte3,
    (byte0==0x7F and byte1==0x45 and byte2==0x4C and byte3==0x46) and "<-- ELF!" or ""))

-- Check page before
byte0 = tonn(mem.read_byte(est - 4096))
byte1 = tonn(mem.read_byte(est - 4095))
byte2 = tonn(mem.read_byte(est - 4094))
byte3 = tonn(mem.read_byte(est - 4093))
print(string.format("  Page-1: %02x %02x %02x %02x %s", byte0, byte1, byte2, byte3,
    (byte0==0x7F and byte1==0x45 and byte2==0x4C and byte3==0x46) and "<-- ELF!" or ""))

-- Wrapper table entries per page
print("\nWrapper addresses on each page:\n")
local pages = {}
for sc, addr in pairs(waddr) do
    local p = addr - (addr % 4096)
    pages[p] = (pages[p] or 0) + 1
end
local sorted_p = {}
for p, _ in pairs(pages) do sorted_p[#sorted_p + 1] = p end
table.sort(sorted_p)
for _, p in ipairs(sorted_p) do
    print(string.format("  Page 0x%x: %d wrappers", p, pages[p]))
end

-- Spacing analysis for consecutive wrappers
print("\nSpacing for first 50 wrappers:\n")
for sc = 1, 50 do
    if waddr[sc] and waddr[sc-1] then
        local diff = waddr[sc] - waddr[sc-1]
        print(string.format("  [%d-%d] = %d bytes", sc-1, sc, diff))
    end
end

print("\n[+] OK")
