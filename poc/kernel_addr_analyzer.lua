--[[
    kernel_addr_analyzer.lua
    Analyze the 10 kernel addresses near syscall_wrapper[454]
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")

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

S.resolve({close=6, getpid=20})

print("[+] Kernel Address Analyzer\n")

-- Find sc454 wrapper
local w454 = toaddr(S.syscall_wrapper[454])
print(string.format("sc454 wrapper at 0x%x\n", w454))

-- Scan forward for kernel pointers
local kptrs = {}
for off = 0, 0x10000, 8 do
    local addr = w454 + off
    local lo = tonn(mem.read_dword(addr))
    local hi = tonn(mem.read_dword(addr+4))
    local val = hi * 4294967296 + lo
    if hi >= 0xFFFF8000 or hi == 0xFFFFFFFF then
        table.insert(kptrs, {off=off, val=val, hi=hi, lo=lo})
        if #kptrs >= 20 then break end
    end
end

print(string.format("Found %d kernel addresses\n", #kptrs))

if #kptrs == 0 then return end

-- Print each address
print("[*] Kernel addresses:\n")
for _, p in ipairs(kptrs) do
    local aligned = (p.val % 4096 == 0) and "YES" or "NO"
    print(string.format("  +0x%04x: 0x%016x  page_aligned=%s  hi=0x%08x lo=0x%08x",
        p.off, p.val, aligned, p.hi, p.lo))
end

-- Analyze upper bits patterns
print("\n[*] Upper 32 bits analysis:\n")
for _, p in ipairs(kptrs) do
    print(string.format("  0x%016x → upper=0x%08x", p.val, p.hi))
end

-- Find common upper bits
print("\n[*] Common upper bits:\n")
local common = kptrs[1].hi
for i = 2, #kptrs do
    common = bit32.band(common, kptrs[i].hi)
end
print(string.format("  AND of all upper 32 bits: 0x%08x", common))

local any = 0
for i = 1, #kptrs do
    any = bit32.bor(any, kptrs[i].hi)
end
print(string.format("  OR  of all upper 32 bits: 0x%08x", any))

-- Group by page-aligned base
print("\n[*] Hypothesized kernel bases:\n")
local bases = {}
for _, p in ipairs(kptrs) do
    local base = p.val - (p.val % 4096)
    bases[base] = (bases[base] or 0) + 1
end
for base, count in pairs(bases) do
    print(string.format("  0x%016x: %d addresses", base, count))
end

-- Check if addresses form a linear pattern
print("\n[*] Address pairs (differences):\n")
for i = 2, #kptrs do
    local diff = kptrs[i].val - kptrs[i-1].val
    local pct = (diff / 4096)
    print(string.format("  0x%016x - 0x%016x = %d (0x%x) = %d pages",
        kptrs[i].val, kptrs[i-1].val, diff, diff, pct))
end

-- Check for kernel base candidates by looking at addresses mod large boundaries
print("\n[*] Kernel base candidates (mask lower bits):\n")
local masks = {0xFFFFFFFF00000000, 0xFFFFFFFFF0000000, 0xFFFFFFF000000000}
for _, mask in ipairs(masks) do
    local mhi = math.floor(mask / 4294967296)
    local mlo = mask % 4294967296
    print(string.format("  mask 0x%016x:", mask))
    local seen = {}
    for _, p in ipairs(kptrs) do
        local masked_lo = bit32.band(p.lo, mlo)
        local masked_hi = bit32.band(p.hi, mhi)
        local masked = masked_hi * 4294967296 + masked_lo
        if not seen[masked] then
            seen[masked] = true
            print(string.format("    0x%016x: 0x%016x", masked, p.val - masked))
        end
    end
end

print("\n[+] Analysis complete")
