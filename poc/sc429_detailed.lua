--[[
    sc429_detailed.lua
    - Probe sc429 with small integers (no buffers)
    - Then test problematic scnos with buf
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({close=6})

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

local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    if w == 0 then return -2 end
    return tonn(nat.fcall_with_rax(w + find_tramp(w), scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] sc429 Detailed Probe\n")

-- Phase 1: sc429 with integer args only (rdi = info_type?)
print("[Phase 1] sc429 rdi = 0..31\n")
for i = 0, 31 do
    local r = fcall(429, i, 0, 0, 0, 0, 0)
    print(string.format("  sc429(%2d, 0, 0, 0, 0, 0) = %d", i, r))
end

-- Try rsi variations with rdi=0
print("\n[Phase 2] sc429 rsi = 0..7 (rdi=0)\n")
for i = 0, 7 do
    local r = fcall(429, 0, i, 0, 0, 0, 0)
    print(string.format("  sc429(0, %d, 0, 0, 0, 0) = %d", i, r))
end

-- Try rdx variations
print("\n[Phase 3] sc429 rdx = 0..7 (rdi=0, rsi=0)\n")
for i = 0, 7 do
    local r = fcall(429, 0, 0, i, 0, 0, 0)
    print(string.format("  sc429(0, 0, %d, 0, 0, 0) = %d", i, r))
end

-- Phase 4: sc454 verification
print("\n[Phase 4] sc454 verification\n")
local buf = mem.alloc(0x1000)
for i = 0, 15 do mem.write_byte(buf + i, 0xCC) end
print(string.format("  sc454(0,0,0,0,0,0) = %d", fcall(454, 0,0,0,0,0,0)))
print(string.format("  sc454(buf,0x100,0,0,0,0) = %d", fcall(454, buf,0x100,0,0,0,0)))
print(string.format("  sc454(buf,0x10,0,0,0,0) = %d", fcall(454, buf,0x10,0,0,0,0)))

-- Phase 5: Test sc431 onwards with buf+size starting from sc431
print("\n[Phase 5] Testing sc431-444 with buf+size\n")
local buf2 = mem.alloc(0x1000)
for i = 0, 15 do mem.write_byte(buf2 + i, 0xCC) end

for scno = 431, 444 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        print(string.format("  sc%d...", scno))
        for i = 0, 15 do mem.write_byte(buf2 + i, 0xCC) end
        local r = tonn(nat.fcall_with_rax(w + find_tramp(w), scno, buf2, 0x100, 0, 0, 0, 0))
        print(string.format("    = %d", r))
        if r ~= -1 then
            local hex = ""
            for j = 0, 15 do hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf2 + j))) end
            print(string.format("    buf: %s", hex))
        end
    end
end

print("\n[+] Phase 5 complete (survived)")
