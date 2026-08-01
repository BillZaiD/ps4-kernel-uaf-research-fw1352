--[[
    sbl_refined_probe.lua
    - Deep probe sc429 and sc454
    - Test remaining wrappers with buf args (not zero, to avoid crash)
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
    local tramp = w + find_tramp(w)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

local function hexdump(buf, n)
    local s = ""
    for i = 0, n-1 do
        s = s .. string.format("%02x ", tonn(mem.read_byte(buf + i)))
    end
    return s
end

print("[+] SBL Refined Probe\n")

-- Phase 1: sc429 deep probe
print("[Phase 1] sc429 deep probe\n")
local buf = mem.alloc(0x4000)
for i = 0, 0xFF do mem.write_byte(buf + i, 0xCC) end

print(string.format("  (0,0,0,0,0,0) = %d", fcall(429, 0,0,0,0,0,0)))

-- Test buf+size variations
for _, sz in ipairs({8, 16, 32, 64, 128, 256, 512, 0x1000, 0x2000, 0x4000}) do
    for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end
    print(string.format("  (buf,%d,0,0,0,0) = %d", sz, fcall(429, buf, sz, 0,0,0,0)))
    -- Show first 16 bytes
    local hex = ""
    for i = 0, 15 do hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf + i))) end
    print(string.format("    buf[0..15]: %s", hex))
end

-- Try with rdx as third arg
print("\n[*] sc429 with rdx (flags) variations\n")
for _, fl in ipairs({0,1,2,3,4,8,16,32,64,128,256,512,0x80000000}) do
    for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end
    local r = fcall(429, buf, 0x100, fl, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  (buf,0x100,%d,0,0,0) = %d [NON -1]", fl, r))
    end
end

-- Try with r8/r9
print("\n[*] sc429 with r8/r9 variations\n")
for _, r8v in ipairs({0,1,0x100,0x1000}) do
    for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end
    local r = fcall(429, buf, 0x100, 0, 0, r8v, 0)
    if r ~= -1 then
        print(string.format("  (buf,0x100,0,0,%d,0) = %d [NON -1]", r8v, r))
    end
end

-- Phase 2: sc454 deep probe
print("\n[Phase 2] sc454 additional probing\n")
for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end

-- Try rdx as output size ptr
local sizep = mem.alloc(8)
mem.write_qword(sizep, 0)
print(string.format("  sc454(buf,0x100,sizep,0,0,0) = %d", fcall(454, buf, 0x100, sizep, 0,0,0)))
print(string.format("    *sizep = %d", tonn(mem.read_qword(sizep))))

-- Try with rcx as pid
for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end
print(string.format("  sc454(buf,0x100,0,0,0,0) = %d", fcall(454, buf, 0x100, 0,0,0,0)))

-- Various buf sizes as before
for _, sz in ipairs({8,12,14,16,20,22,24,28,32,48,64,128,256}) do
    for i = 0, 63 do mem.write_byte(buf + i, 0xCC) end
    print(string.format("  sc454(buf,%d,0,0,0,0) = %d", sz, fcall(454, buf, sz, 0,0,0,0)))
    local hex = ""
    for i = 0, 15 do hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf + i))) end
    print(string.format("    buf[0..15]: %s", hex))
end

-- Phase 3: Call remaining wrappers with buf+size (not zero, to avoid crash)
print("\n[Phase 3] All wrappers with buf+size\n")

-- Re-scan wrappers (game was restarted)
print("[*] Scanning wrappers 400-599...\n")
local wrappers = {}
for scno = 400, 599 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then wrappers[#wrappers + 1] = scno end
end
print(string.format("[+] Found %d wrappers\n", #wrappers))

-- Call each with (buf, 0x100, 0, 0, 0, 0)
print("[*] Calling each with (buf, 0x100, 0, 0, 0, 0)\n")
local interesting = {}
for _, scno in ipairs(wrappers) do
    print(string.format("  sc%d...", scno))
    for i = 0, 15 do mem.write_byte(buf + i, 0xCC) end
    local r = fcall(scno, buf, 0x100, 0, 0, 0, 0)
    print(string.format("    = %d", r))
    if r ~= -1 then
        table.insert(interesting, {scno=scno, r=r})
        local hex = hexdump(buf, 16)
        print(string.format("    buf[0..15]: %s", hex))
    end
    -- Check for kernel pointers in buf
    local kptrs = 0
    for j = 0, 248, 8 do
        local v = tonn(mem.read_qword(buf + j))
        if v > 0xFFFF800000000000 then kptrs = kptrs + 1 end
    end
    if kptrs > 0 then print(string.format("    kernel_ptrs_in_buf: %d", kptrs)) end
end

-- Summary
print("\n[+] Summary: Interesting syscalls (non -1)\n")
for _, v in ipairs(interesting) do
    print(string.format("  sc%d -> %d", v.scno, v.r))
end

local total_tested = #wrappers
print(string.format("\n[+] Tested %d wrappers, %d returned non--1", total_tested, #interesting))

print("\n[+] Done")
