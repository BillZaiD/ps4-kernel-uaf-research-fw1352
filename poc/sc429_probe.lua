--[[
    sc429_probe.lua
    Deep probe of sc429 which returned 14 with zero args
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

print("[+] sc429 deep probe\n")

-- Test sc429 with various args
local buf = mem.alloc(0x1000)
for i = 0, 0xFF do mem.write_byte(buf + i, 0xCC) end

-- Pattern A: zero args
print(string.format("  (0,0,0,0,0,0) = %d", fcall(429, 0,0,0,0,0,0)))

-- Pattern B: buf+size
print(string.format("  (buf,0x100,0,0,0,0) = %d", fcall(429, buf,0x100,0,0,0,0)))

-- Check buf for changes
local changed = 0
for i = 0, 255 do
    if tonn(mem.read_byte(buf + i)) ~= 0xCC then changed = changed + 1 end
end
print(string.format("  buf changed bytes: %d", changed))

-- Pattern C: various arg combos
print(string.format("  (buf,0x400,0,0,0,0) = %d", fcall(429, buf,0x400,0,0,0,0)))
print(string.format("  (buf,0x100,0x100,0,0,0) = %d", fcall(429, buf,0x100,0x100,0,0,0)))
print(string.format("  (0,0x100,0,0,0,0) = %d", fcall(429, 0,0x100,0,0,0,0)))
print(string.format("  (buf,0,0,0,0,0) = %d", fcall(429, buf,0,0,0,0,0)))

-- Check if sc429 and sc454 have same signature
print(string.format("  sc429(buf,0x100,0,0,0,0): %d", fcall(429, buf,0x100,0,0,0,0)))
print(string.format("  sc454(buf,0x100,0,0,0,0): %d", fcall(454, buf,0x100,0,0,0,0)))

-- Try rdx as size_ptr
local sizep = mem.alloc(8)
mem.write_qword(sizep, 0)
print(string.format("  sc429(buf,0x100,sizep,0,0,0): %d", fcall(429, buf,0x100,sizep,0,0,0)))
print(string.format("  *sizep after = %d", tonn(mem.read_qword(sizep))))

print("[+] sc429 done")
