--[[
    sc454_detailed.lua
    Detailed investigation of sc454 - write known pattern first
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({close = 6})

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

local function find_trampoline(w, limit)
    limit = limit or 35
    for i = 0, limit do
        local b1 = mem.read_byte(w + i)
        local b2 = mem.read_byte(w + i + 1)
        local b3 = mem.read_byte(w + i + 2)
        if b1 == 0x49 and b2 == 0x89 and b3 == 0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    if w == 0 then return nil end
    local tramp = w + find_trampoline(w)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

local function fill_pattern(addr, n, pattern)
    for off = 0, n - 8, 8 do
        mem.write_qword(addr + off, pattern)
    end
end

local function read_hex(addr, n)
    local hex = ""
    for off = 0, n - 1, 8 do
        local v = tonn(mem.read_qword(addr + off))
        hex = hex .. string.format("%016x ", v)
        if (#hex > 120) then
            print("    " .. hex)
            hex = ""
        end
    end
    if #hex > 0 then print("    " .. hex) end
end

print("[+] sc454 detailed investigation\n")

-- Fill buffer with 0x4141414141414141 pattern
local buf = mem.alloc(128)
fill_pattern(buf, 128, 0x4141414141414141)

print("[*] Before sc454:\n")
read_hex(buf, 64)

-- Call sc454 with different sizes
local r = fcall(454, buf, 64, 0, 0, 0, 0)
print(string.format("\n[*] sc454(buf, 64) = %d\n", r))
read_hex(buf, 64)

-- Try sc454 with ptr to write actual size
local sizep = mem.alloc(8)
mem.write_qword(sizep, 64)
r = fcall(454, buf, 64, sizep, 0, 0, 0)
print(string.format("\n[*] sc454(buf, 64, &sizep) = %d, *sizep=%d\n", r, tonn(mem.read_qword(sizep))))
read_hex(buf, 64)

-- Check if any bytes changed (compare with original pattern)
print("\n[*] Scanning for modified bytes (not 0x4141414141414141):\n")
local modified = 0
for off = 0, 120, 8 do
    local v = tonn(mem.read_qword(buf + off))
    if v ~= 0x4141414141414141 and v ~= 0 then
        modified = modified + 1
        if modified <= 10 then
            print(string.format("  [+%d] 0x%x", off, v))
        end
    end
end
if modified == 0 then
    print("  (none - all 0x4141... or 0)\n")
end

-- Try different syscall argument arrangements
print("[*] Alternative arg arrangements:\n")

-- Maybe args are (buf, bufsize, flag)
for flag = 0, 3 do
    local b2 = mem.alloc(64)
    fill_pattern(b2, 64, 0xDEADBEEFCAFEBABE)
    r = fcall(454, b2, 64, flag, 0, 0, 0)
    local changed = 0
    for off = 0, 56, 8 do
        local v = tonn(mem.read_qword(b2 + off))
        if v ~= 0xDEADBEEFCAFEBABE and v ~= 0 then
            changed = changed + 1
            if changed <= 3 then
                print(string.format("  flag=%d off=%d changed to 0x%x", flag, off, v))
            end
        end
    end
    if changed == 0 then
        print(string.format("  flag=%d: no change (ret=%d)", flag, r))
    end
end

-- Check if it's actually sbl_get_self_auth_info by looking at size probing more carefully
print("\n[*] Size probing with non-zero pattern:\n")
local sizes = {8, 14, 15, 16, 21, 22, 23, 24, 28, 32}
for _, sz in ipairs(sizes) do
    local b3 = mem.alloc(math.max(sz, 32))
    fill_pattern(b3, 32, 0xA5A5A5A5A5A5A5A5)
    r = fcall(454, b3, sz, 0, 0, 0, 0)
    
    local changed = 0
    for off = 0, math.min(sz, 28), 8 do
        local v = tonn(mem.read_qword(b3 + off))
        if v ~= 0xA5A5A5A5A5A5A5A5 and v ~= 0 then
            changed = changed + 1
        end
    end
    print(string.format("  size=%3d ret=%3d bytes_changed=%d", sz, r, changed))
end

print("\n[+] Done")
