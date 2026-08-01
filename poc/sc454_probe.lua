--[[
    sc454_probe.lua
    Investigate the working Sony syscall 454 (sbl_get_self_auth_info)
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

local function is_kptr(v)
    return v > 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
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

print("[+] sc454 Investigation\n")

-- Test 1: What args does it need?
-- sbl_get_self_auth_info(void *buf, size_t size, uint64_t *unk)
print("[*] Test 1: Argument probing\n")

-- With nil buf
local r = fcall(454, 0, 0, 0, 0, 0, 0)
print(string.format("  buf=NULL size=0 -> %d", r))

-- With small buf
local buf = mem.alloc(256)

r = fcall(454, buf, 16, 0, 0, 0, 0)
print(string.format("  buf size=16 -> %d", r))

-- Print first 32 bytes of buf
print("  Buf after sc454(16):")
local hex = ""
for j = 0, 31 do
    hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf + j)))
end
print("    " .. hex)

r = fcall(454, buf, 64, 0, 0, 0, 0)
print(string.format("  buf size=64 -> %d", r))

hex = ""
for j = 0, 63 do
    hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf + j)))
    if (j + 1) % 16 == 0 then
        print("    +" .. string.format("%02x", j - 15) .. ": " .. hex)
        hex = ""
    end
end

r = fcall(454, buf, 256, 0, 0, 0, 0)
print(string.format("  buf size=256 -> %d", r))

hex = ""
for j = 0, 63 do
    hex = hex .. string.format("%02x ", tonn(mem.read_byte(buf + j)))
    if (j + 1) % 16 == 0 then
        print("    +" .. string.format("%02x", j - 15) .. ": " .. hex)
        hex = ""
    end
end

-- Check for kernel pointers in buf
print("\n[*] Scanning for kernel pointers...")
local kptrs = 0
for j = 0, 248, 8 do
    local v = tonn(mem.read_qword(buf + j))
    if is_kptr(v) and kptrs < 5 then
        kptrs = kptrs + 1
        print(string.format("  KPTR at +%d: 0x%x", j, v))
    end
end
if kptrs == 0 then
    print("  No kernel pointers found")
end

-- Test with different sizes to find optimal
print("\n[*] Test 2: Size probing\n")
local sizes = {8, 12, 14, 16, 20, 22, 24, 28, 32, 48, 64, 128, 256}
for _, sz in ipairs(sizes) do
    local b2 = mem.alloc(sz)
    r = fcall(454, b2, sz, 0, 0, 0, 0)
    print(string.format("  size=%3d -> ret=%3d", sz, r))
end

-- Test 3: Does the return value tell us anything useful?
print("\n[*] Test 3: Repeatability\n")
for iter = 1, 5 do
    local b3 = mem.alloc(64)
    r = fcall(454, b3, 64, 0, 0, 0, 0)
    if iter == 1 then
        local hex2 = ""
        for j = 0, 31 do
            hex2 = hex2 .. string.format("%02x ", tonn(mem.read_byte(b3 + j)))
        end
        print(string.format("  iter %d: ret=%d data: %s", iter, r, hex2))
    else
        print(string.format("  iter %d: ret=%d", iter, r))
    end
end

-- Test 4: Try with 3rd arg (rdx) as output size pointer
print("\n[*] Test 4: 3rd argument as size pointer\n")
local sizep = mem.alloc(8)
mem.write_qword(sizep, 64)

r = fcall(454, buf, 256, sizep, 0, 0, 0)
print(string.format("  buf=256 sizep=64 -> ret=%d", r))
local written = tonn(mem.read_qword(sizep))
print(string.format("  *sizep after = %d", written))

mem.write_qword(sizep, 0)
r = fcall(454, buf, 256, sizep, 0, 0, 0)
print(string.format("  *sizep=0 before: ret=%d *sizep=%d", r, tonn(mem.read_qword(sizep))))

print("\n[+] Done")
