--[[
    sc454_zero_test.lua
    Call sc454 on zeroed buffer and look for any non-zero bytes
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

print("[+] sc454 zero-buffer test\n")

-- Allocate clean zeroed buffer
local buf = mem.alloc(256)
local r = fcall(454, buf, 256, 0, 0, 0, 0)
print(string.format("  sc454(buf,256) = %d\n", r))

-- Scan for any non-zero qwords
local non_zero = 0
for off = 0, 248, 8 do
    local v = tonn(mem.read_qword(buf + off))
    if v ~= 0 then
        non_zero = non_zero + 1
        if non_zero <= 20 then
            print(string.format("  [+%d] 0x%016x", off, v))
        end
    end
end
print(string.format("\n  Total non-zero qwords: %d/32", non_zero))

-- Also check individual bytes at each qword
if non_zero > 0 then
    print("\n[*] Non-zero qwords (format is raw qword value):\n")
    -- (just the qwords above are sufficient)
end

-- Try different sizes
print("\n[*] Size probing with zeroed buffers:\n")
local sizes = {14, 16, 22, 24, 32, 64, 128, 256}
for _, sz in ipairs(sizes) do
    local b2 = mem.alloc(sz)
    r = fcall(454, b2, sz, 0, 0, 0, 0)
    local nz = 0
    for off = 0, sz - 8, 8 do
        if tonn(mem.read_qword(b2 + off)) ~= 0 then
            nz = nz + 1
        end
    end
    print(string.format("  size=%3d ret=%3d non_zero_qwords=%d", sz, r, nz))
    if nz > 0 then
        for off = 0, sz - 8, 8 do
            local v = tonn(mem.read_qword(b2 + off))
            if v ~= 0 then
                print(string.format("    [+%d] 0x%x", off, v))
            end
        end
    end
end

print("\n[+] Done")
