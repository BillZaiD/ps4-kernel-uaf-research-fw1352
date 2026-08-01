--[[
    sbl_syscall_probe.lua
    Systematic probe of SBL syscall range (400-599)
    Phase 1: wrapper scan only (safe)
    Phase 2: test calls with varying args
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({close=6, getpid=20})

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
    if w == 0 then return -2, "no wrapper" end
    local tramp = w + find_tramp(w)
    local r = tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
    -- Lua numbers are signed doubles; wrap to unsigned for kernel values
    return r, "ok"
end

print("[+] SBL Syscall Probe - FW 13.52\n")

-- Phase 1: Scan which syscalls have wrappers
print("[Phase 1] Wrapper scan (scnos 400-599)\n")

local wrappers_found = {}
for scno = 400, 599 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        wrappers_found[#wrappers_found + 1] = scno
        print(string.format("  sc%d: wrapper at 0x%x", scno, w))
    end
end

print(string.format("\n[+] Found %d wrappers in range 400-599\n", #wrappers_found))

-- Phase 2: Call each wrapper with null args (safe - tests if syscall panics with zeros)
print("[Phase 2] Testing with zero args\n")

for _, scno in ipairs(wrappers_found) do
    local r, status = fcall(scno, 0, 0, 0, 0, 0, 0)
    print(string.format("  sc%d(0,0,0,0,0,0) = %d", scno, r))
end

-- Phase 3: Call with buffer+size args
print("\n[Phase 3] Testing with buf + size\n")

local buf = mem.alloc(0x1000)
for _, scno in ipairs(wrappers_found) do
    local r1, _ = fcall(scno, buf, 0x100, 0, 0, 0, 0)
    local r2, _ = fcall(scno, buf, 0x100, 1, 0, 0, 0)
    local r3, _ = fcall(scno, buf, 0x100, 0, 1, 0, 0)
    if r1 ~= -1 or r2 ~= -1 or r3 ~= -1 then
        print(string.format("  sc%d(buf,sz,0,0,0,0)=%d  (sz,1,0)=%d  (sz,0,1)=%d [INTERESTING]", scno, r1, r2, r3))
    else
        print(string.format("  sc%d(buf,0x100): all -1 (boring)", scno))
    end
end

-- Phase 4: Deep probe of sc454 with variations
print("\n[Phase 4] Deep probe of sc454\n")

-- Try different argument orders and combinations
local combos = {
    {buf, 0x100, 0, 0, 0, 0, "buf,0x100"},
    {0, 0, 0, 0, 0, 0, "all zero"},
    {buf, 0x100, 1, 0, 0, 0, "flags=1"},
    {buf, 0x100, 0, 1, 0, 0, "rcx=1"},
    {buf, 0x100, 0, 0, 1, 0, "r8=1"},
    {buf, 0x100, 0, 0, 0, 1, "r9=1"},
    {0, 0x100, 0, 0, 0, 0, "null buf"},
    {buf, 0x10, 0, 0, 0, 0, "small sz=0x10"},
    {buf, 0x1000, 0, 0, 0, 0, "big sz=0x1000"},
    {buf, 0x4000, 0, 0, 0, 0, "sz=0x4000"},
}

for _, c in ipairs(combos) do
    -- Poison buffer before each call
    for i = 0, 63 do mem.write_byte(buf + i, 0xEE) end
    local r = tonn(nat.fcall_with_rax(
        toaddr(S.syscall_wrapper[454]) + find_tramp(toaddr(S.syscall_wrapper[454])),
        454, c[1], c[2], c[3], c[4], c[5], c[6]
    ))
    -- Check if any buf bytes changed
    local changed = 0
    local first_val = 0
    for i = 0, 63 do
        local b = tonn(mem.read_byte(buf + i))
        if b ~= 0xEE then
            changed = changed + 1
            if first_val == 0 then first_val = b end
        end
    end
    print(string.format("  sc454(%s) = %d  buf_changed=%d  first_new_val=0x%02x", c[7], r, changed, first_val))
end

-- Phase 5: Check adjacent scnos to 454 (452-460) more carefully
print("\n[Phase 5] Adjacent range 450-470 detailed\n")

for scno = 450, 470 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        -- Three call patterns
        local r1 = tonn(nat.fcall_with_rax(w + find_tramp(w), scno, 0, 0, 0, 0, 0, 0))
        local r2 = tonn(nat.fcall_with_rax(w + find_tramp(w), scno, buf, 0x100, 0, 0, 0, 0))
        local r3 = tonn(nat.fcall_with_rax(w + find_tramp(w), scno, buf, 0x100, buf+0x800, 0, 0, 0))
        if r1 ~= -1 or r2 ~= -1 or r3 ~= -1 then
            print(string.format("  sc%d: 0=%d buf=%d buf+ptr=%d [*** NON -1 ***]", scno, r1, r2, r3))
        else
            print(string.format("  sc%d: 0=%d buf=%d buf+ptr=%d", scno, r1, r2, r3))
        end
    end
end

print("\n[+] SBL syscall probe complete")
