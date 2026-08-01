--[[
    native_syscall.lua
    Find syscall;ret gadget and call any syscall number directly
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

local function find_bytes(w, b1, b2, b3, limit)
    limit = limit or 40
    for i = 0, limit do
        if tonn(mem.read_byte(w+i))==b1 and tonn(mem.read_byte(w+i+1))==b2 then
            if b3 == nil or tonn(mem.read_byte(w+i+2))==b3 then
                return i
            end
        end
    end
    return -1
end

print("[+] Native Syscall Gadget Finder\n")

-- Use sc454's wrapper as base (known to work)
local w454 = toaddr(S.syscall_wrapper[454])
print(string.format("sc454 wrapper at 0x%x\n", w454))

-- Dump wrapper bytes
print("[*] Dumping sc454 wrapper bytes:\n")
local hex = ""
for i = 0, 47 do
    hex = hex .. string.format("%02x ", tonn(mem.read_byte(w454 + i)))
    if (i+1) % 16 == 0 then hex = hex .. "\n" end
end
print(hex .. "\n")

-- Find mov r10, rcx (49 89 CA)
local tramp_off = find_bytes(w454, 0x49, 0x89, 0xCA)
print(string.format("trampoline (mov r10,rcx) at +%d\n", tramp_off))

-- Find syscall; ret after trampoline
if tramp_off >= 0 then
    local syscall_off = find_bytes(w454 + tramp_off, 0x0F, 0x05)
    if syscall_off >= 0 then
        local syscall_addr = w454 + tramp_off + syscall_off
        print(string.format("syscall at +%d (addr 0x%x)", tramp_off + syscall_off, syscall_addr))
        -- Check if ret follows
        if tonn(mem.read_byte(syscall_addr + 2)) == 0xC3 then
            print("[+] Found syscall;ret gadget!")
        end
    end
end

-- Now test: use getpid wrapper as universal trampoline
local w_getpid = toaddr(S.syscall_wrapper[20])
local tramp_gp = w_getpid + find_bytes(w_getpid, 0x49, 0x89, 0xCA)
print(string.format("\n[*] getpid wrapper at 0x%x, tramp at +%d\n", w_getpid, find_bytes(w_getpid, 0x49, 0x89, 0xCA)))

-- Function to call any sysno using getpid's trampoline
local function any_scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp_gp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

-- Phase 1: Test with known working syscalls
print("[Phase 1] Verify universal trampoline\n")
print(string.format("getpid() via universal = %d (expect pid)", any_scall(20, 0,0,0,0,0,0)))
print(string.format("close(999) via universal = %d (expect -1, EBADF)", any_scall(6, 999,0,0,0,0,0)))

-- Phase 2: Call syscalls without wrappers
print("\n[Phase 2] Syscalls without wrappers\n")
local buf = mem.alloc(0x1000)
for i = 0, 15 do mem.write_byte(buf + i, 0xEE) end

-- sc452 - no wrapper
print(string.format("sc452(buf,0x100,0,0,0,0) = %d", any_scall(452, buf, 0x100, 0,0,0,0)))
print(string.format("sc452(0,0,0,0,0,0) = %d", any_scall(452, 0,0,0,0,0,0)))
-- sc460 - no wrapper
print(string.format("sc460(buf,0x100,0,0,0,0) = %d", any_scall(460, buf, 0x100, 0,0,0,0)))
print(string.format("sc460(0,0,0,0,0,0) = %d", any_scall(460, 0,0,0,0,0,0)))

-- Phase 3: Try extended range 600-650
print("\n[Phase 3] Extended range 600-650\n")
for scno = 600, 650 do
    local r = any_scall(scno, 0, 0, 0, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d(0,0,0,0,0,0) = %d [*** NON -1 ***]", scno, r))
    end
end

-- Phase 4: Also check 540-599 that we couldn't test before
print("\n[Phase 4] SBL range 540-599 with buf\n")
for scno = 540, 599 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        local r = tonn(nat.fcall_with_rax(w + find_bytes(w, 0x49, 0x89, 0xCA), scno, buf, 0x100, 0, 0, 0, 0))
        if r ~= -1 then
            print(string.format("  sc%d(buf,0x100,0,0,0,0) = %d [INTERESTING]", scno, r))
        end
    end
end

print("\n[+] Done")
