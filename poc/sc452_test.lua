--[[
    sc452_test.lua
    Minimal test: call sc452 via universal trampoline
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

local function find_bytes(w, b1, b2, b3, lim)
    lim = lim or 40
    for i = 0, lim do
        if tonn(mem.read_byte(w+i))==b1 and tonn(mem.read_byte(w+i+1))==b2 then
            if b3==nil or tonn(mem.read_byte(w+i+2))==b3 then return i end
        end
    end
    return -1
end

-- Get universal trampoline from any working wrapper
local w_gp = toaddr(S.syscall_wrapper[20])
local tramp = w_gp + 7  -- mov r10, rcx

local function scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] Minimal sc452 test\n")
print(string.format("getpid = %d", scall(20, 0,0,0,0,0,0)))
print("[*] getpid OK, calling sc452...\n")
local buf = mem.alloc(0x1000)
print(string.format("sc452(buf,0x100) = %d", scall(452, buf, 0x100, 0,0,0,0)))
print("[+] sc452 OK")
