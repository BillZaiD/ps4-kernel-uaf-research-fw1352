local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
S.resolve({kqueue = 362, kevent = 363, close = 6})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function kevent(...)
    return tonn(S.kevent(...))
end

print("[*] 2 events both with fflags=0x80000000\n")

local kq = tonn(S.kqueue())
print(string.format("kq=%d\n", kq))

local function mk(ident)
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, 0xFFF9)
    mem.write_word(ev + 10, 0x25)
    mem.write_dword(ev + 12, 0x80000000)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

print("  ev1\n")
local e1 = mk(0x100)
local r = kevent(kq, e1, 1, nil, 0, 0)
print(string.format("  r1=%d\n", r))

print("  ev2\n")
local e2 = mk(0x200)
r = kevent(kq, e2, 1, nil, 0, 0)
print(string.format("  r2=%d\n", r))

local out = mem.alloc(64)
print("  read\n")
local nr = kevent(kq, nil, 0, out, 2, 0)
print(string.format("  nr=%d\n", nr))

S.close(kq)
print("[+] Done")
