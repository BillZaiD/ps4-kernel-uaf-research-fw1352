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

local function mk_ev(ident, filter, flags, fflags, data, udata)
    local ev = mem.alloc(32)
    for i = 0, 31 do mem.write_byte(ev + i, 0) end
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, filter)
    mem.write_word(ev + 10, flags)
    mem.write_dword(ev + 12, fflags)
    mem.write_qword(ev + 16, data)
    mem.write_qword(ev + 24, udata)
    return ev
end

print("[*] Test multi-register\n")
local kq = tonn(S.kqueue())
print(string.format("  kq=%d\n", kq))

-- Register 1
local ev1 = mk_ev(0xb01, -11, 0x41, 0, 0, 0)
print(string.format("  ev1 at 0x%x", ev1))
local r1 = kevent(kq, ev1, 1, nil, 0, 0)
print(string.format("  ADD ev1: %d", r1))

-- Register 2
local ev2 = mk_ev(0xb02, -11, 0x41, 0, 0, 0)
print(string.format("  ev2 at 0x%x", ev2))
local r2 = kevent(kq, ev2, 1, nil, 0, 0)
print(string.format("  ADD ev2: %d\n", r2))

-- Read
local out = mem.alloc(64)
local nr = kevent(kq, nil, 0, out, 2, 0)
print(string.format("  READ: %d events\n", nr))

S.close(kq)
print("\n[+] Done")
