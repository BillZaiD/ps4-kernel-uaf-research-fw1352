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

print("[*] ev1 with trig, ev2 without\n")

local kq = tonn(S.kqueue())

local function mk(ident, trig)
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, 0xFFF9)
    mem.write_word(ev + 10, 0x25)
    mem.write_dword(ev + 12, trig and 0x80000000 or 0)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

print("  ev1 (trig)\n")
local e1 = mk(0x100, true)
local r = kevent(kq, e1, 1, nil, 0, 0)
print(string.format("  r1=%d\n", r))

print("  ev2 (no trig)\n")
local e2 = mk(0x200, false)
r = kevent(kq, e2, 1, nil, 0, 0)
print(string.format("  r2=%d\n", r))

local out = mem.alloc(64)
local nr = kevent(kq, nil, 0, out, 2, 0)
print(string.format("  nr=%d\n", nr))
for i = 0, nr-1 do
    local id = tonn(mem.read_qword(out + i*32))
    local d = tonn(mem.read_qword(out + i*32 + 16))
    print(string.format("  [%d] ident=0x%x data=%d", i, id, d))
end

S.close(kq)
print("[+] Done")
