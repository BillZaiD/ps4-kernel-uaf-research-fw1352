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

print("[*] Using old script values: filter=-7, flags=0x25, trig=0x80000000\n")

local kq = tonn(S.kqueue())
print(string.format("  kq=%d\n", kq))

local function mk_ev(fflags)
    local ev = mem.alloc(32)
    for i = 0, 31 do mem.write_byte(ev + i, 0) end
    mem.write_qword(ev + 0, 0x100)
    mem.write_word(ev + 8, 0xFFF9)       -- filter = -7 (not -11!)
    mem.write_word(ev + 10, 0x25)        -- EV_ADD|EV_ENABLE|EV_CLEAR
    mem.write_dword(ev + 12, fflags or 0)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

-- Register + trigger
local ev = mk_ev(0x80000000)
local r = kevent(kq, ev, 1, nil, 0, 0)
print(string.format("  reg+trig: %d\n", r))

-- Read
local out = mem.alloc(32)
local nr = kevent(kq, nil, 0, out, 1, 0)
if nr > 0 then
    local data = tonn(mem.read_qword(out + 16))
    print(string.format("  read: data=%d\n", data))
else
    print(string.format("  read: nr=%d\n", nr))
end

-- Register SECOND event with different ident
local ev2 = mk_ev(0x80000000)
mem.write_qword(ev2 + 0, 0x200)  -- different ident
r = kevent(kq, ev2, 1, nil, 0, 0)
print(string.format("  second reg+trig: %d\n", r))

-- Read all
local out2 = mem.alloc(64)
nr = kevent(kq, nil, 0, out2, 2, 0)
print(string.format("  second read: %d events\n", nr))
for i = 0, nr-1 do
    local d = tonn(mem.read_qword(out2 + i*32 + 16))
    local id = tonn(mem.read_qword(out2 + i*32 + 0))
    print(string.format("    [%d] ident=0x%x data=%d", i, id, d))
end

S.close(kq)
print("[+] Done")
