local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
S.resolve({kqueue = 362, kevent = 363, close = 6})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[*] Debug v3\n")

local kq = tonn(S.kqueue())
print(string.format("kq=%d\n", kq))

local function make_ev()
    local ev = mem.alloc(32)
    for i = 0, 31 do mem.write_byte(ev + i, 0) end
    mem.write_qword(ev + 0, 0x42)
    mem.write_word(ev + 8, 0xFFF5)
    mem.write_word(ev + 10, 0x41)
    mem.write_dword(ev + 12, 0)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

print("  make ev1\n")
local ev1 = make_ev()
print("  make ev2\n")
local ev2 = make_ev()

print("  call kevent(ev1)\n")
local r1 = S.kevent(kq, ev1, 1, nil, 0, 0)
print(string.format("  r1 = %s\n", tostring(r1)))

print("  call kevent(ev2)\n")
local r2 = S.kevent(kq, ev2, 1, nil, 0, 0)
print(string.format("  r2 = %s\n", tostring(r2)))

print("  read\n")
local out = mem.alloc(64)
local nr = S.kevent(kq, nil, 0, out, 2, 0)
print(string.format("  nr = %s\n", tostring(nr)))

S.close(kq)
print("[+] Done")
