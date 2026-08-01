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

print("[*] Register all before reading\n")

local kq = tonn(S.kqueue())
print(string.format("kq=%d\n", kq))

local function mk(ident, fflags)
    local ev = mem.alloc(32)
    for i = 0, 31 do mem.write_byte(ev + i, 0) end
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, 0xFFF9)
    mem.write_word(ev + 10, 0x25)
    mem.write_dword(ev + 12, fflags)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

-- Register 3 events WITHOUT any read in between
print("  reg 0x100\n")
local e1 = mk(0x100, 0x80000000)
local r = kevent(kq, e1, 1, nil, 0, 0)
print(string.format("  = %d\n", r))

print("  reg 0x200\n")
local e2 = mk(0x200, 0x80000000)
local r = kevent(kq, e2, 1, nil, 0, 0)
print(string.format("  = %d\n", r))

print("  reg 0x300\n")
local e3 = mk(0x300, 0x80000000)
r = kevent(kq, e3, 1, nil, 0, 0)
print(string.format("  = %d\n", r))

-- NOW read all
print("  read all\n")
local out = mem.alloc(32 * 10)
local nr = kevent(kq, nil, 0, out, 10, 0)
print(string.format("  nr = %d\n", nr))

for i = 0, nr - 1 do
    local ident = tonn(mem.read_qword(out + i * 32))
    local data = tonn(mem.read_qword(out + i * 32 + 16))
    print(string.format("  [%d] ident=0x%x data=%d", i, ident, data))
end

S.close(kq)
print("[+] Done")
