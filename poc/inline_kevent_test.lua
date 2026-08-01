local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
S.resolve({kqueue = 362, kevent = 363, close = 6})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[*] Test begin\n")

local kq = tonn(S.kqueue())
print(string.format("kq=%d\n", kq))

-- Build two events ahead of time
local ev1 = mem.alloc(32)
local ev2 = mem.alloc(32)

print(string.format("ev1=0x%x ev2=0x%x\n", ev1, ev2))

for j = 0, 31 do
    mem.write_byte(ev1 + j, 0)
    mem.write_byte(ev2 + j, 0)
end
print("  cleared\n")

mem.write_qword(ev1 + 0, 0xb01)
mem.write_word(ev1 + 8, 0xFFF5)
mem.write_word(ev1 + 10, 0x41)
mem.write_dword(ev1 + 12, 0)
mem.write_qword(ev1 + 16, 0)
mem.write_qword(ev1 + 24, 0)
print("  ev1 built\n")

mem.write_qword(ev2 + 0, 0xb02)
mem.write_word(ev2 + 8, 0xFFF5)
mem.write_word(ev2 + 10, 0x41)
mem.write_dword(ev2 + 12, 0)
mem.write_qword(ev2 + 16, 0)
mem.write_qword(ev2 + 24, 0)
print("  ev2 built\n")

print("  Calling kevent(ev1)...\n")
local r1 = S.kevent(kq, ev1, 1, nil, 0, 0)
print(string.format("  kevent1 = %s\n", tostring(r1)))

print("  Calling kevent(ev2)...\n")
local r2 = S.kevent(kq, ev2, 1, nil, 0, 0)
print(string.format("  kevent2 = %s\n", tostring(r2)))

print("  Reading...\n")
local out = mem.alloc(64)
for j = 0, 63 do mem.write_byte(out + j, 0xCC) end
local nr = S.kevent(kq, nil, 0, out, 2, 0)
print(string.format("  read = %s\n", tostring(nr)))

S.close(kq)
print("[+] Done")
