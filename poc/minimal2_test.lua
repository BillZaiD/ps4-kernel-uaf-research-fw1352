local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
S.resolve({kqueue = 362, kevent = 363, close = 6})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[*] Minimal multi test\n")

local kq = tonn(S.kqueue())
print(string.format("kq=%d\n", kq))

-- Build ONE event with ident=0x42 (same as working test)
local ev = mem.alloc(32)
for i = 0, 31 do mem.write_byte(ev + i, 0) end
mem.write_qword(ev + 0, 0x42)
mem.write_word(ev + 8, 0xFFF5)
mem.write_word(ev + 10, 0x41)
mem.write_dword(ev + 12, 0)
mem.write_qword(ev + 16, 0)
mem.write_qword(ev + 24, 0)

print("  ADD 0x42...\n")
local r = S.kevent(kq, ev, 1, nil, 0, 0)
print(string.format("  = %s\n", tostring(r)))

-- Modify in-place to ident=0x43
mem.write_qword(ev + 0, 0x43)
print("  ADD 0x43...\n")
r = S.kevent(kq, ev, 1, nil, 0, 0)
print(string.format("  = %s\n", tostring(r)))

local out = mem.alloc(64)
for i = 0, 63 do mem.write_byte(out + i, 0xCC) end
print("  READ...\n")
r = S.kevent(kq, nil, 0, out, 2, 0)
print(string.format("  = %s\n", tostring(r)))

S.close(kq)
print("[+] Done")
