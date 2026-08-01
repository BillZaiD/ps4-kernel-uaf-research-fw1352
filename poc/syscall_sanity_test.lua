--[[
    syscall_sanity_test.lua
    Test basic syscalls to ensure S.kevent still works
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

S.resolve({kqueue = 362, kevent = 363, close = 6, write = 4, getpid = 20})

print("[*] Sanity test\n")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

-- Test 1: getpid
local pid = tonn(S.getpid())
print(string.format("[+] getpid = %d", pid))

-- Test 2: kqueue
local kq = tonn(S.kqueue())
print(string.format("[+] kqueue = %d", kq))

-- Test 3: kevent register with NOTE_TRIGGER using mem.write_word
local ev = mem.alloc(32)
for i = 0, 31 do mem.write_byte(ev + i, 0) end

mem.write_qword(ev + 0, 0x42)     -- ident
mem.write_word(ev + 8, 0xFFF5)    -- filter = -11 (EVFILT_USER)
mem.write_word(ev + 10, 0x41)     -- flags = EV_ADD|EV_CLEAR
mem.write_dword(ev + 12, 0)       -- fflags
mem.write_qword(ev + 16, 0)       -- data
mem.write_qword(ev + 24, 0)       -- udata

print("[*] Performing kevent(ADD)...")
local r = S.kevent(kq, ev, 1, nil, 0, 0)
print(string.format("  kevent(ADD) returned: %s", tostring(r)))
r = tonn(r)
print(string.format("  kevent(ADD) = %d", r))

-- Now set NOTE_TRIGGER and re-register
mem.write_dword(ev + 12, 0x01000000)  -- NOTE_TRIGGER

print("[*] Performing kevent(ADD+TRIGGER)...")
r = S.kevent(kq, ev, 1, nil, 0, 0)
print(string.format("  kevent(ADD+TRIGGER) returned: %s", tostring(r)))
r = tonn(r)
print(string.format("  kevent(ADD+TRIGGER) = %d", r))

-- Read
local out = mem.alloc(32)
for i = 0, 31 do mem.write_byte(out + i, 0xCC) end

print("[*] Performing kevent(READ)...")
r = S.kevent(kq, nil, 0, out, 1, 0)
print(string.format("  kevent(READ) returned: %s", tostring(r)))
r = tonn(r)

if r > 0 then
    print(string.format("  Got %d events!", r))
    local ident = tonn(mem.read_qword(out + 0))
    local data = tonn(mem.read_qword(out + 16))
    print(string.format("  ident=0x%x data=%d", ident, data))
else
    print(string.format("  No events: %d", r))
end

-- Cleanup
S.close(kq)
print("\n[+] Done")
