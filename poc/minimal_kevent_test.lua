--[[
    minimal_kevent_test.lua
    Minimal EVFILT_USER test to verify kevent API
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

S.resolve({kqueue = 362, kevent = 363, close = 6})

local function kevent(...)
    local r = S.kevent(...)
    if type(r) == "table" and r.h then
        return r.h * 4294967296 + r.l
    end
    return tonumber(tostring(r or 0)) or 0
end

print("[*] Starting minimal kevent test\n")

-- Create kqueue
local kq = kevent(tonn(S.kqueue()))
print(string.format("[+] kq = %d", kq))

-- Build kevent struct manually (matching kevent_raw_dump)
local uev = mem.alloc(32)
mem.write_qword(uev + 0, 0x1234)      -- ident
mem.write_qword(uev + 8, 0xFFF50041)  -- filter=-11 EVFILT_USER + EV_ADD|EV_CLEAR as qword
mem.write_dword(uev + 12, 0)          -- fflags
mem.write_qword(uev + 16, 0)          -- data
mem.write_qword(uev + 24, 0x41414141) -- udata

-- Actually write filter and flags as separate 2-byte values
-- At +8: filter (int16) = -11 = 0xFFF5
-- At +10: flags (uint16) = EV_ADD|EV_CLEAR = 0x0041
-- This overwrites bytes 8-11
-- But the qword write at +8 already set all 8 bytes. Need to individually correct bytes 8-11.

-- Override bytes at +8,+9 (filter=-11 int16 LE = 0xF5, 0xFF)
mem.write_byte(uev + 8, 0xF5)
mem.write_byte(uev + 9, 0xFF)
-- Override bytes at +10,+11 (flags=0x0041 uint16 LE = 0x41, 0x00)
mem.write_byte(uev + 10, 0x41)
mem.write_byte(uev + 11, 0x00)

print("[*] Registering EVFILT_USER with NOTE_TRIGGER...")

-- Add with NOTE_TRIGGER (fflags=0x01000000)
mem.write_dword(uev + 12, 0x01000000)

local r = kevent(kq, uev, 1, nil, 0, 0)
print(string.format("  kevent(add+trigger) = %d", r))

-- Read
local out = mem.alloc(32)
for j = 0, 31 do mem.write_byte(out + j, 0xCC) end

local nr = kevent(kq, nil, 0, out, 1, 0)
print(string.format("  kevent(read) = %d", nr))

if nr > 0 then
    local ident = kevent(mem.read_qword(out + 0))
    local filter_lo = kevent(mem.read_byte(out + 8))
    local filter_hi = kevent(mem.read_byte(out + 9))
    local flags_lo = kevent(mem.read_byte(out + 10))
    local flags_hi = kevent(mem.read_byte(out + 11))
    local fflags = kevent(mem.read_dword(out + 12))
    local data = kevent(mem.read_qword(out + 16))
    local udata = kevent(mem.read_qword(out + 24))
    
    print(string.format("  ident=0x%x filter_bytes=%02x%02x flags_bytes=%02x%02x fflags=0x%x data=%d udata=0x%x",
        ident, filter_hi, filter_lo, flags_hi, flags_lo, fflags, data, udata))
end

S.close(kq)
print("\n[+] Minimal test done")
