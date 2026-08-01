--[[
    kevent_raw_dump.lua
    Read raw kevent bytes to verify struct layout on PS4
    Check if data field offset is correct
]]

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

print("[+] Raw kevent struct analysis\n")

-- Register and trigger ONE EVFILT_USER
local kq = tonn(S.kqueue())

local uev = mem.alloc(32)
-- ident=0x1234567890ABCDEF (distinct pattern)
mem.write_qword(uev + 0, 0x1234567890ABCDEF)
mem.write_word(uev + 8, 0xFFF9)       -- EVFILT_USER=-7
mem.write_word(uev + 10, 0x25)        -- EV_ADD|EV_ENABLE|EV_CLEAR
mem.write_dword(uev + 12, 0x80000000) -- NOTE_TRIGGER
mem.write_qword(uev + 16, 0xDEADBEEFCAFEBABE)  -- data (should be overwritten)
mem.write_qword(uev + 24, 0x1111222233334444)  -- udata

kevent(kq, uev, 1, nil, 0, 0)

-- Read event
local out = mem.alloc(32)
-- Fill with known pattern to see what kernel writes
for j = 0, 31 do
    mem.write_byte(out + j, 0xCC)
end

local ne = kevent(kq, nil, 0, out, 1, 0)
print(string.format("[+] Events: %s", tostring(ne)))

if ne and ne > 0 then
    print("\n[+] Raw 32 bytes of kevent struct:")
    local hex = ""
    for j = 0, 31 do
        local b = tonn(mem.read_byte(out + j))
        hex = hex .. string.format("%02x ", b)
        if (j + 1) % 8 == 0 then
            print(string.format("  +0x%02x: %s", j - 7, hex))
            hex = ""
        end
    end
    
    print("\n[+] Parsed fields:")
    local ident = tonn(mem.read_qword(out + 0))
    local filter = tonn(mem.read_word(out + 8))
    local flags = tonn(mem.read_word(out + 10))
    local fflags = tonn(mem.read_dword(out + 12))
    local data = tonn(mem.read_qword(out + 16))
    local udata = tonn(mem.read_qword(out + 24))
    
    print(string.format("  ident (+0x00) = 0x%x (expected: 0x1234567890ABCDEF)", ident))
    print(string.format("  filter (+0x08) = %d (expected: -7 = 65529 unsigned)", filter))
    print(string.format("  flags  (+0x0a) = 0x%x", flags))
    print(string.format("  fflags (+0x0c) = 0x%x", fflags))
    print(string.format("  data   (+0x10) = %d (0x%x)", data, data))
    print(string.format("  udata  (+0x18) = 0x%x (expected: 0x1111222233334444)", udata))
end

-- Now test with 3 EVFILT_USER to see data pattern
print("\n[+] Testing 3 EVFILT_USER events\n")
local kq2 = tonn(S.kqueue())

for i = 1, 3 do
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, 0xABC + i)
    mem.write_word(ev + 8, 0xFFF9)
    mem.write_word(ev + 10, 0x25)
    mem.write_dword(ev + 12, 0x80000000)
    mem.write_qword(ev + 16, 0xA0A0A0A0A0A0A0A0)
    mem.write_qword(ev + 24, 0xB0B0B0B0B0B0B0B0)
    kevent(kq2, ev, 1, nil, 0, 0)
end

local out2 = mem.alloc(96)
local ne2 = kevent(kq2, nil, 0, out2, 3, 0)
if ne2 and ne2 > 0 then
    print(string.format("[+] %d events:", ne2))
    for i = 0, ne2 - 1 do
        local off = i * 32
        print(string.format("\n  Event %d (offset +0x%02x):", i, off))
        local ident = tonn(mem.read_qword(out2 + off))
        local filter = tonn(mem.read_word(out2 + off + 8))
        local data = tonn(mem.read_qword(out2 + off + 16))
        local udata = tonn(mem.read_qword(out2 + off + 24))
        print(string.format("    ident=0x%x filter=%d data=%d udata=0x%x", ident, filter, data, udata))
    end
end

-- Test: What happens with NO EV_CLEAR and multiple triggers?
print("\n[+] Without EV_CLEAR, trigger 5 times, read once\n")
local kq3 = tonn(S.kqueue())

-- Add EVFILT_USER WITHOUT EV_CLEAR
local ev3 = mem.alloc(32)
mem.write_qword(ev3 + 0, 0x500)
mem.write_word(ev3 + 8, 0xFFF9)
mem.write_word(ev3 + 10, 0x5)     -- EV_ADD|EV_ENABLE (NO EV_CLEAR)
mem.write_dword(ev3 + 12, 0x80000000)  -- NOTE_TRIGGER (first trigger on add)
mem.write_qword(ev3 + 16, 0)
mem.write_qword(ev3 + 24, 0)
kevent(kq3, ev3, 1, nil, 0, 0)

-- Trigger 4 more times
for i = 1, 4 do
    local tev = mem.alloc(32)
    mem.write_qword(tev + 0, 0x500)
    mem.write_word(tev + 8, 0xFFF9)
    mem.write_word(tev + 10, 0x5)
    mem.write_dword(tev + 12, 0x80000000)
    mem.write_qword(tev + 16, 0)
    mem.write_qword(tev + 24, 0)
    kevent(kq3, tev, 1, nil, 0, 0)
end

-- Read (should have accumulated 5 triggers without EV_CLEAR)
local out3 = mem.alloc(32)
local ne3 = kevent(kq3, nil, 0, out3, 1, 0)
if ne3 and ne3 > 0 then
    local data = tonn(mem.read_qword(out3 + 16))
    print(string.format("  Without EV_CLEAR, 5 triggers: data=%d (expected: 5)", data))
end

-- Read again (should still have data=5 because no EV_CLEAR)
local out3b = mem.alloc(32)
local ne3b = kevent(kq3, nil, 0, out3b, 1, 0)
if ne3b and ne3b > 0 then
    local data = tonn(mem.read_qword(out3b + 16))
    print(string.format("  Second read (still no EV_CLEAR): data=%d", data))
end

kevent(kq3, nil, 0, nil, 0, 0)

-- Test: What data value with 2 knotes, both triggered once?
print("\n[+] Multiple knotes triggered: raw struct dump\n")
local kq4 = tonn(S.kqueue())

for i = 1, 5 do
    local ev4 = mem.alloc(32)
    mem.write_qword(ev4 + 0, 0x600 + i)
    mem.write_word(ev4 + 8, 0xFFF9)
    mem.write_word(ev4 + 10, 0x25)
    mem.write_dword(ev4 + 12, 0x80000000)
    mem.write_qword(ev4 + 16, 0xAAAAAAAAAAAAAAAA)
    mem.write_qword(ev4 + 24, 0xBBBBBBBBBBBBBBBB)
    kevent(kq4, ev4, 1, nil, 0, 0)
end

local out4 = mem.alloc(160)
local ne4 = kevent(kq4, nil, 0, out4, 5, 0)
if ne4 and ne4 > 0 then
    print(string.format("[+] %d events - full dump:", ne4))
    for i = 0, ne4 - 1 do
        local off = i * 32
        local hex = ""
        for j = 0, 31 do
            hex = hex .. string.format("%02x", tonn(mem.read_byte(out4 + off + j)))
        end
        local ident = tonn(mem.read_qword(out4 + off))
        local data = tonn(mem.read_qword(out4 + off + 16))
        print(string.format("  [%d] +0x00:%s data=%-3d ident=0x%x", i, hex:sub(1, 16), data, ident))
    end
end

kevent(kq4, nil, 0, nil, 0, 0)
kevent(kq, nil, 0, nil, 0, 0)
kevent(kq2, nil, 0, nil, 0, 0)

print("\n[+] Struct analysis complete")
