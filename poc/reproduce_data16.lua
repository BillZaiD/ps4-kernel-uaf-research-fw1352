--[[
    reproduce_data16.lua
    Try to reproduce the data=16 (KN_DETACHED) anomaly seen earlier
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

local EVFILT_USER = -11
local EV_ADD = 0x0001
local EV_CLEAR = 0x0040
local NOTE_TRIGGER = 0x01000000

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

local function read_int16(addr)
    local lo = tonn(mem.read_byte(addr))
    local hi = tonn(mem.read_byte(addr + 1))
    local v = lo + hi * 256
    if v >= 32768 then v = v - 65536 end
    return v
end

local function read_uint16(addr)
    local lo = tonn(mem.read_byte(addr))
    local hi = tonn(mem.read_byte(addr + 1))
    return lo + hi * 256
end

local function read_ev(ev)
    return {
        ident = tonn(mem.read_qword(ev + 0)),
        filter = read_int16(ev + 8),
        flags = read_uint16(ev + 10),
        fflags = tonn(mem.read_dword(ev + 12)),
        data = tonn(mem.read_qword(ev + 16)),
        udata = tonn(mem.read_qword(ev + 24)),
    }
end

print("[+] Reproducing data=16 anomaly\n")

-- Scenario that produced data=16 before:
-- Register 10 EVFILT_USER with different idents on same kq, 
-- THEN read (without triggering)

print("[*] Scenario: 10 events registered, read before any trigger\n")

local kq = tonn(S.kqueue())
print(string.format("  kq=%d\n", kq))

-- Register 10 events
for ident = 0xb01, 0xb0a do
    local ev = mk_ev(ident, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
    kevent(kq, ev, 1, nil, 0, 0)
end

-- Read all available events
local out = mem.alloc(32 * 20)
local nr = kevent(kq, nil, 0, out, 20, 0)
print(string.format("  Read after 10x ADD: %d events\n", nr))

for i = 0, nr - 1 do
    local e = read_ev(out + i * 32)
    print(string.format("    [%d] ident=0x%x flags=0x%x fflags=0x%x data=%d udata=0x%x",
        i, e.ident, e.flags, e.fflags, e.data, e.udata))
end

-- Now trigger all 10
print("\n[*] Triggering all 10 with NOTE_TRIGGER\n")
for ident = 0xb01, 0xb0a do
    local ev = mk_ev(ident, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
    kevent(kq, ev, 1, nil, 0, 0)
end

nr = kevent(kq, nil, 0, out, 20, 0)
print(string.format("  Read after trigger: %d events\n", nr))
for i = 0, nr - 1 do
    local e = read_ev(out + i * 32)
    print(string.format("    [%d] ident=0x%x data=%d", i, e.ident, e.data))
end

-- Scenario: Separate register and trigger for each
print("\n[*] Scenario: register + trigger + read for each of 10\n")

local kq2 = tonn(S.kqueue())

for ident = 0xc01, 0xc0a do
    -- Register
    local ev = mk_ev(ident, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
    kevent(kq2, ev, 1, nil, 0, 0)
    
    -- Trigger
    ev = mk_ev(ident, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
    kevent(kq2, ev, 1, nil, 0, 0)
    
    -- Read (only this ident)
    local o2 = mem.alloc(32)
    local nr2 = kevent(kq2, nil, 0, o2, 1, 0)
    if nr2 > 0 then
        local e = read_ev(o2)
        print(string.format("    ident=0x%x -> data=%d", e.ident, e.data))
    else
        print(string.format("    ident=0x%x -> no event", ident))
    end
end

S.close(kq2)

-- Scenario: Original 10-register-then-10-trigger-then-read (like old test 3)
print("\n[*] Scenario: register 10, trigger 10, read all (original data=16 test)\n")

local kq3 = tonn(S.kqueue())

for ident = 0xd01, 0xd0a do
    local ev = mk_ev(ident, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
    kevent(kq3, ev, 1, nil, 0, 0)
end

print("  (10 registered)\n")

-- Read before trigger (like old test did)
local o3 = mem.alloc(32 * 20)
local nr3 = kevent(kq3, nil, 0, o3, 20, 0)
print(string.format("  Pre-trigger read: %d events\n", nr3))
for i = 0, nr3 - 1 do
    local e = read_ev(o3 + i * 32)
    print(string.format("    [%d] ident=0x%x data=%d", i, e.ident, e.data))
end

-- Now trigger all
for ident = 0xd01, 0xd0a do
    local ev = mk_ev(ident, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
    kevent(kq3, ev, 1, nil, 0, 0)
end

print("\n  (10 triggered)\n")

nr3 = kevent(kq3, nil, 0, o3, 20, 0)
print(string.format("  Post-trigger read: %d events\n", nr3))
for i = 0, nr3 - 1 do
    local e = read_ev(o3 + i * 32)
    print(string.format("    [%d] ident=0x%x data=%d flags=0x%x fflags=0x%x",
        i, e.ident, e.data, e.flags, e.fflags))
end

S.close(kq3)

print("\n[+] Done")
