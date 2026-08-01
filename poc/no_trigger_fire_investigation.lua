--[[
    no_trigger_fire_investigation.lua
    Investigate PS4-specific EVFILT_USER auto-firing on registration
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

S.resolve({
    kqueue = 362, kevent = 363, close = 6
})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

-- Write int16 LE at offset (uses 2 bytes)
local function write_int16(ev, off, v)
    if v < 0 then v = 65536 + v end
    mem.write_byte(ev + off, v % 256)
    mem.write_byte(ev + off + 1, math.floor(v / 256) % 256)
end

-- Read int16 LE at offset
local function read_int16(ev, off)
    local lo = tonn(mem.read_byte(ev + off))
    local hi = tonn(mem.read_byte(ev + off + 1))
    local v = lo + hi * 256
    if v >= 32768 then v = v - 65536 end
    return v
end

-- Build kevent struct (FreeBSD layout, 32 bytes per event)
local function build_ev(ident, filter, flags, fflags, data, udata)
    local ev = mem.alloc(32)
    for i = 0, 31 do mem.write_byte(ev + i, 0) end
    mem.write_qword(ev + 0, ident)   -- ident
    write_int16(ev, 8, filter)       -- filter (int16)
    write_int16(ev, 10, flags)       -- flags (uint16)
    mem.write_dword(ev + 12, fflags) -- fflags (uint32)
    mem.write_qword(ev + 16, data)   -- data (int64)
    mem.write_qword(ev + 24, udata)  -- udata (uint64)
    return ev
end

local function read_ev(ev)
    return {
        ident  = tonn(mem.read_qword(ev + 0)),
        filter = read_int16(ev, 8),
        flags  = read_int16(ev, 10),
        fflags = tonn(mem.read_dword(ev + 12)),
        data   = tonn(mem.read_qword(ev + 16)),
        udata  = tonn(mem.read_qword(ev + 24)),
    }
end

local function ev_dump(ev)
    local e = read_ev(ev)
    return string.format("ident=0x%x filter=%d flags=0x%x fflags=0x%x data=%d udata=0x%x",
        e.ident, e.filter, e.flags, e.fflags, e.data, e.udata)
end

-- NOTE: EVFILT_USER = -11, EV_ADD=0x0001, EV_CLEAR=0x0040, NOTE_TRIGGER=0x01000000
local EVFILT_USER = -11
local EV_ADD = 0x0001
local EV_CLEAR = 0x0040
local NOTE_TRIGGER = 0x01000000

print("[-] EVFILT_USER Auto-Fire Investigation\n")

-- Test 1: Does it fire on EV_ADD alone? Check with different ident values
print("[*] Test 1: Does auto-fire depend on ident?\n")

for _, ident in ipairs({0, 1, 0x10, 0x100, 0x1000, 0xdead, 0xbadd, 0x12345678}) do
    local kq = tonn(S.kqueue())
    local ev = build_ev(ident, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0x4141)
    local r = tonn(S.kevent(kq, ev, 1, nil, 0, 0))
    
    -- Try to read immediately
    local evout = mem.alloc(32)
    local nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
    
    if nr > 0 then
        local e = read_ev(evout)
        print(string.format("  ident=0x%x: auto-fired! data=%d flags=0x%x fflags=0x%x",
            ident, e.data, e.flags, e.fflags))
    else
        print(string.format("  ident=0x%x: no auto-fire (nr=%d)", ident, nr))
    end
    
    S.close(kq)
end

-- Test 2: Does auto-fire require EV_CLEAR?
print("\n[*] Test 2: Effect of EV_CLEAR on auto-fire\n")
for _, use_clear in ipairs({true, false}) do
    local kq = tonn(S.kqueue())
    local flags = EV_ADD
    if use_clear then flags = flags + EV_CLEAR end
    
    local ev = build_ev(0x1, EVFILT_USER, flags, 0, 0, 0)
    local r = tonn(S.kevent(kq, ev, 1, nil, 0, 0))
    
    local evout = mem.alloc(32)
    local nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
    
    if nr > 0 then
        local e = read_ev(evout)
        print(string.format("  EV_CLEAR=%s: auto-fired! data=%d", tostring(use_clear), e.data))
    else
        print(string.format("  EV_CLEAR=%s: no auto-fire", tostring(use_clear)))
    end
    S.close(kq)
end

-- Test 3: Does auto-fire depend on existing events in kqueue?
print("\n[*] Test 3: Auto-fire with existing kqueue events\n")
local kq = tonn(S.kqueue())

-- Register a normal EVFILT_USER first
local ev = build_ev(0xa, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
S.kevent(kq, ev, 1, nil, 0, 0)

-- Now add another with auto-trigger
local ev2 = build_ev(0xb, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
S.kevent(kq, ev2, 1, nil, 0, 0)

-- Read all
local evout_arr = mem.alloc(64)  -- 2 events
local nr = tonn(S.kevent(kq, nil, 0, evout_arr, 2, 0))
print(string.format("  Add to existing kq: %d events returned", nr))
for i = 0, nr - 1 do
    print("    [" .. i .. "] " .. ev_dump(evout_arr + i * 32))
end

-- Trigger 0xa
local ev3 = build_ev(0xa, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
S.kevent(kq, ev3, 1, nil, 0, 0)

nr = tonn(S.kevent(kq, nil, 0, evout_arr, 2, 0))
print(string.format("  After trigger 0xa: %d events", nr))
for i = 0, nr - 1 do
    print("    [" .. i .. "] " .. ev_dump(evout_arr + i * 32))
end

-- Now add new EVFILT_USER with no ident conflict
local ev4 = build_ev(0xc, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
S.kevent(kq, ev4, 1, nil, 0, 0)

-- Trigger old one
S.kevent(kq, ev3, 1, nil, 0, 0)

nr = tonn(S.kevent(kq, nil, 0, evout_arr, 3, 0))
print(string.format("  Add 0xc while 0xa triggered: %d events", nr))
for i = 0, nr - 1 do
    print("    [" .. i .. "] " .. ev_dump(evout_arr + i * 32))
end

S.close(kq)

-- Test 4: Does auto-fire timing matter? (is it deferred?)
print("\n[*] Test 4: Delayed read after registration\n")
for _, delay_ms in ipairs({0, 100, 500}) do
    local kq = tonn(S.kqueue())
    local ev = build_ev(0xd, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
    S.kevent(kq, ev, 1, nil, 0, 0)
    
    -- "Delay" by reading other kq or doing nothing
    -- (can't actually sleep in Lua)
    local evout = mem.alloc(32)
    -- Just try to read, no delay possible
    local nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
    print(string.format("  No delay: nr=%d data=%d", nr, 
        nr > 0 and tonn(mem.read_qword(evout + 16)) or 0))
    S.close(kq)
end

-- Test 5: Vary number of knote structs sharing same ident
print("\n[*] Test 5: Multiple knotes in multiple kqueues, same kq\n")
local kq_a = tonn(S.kqueue())
local kq_b = tonn(S.kqueue())

-- Register ident=0x1a in kq_a and kq_b
local ev = build_ev(0x1a, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0xaaaa)
S.kevent(kq_a, ev, 1, nil, 0, 0)
S.kevent(kq_b, ev, 1, nil, 0, 0)

-- Read from each
local evout = mem.alloc(32)
local nr = tonn(S.kevent(kq_a, nil, 0, evout, 1, 0))
print(string.format("  kq_a, ident=0x1a: nr=%d %s", nr, nr > 0 and ev_dump(evout) or ""))
nr = tonn(S.kevent(kq_b, nil, 0, evout, 1, 0))
print(string.format("  kq_b, ident=0x1a: nr=%d %s", nr, nr > 0 and ev_dump(evout) or ""))

-- Trigger ident=0x1a in both
local evt = build_ev(0x1a, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
S.kevent(kq_a, evt, 0, nil, 0, 0)  -- Can't trigger from another kq?
nr = tonn(S.kevent(kq_a, nil, 0, evout, 1, 0))
print(string.format("  kq_a after trigger: nr=%d %s", nr, nr > 0 and ev_dump(evout) or ""))
nr = tonn(S.kevent(kq_b, nil, 0, evout, 1, 0))
print(string.format("  kq_b after trigger: nr=%d %s", nr, nr > 0 and ev_dump(evout) or ""))

S.close(kq_a)
S.close(kq_b)

-- Test 6: Does auto-fire happen if we DON'T create a new knote but re-register same ident?
print("\n[*] Test 6: Re-register existing ident\n")
local kq = tonn(S.kqueue())

-- First registration
local ev = build_ev(0x2a, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0)
S.kevent(kq, ev, 1, nil, 0, 0)
local evout = mem.alloc(32)
local nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
print(string.format("  First reg: nr=%d data=%d", nr, nr > 0 and tonn(mem.read_qword(evout + 16)) or 0))

-- Re-register same ident
S.kevent(kq, ev, 1, nil, 0, 0)
nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
print(string.format("  Re-reg: nr=%d data=%d", nr, nr > 0 and tonn(mem.read_qword(evout + 16)) or 0))

S.close(kq)

-- Test 7: Investigate data values - compare with internal kn_sdata
print("\n[*] Test 7: Can data distinguish kqueue-freed vs kqueue-active?\n")

local function test_knote_lifetime()
    local kq = tonn(S.kqueue())
    local ev = build_ev(0x3a, EVFILT_USER, EV_ADD, 0, 0, 0)  -- NO EV_CLEAR
    S.kevent(kq, ev, 1, nil, 0, 0)
    
    -- Trigger
    local evt = build_ev(0x3a, EVFILT_USER, NOTE_TRIGGER, 0, 0, 0)
    S.kevent(kq, evt, 1, nil, 0, 0)
    
    -- Read (non-EV_CLEAR means data persists)
    local evout = mem.alloc(32)
    local nr = tonn(S.kevent(kq, nil, 0, evout, 1, 0))
    print(string.format("  After trigger (no EV_CLEAR): nr=%d data=%d", nr, 
        nr > 0 and tonn(mem.read_qword(evout + 16)) or 0))
    
    -- Read again with different return area to see if stale
    local evout2 = mem.alloc(32)
    nr = tonn(S.kevent(kq, nil, 0, evout2, 1, 0))
    print(string.format("  Second read: nr=%d", nr))
    
    -- Close kqueue and reopen
    S.close(kq)
    local kq2 = tonn(S.kqueue())
    local ev2 = build_ev(0x3a, EVFILT_USER, EV_ADD, 0, 0, 0)
    S.kevent(kq2, ev2, 1, nil, 0, 0)
    
    -- Trigger
    S.kevent(kq2, evt, 1, nil, 0, 0)
    
    -- Read
    local evout3 = mem.alloc(32)
    nr = tonn(S.kevent(kq2, nil, 0, evout3, 1, 0))
    print(string.format("  New kq, same ident: nr=%d data=%d", nr,
        nr > 0 and tonn(mem.read_qword(evout3 + 16)) or 0))
end
test_knote_lifetime()

print("\n[+] Done")
