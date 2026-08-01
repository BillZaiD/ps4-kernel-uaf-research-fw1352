--[[
    evfilt_user_investigation.lua
    تحليل متعمق لـ EVFILT_USER data field
    + التأكد من العلاقة بين الأحداث
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

local function mkuev(ident, flags, fflags)
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, ident)
    mem.write_word(ev + 8, 0xFFF9)  -- EVFILT_USER
    mem.write_word(ev + 10, flags)
    mem.write_dword(ev + 12, fflags)
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    return ev
end

local function parse_kev(buf, idx)
    local off = idx * 32
    return {
        ident = tonn(mem.read_qword(buf + off)),
        data = tonn(mem.read_qword(buf + off + 16)),
    }
end

print("[+] EVFILT_USER - Investigation\n")

-- Test 1: Are events lost due to single kevent call with multiple changelist entries?
print("[*] Test 1: Batch vs individual registration\n")

-- Method A: All 5 in one changelist
local kq_a = tonn(S.kqueue())
local clist = mem.alloc(32 * 5)
for i = 1, 5 do
    local off = (i - 1) * 32
    mem.write_qword(clist + off + 0, 0x100 + i)
    mem.write_word(clist + off + 8, 0xFFF9)
    mem.write_word(clist + off + 10, 0x25)
    mem.write_dword(clist + off + 12, 0x80000000)
end
local ret_a = kevent(kq_a, clist, 5, nil, 0, 0)
print(string.format("  Batch add: ret=%s", tostring(ret_a)))

local out_a = mem.alloc(32 * 10)
local n_a = kevent(kq_a, nil, 0, out_a, 10, 0)
print(string.format("  Batch read: %d events", n_a or 0))
if n_a and n_a > 0 then
    for i = 0, n_a - 1 do
        local kv = parse_kev(out_a, i)
        print(string.format("    [%d] ident=0x%x data=%d", i, kv.ident, kv.data))
    end
end
kevent(kq_a, nil, 0, nil, 0, 0)

-- Method B: Individual calls
local kq_b = tonn(S.kqueue())
for i = 1, 5 do
    local ev = mkuev(0x200 + i, 0x25, 0x80000000)
    local r = kevent(kq_b, ev, 1, nil, 0, 0)
end
print("\n  Individual add: done")
local out_b = mem.alloc(32 * 10)
local n_b = kevent(kq_b, nil, 0, out_b, 10, 0)
print(string.format("  Individual read: %d events", n_b or 0))
if n_b and n_b > 0 then
    for i = 0, n_b - 1 do
        local kv = parse_kev(out_b, i)
        print(string.format("    [%d] ident=0x%x data=%d", i, kv.ident, kv.data))
    end
end
kevent(kq_b, nil, 0, nil, 0, 0)

-- Test 2: Does data value depend on kqueue state?
print("\n[*] Test 2: Data value vs kqueue state\n")

local kq_c = tonn(S.kqueue())
-- Register+trigger 10 events
for i = 1, 10 do
    local ev = mkuev(0x300 + i, 0x25, 0x80000000)
    kevent(kq_c, ev, 1, nil, 0, 0)
end
local out_c = mem.alloc(32 * 10)
local n_c = kevent(kq_c, nil, 0, out_c, 10, 0)
if n_c and n_c > 0 then
    print(string.format("  10 events: first data=%d last data=%d", 
        parse_kev(out_c, 0).data, parse_kev(out_c, n_c - 1).data))
end

-- Trigger a DIFFERENT set and check data
for i = 1, 5 do
    local ev = mkuev(0x400 + i, 0x25, 0x80000000)
    kevent(kq_c, ev, 1, nil, 0, 0)
end
local out_c2 = mem.alloc(32 * 10)
local n_c2 = kevent(kq_c, nil, 0, out_c2, 10, 0)
if n_c2 and n_c2 > 0 then
    print(string.format("  Second batch: first data=%d last data=%d",
        parse_kev(out_c2, 0).data, parse_kev(out_c2, n_c2 - 1).data))
end
kevent(kq_c, nil, 0, nil, 0, 0)

-- Test 3: What if we DON'T register with NOTE_TRIGGER but trigger separately?
print("\n[*] Test 3: Separate register + trigger\n")

local kq_d = tonn(S.kqueue())

-- Register 10 EVFILT_USER WITHOUT NOTE_TRIGGER
for i = 1, 10 do
    local ev = mkuev(0x500 + i, 0x25, 0)  -- no NOTE_TRIGGER on register
    kevent(kq_d, ev, 1, nil, 0, 0)
end

-- Read without trigger (should be 0)
local out_d0 = mem.alloc(32 * 10)
local n_d0 = kevent(kq_d, nil, 0, out_d0, 10, 0)
print(string.format("  Before trigger: %s events", tostring(n_d0)))

-- Now trigger all 10
for i = 1, 10 do
    local ev = mkuev(0x500 + i, 0x25, 0x80000000)  -- NOTE_TRIGGER
    kevent(kq_d, ev, 1, nil, 0, 0)
end

-- Read
local out_d = mem.alloc(32 * 10)
local n_d = kevent(kq_d, nil, 0, out_d, 10, 0)
print(string.format("  After 10 triggers: %d events", n_d or 0))
if n_d and n_d > 0 then
    for i = 0, n_d - 1 do
        local kv = parse_kev(out_d, i)
        print(string.format("    [%d] ident=0x%x data=%d", i, kv.ident, kv.data))
    end
end
kevent(kq_d, nil, 0, nil, 0, 0)

-- Test 4: Does data correlate with event index or total count?
print("\n[*] Test 4: Data = total_triggered - index?\n")

local kq_e = tonn(S.kqueue())
local N = 50
for i = 1, N do
    local ev = mkuev(0x600 + i, 0x25, 0x80000000)
    kevent(kq_e, ev, 1, nil, 0, 0)
end
local out_e = mem.alloc(32 * (N + 10))
local n_e = kevent(kq_e, nil, 0, out_e, N + 10, 0)
if n_e and n_e > 0 then
    local d0 = parse_kev(out_e, 0).data
    local dN = parse_kev(out_e, n_e - 1).data
    print(string.format("  50 events: first data=%d last data=%d", d0, dN))
    print(string.format("  Range: %d", d0 - dN))
    print(string.format("  Expected if data = total_events - index + 1: %d vs actual %d", N, d0))
    print(string.format("  Missing events: %d", N - n_e))
    
    -- Check: data[i] - data[i+1] = 1 most of the time?
    local diffs = {}
    for i = 0, n_e - 2 do
        local d1 = parse_kev(out_e, i).data
        local d2 = parse_kev(out_e, i + 1).data
        diffs[i] = d1 - d2
    end
    local diff1_count = 0
    for i = 0, n_e - 2 do
        if diffs[i] == 1 then diff1_count = diff1_count + 1 end
    end
    print(string.format("  Adjacent data diffs of exactly 1: %d/%d", diff1_count, n_e - 1))
    if diff1_count < n_e - 1 then
        print("  Non-1 diffs:")
        for i = 0, n_e - 2 do
            if diffs[i] ~= 1 then
                local d1 = parse_kev(out_e, i).data
                local d2 = parse_kev(out_e, i + 1).data
                print(string.format("    [%d] %d -> %d (diff=%d)", i, d1, d2, diffs[i]))
            end
        end
    end
end
kevent(kq_e, nil, 0, nil, 0, 0)

-- Test 5: Cross-kqueue data independence
print("\n[*] Test 5: Cross-kqueue data independence\n")

for kq_idx = 1, 3 do
    local kq_f = tonn(S.kqueue())
    -- Register and trigger 5 events on each kqueue
    for i = 1, 5 do
        local ev = mkuev(0x700 + kq_idx * 100 + i, 0x25, 0x80000000)
        kevent(kq_f, ev, 1, nil, 0, 0)
    end
    local out_f = mem.alloc(32 * 10)
    local n_f = kevent(kq_f, nil, 0, out_f, 10, 0)
    if n_f and n_f > 0 then
        local d0 = parse_kev(out_f, 0).data
        local dn = parse_kev(out_f, n_f - 1).data
        print(string.format("  kqueue[%d]: %d events, data %d -> %d", kq_idx, n_f, d0, dn))
    end
    kevent(kq_f, nil, 0, nil, 0, 0)
end

print("\n[+] Investigation complete")
