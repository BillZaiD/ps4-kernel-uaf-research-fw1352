--[[
    evfilt_user_data_analysis.lua
    Investigate the EVFILT_USER data field anomaly
    Data values change between runs (142 vs 291) and decrease monotonically
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

print("[+] EVFILT_USER Data Field Analysis\n")

-- Test 1: Single EVFILT_USER with different trigger counts
print("[*] Test 1: Single EVFILT_USER, increasing triggers\n")

local kq1 = tonn(S.kqueue())

for trigger_count = 1, 5 do
    -- Register EVFILT_USER
    local uev = mem.alloc(32)
    mem.write_qword(uev + 0, 0x100)     -- ident
    mem.write_word(uev + 8, 0xFFF9)      -- EVFILT_USER
    mem.write_word(uev + 10, 0x25)       -- EV_ADD|EV_ENABLE|EV_CLEAR
    mem.write_dword(uev + 12, 0x80000000)-- NOTE_TRIGGER
    mem.write_qword(uev + 16, 0)
    mem.write_qword(uev + 24, 0)
    kevent(kq1, uev, 1, nil, 0, 0)
    
    -- Trigger N times
    for t = 1, trigger_count do
        local tev = mem.alloc(32)
        mem.write_qword(tev + 0, 0x100)
        mem.write_word(tev + 8, 0xFFF9)
        mem.write_word(tev + 10, 0x25)
        mem.write_dword(tev + 12, 0x80000000)
        mem.write_qword(tev + 16, 0)
        mem.write_qword(tev + 24, 0)
        kevent(kq1, tev, 1, nil, 0, 0)
    end
    
    -- Read event
    local out = mem.alloc(32)
    local ne = kevent(kq1, nil, 0, out, 1, 0)
    if ne and ne > 0 then
        local data = tonn(mem.read_qword(out + 16))
        local ident = tonn(mem.read_qword(out + 0))
        local fflags = tonn(mem.read_dword(out + 12))
        print(string.format("  %d triggers -> ident=0x%x data=%d fflags=0x%x", trigger_count, ident, data, fflags))
    end
end
kevent(kq1, nil, 0, nil, 0, 0)

-- Test 2: data value vs event ORDER
print("\n[*] Test 2: Data value vs event order\n")

local kq2 = tonn(S.kqueue())

-- Register 200 EVFILT_USER with CLEAR flag
for i = 1, 200 do
    local uev = mem.alloc(32)
    mem.write_qword(uev + 0, i)
    mem.write_word(uev + 8, 0xFFF9)
    mem.write_word(uev + 10, 0x25)
    mem.write_dword(uev + 12, 0x80000000)
    mem.write_qword(uev + 16, 0)
    mem.write_qword(uev + 24, 0)
    kevent(kq2, uev, 1, nil, 0, 0)
end

local out2 = mem.alloc(6400)
local ne2 = kevent(kq2, nil, 0, out2, 200, 0)
if ne2 and ne2 > 0 then
    print(string.format("[+] %d events returned", ne2))
    local data_start = tonn(mem.read_qword(out2 + 16))
    local data_end = tonn(mem.read_qword(out2 + (ne2-1)*32 + 16))
    print(string.format("[+] First data=%d Last data=%d", data_start, data_end))
    print(string.format("[+] Difference: %d", data_start - data_end))
    
    -- Is data = total_triggers - event_index?
    local expected_diff = ne2 - 1  -- If each event decrements by 1
    print(string.format("[+] If data = counter - index: expected diff=%d, actual=%d", expected_diff, data_start - data_end))
end

-- Also check: does EV_CLEAR affect data?
print("\n[*] Test 3: EV_CLEAR vs no EV_CLEAR\n")

local kq3 = tonn(S.kqueue())

-- With EV_CLEAR
local uev3a = mem.alloc(32)
mem.write_qword(uev3a + 0, 0x200)
mem.write_word(uev3a + 8, 0xFFF9)
mem.write_word(uev3a + 10, 0x25)    -- EV_ADD|EV_ENABLE|EV_CLEAR
mem.write_dword(uev3a + 12, 0x80000000)
mem.write_qword(uev3a + 16, 0)
mem.write_qword(uev3a + 24, 0)
kevent(kq3, uev3a, 1, nil, 0, 0)
local out3a = mem.alloc(32)
local ne3a = kevent(kq3, nil, 0, out3a, 1, 0)
if ne3a and ne3a > 0 then
    local d = tonn(mem.read_qword(out3a + 16))
    print(string.format("  With EV_CLEAR: data=%d", d))
end

-- Without EV_CLEAR
local uev3b = mem.alloc(32)
mem.write_qword(uev3b + 0, 0x201)
mem.write_word(uev3b + 8, 0xFFF9)
mem.write_word(uev3b + 10, 0x5)     -- EV_ADD|EV_ENABLE only
mem.write_dword(uev3b + 12, 0x80000000)
mem.write_qword(uev3b + 16, 0)
mem.write_qword(uev3b + 24, 0)
kevent(kq3, uev3b, 1, nil, 0, 0)
local out3b = mem.alloc(32)
local ne3b = kevent(kq3, nil, 0, out3b, 1, 0)
if ne3b and ne3b > 0 then
    local d = tonn(mem.read_qword(out3b + 16))
    print(string.format("  Without EV_CLEAR: data=%d", d))
end
kevent(kq3, nil, 0, nil, 0, 0)

-- Test 4: Does data value correlate to kqueue fd number?
print("\n[*] Test 4: Data value vs kqueue count\n")

for kq_num = 1, 3 do
    local kq4 = tonn(S.kqueue())
    -- Register and trigger one EVFILT_USER
    local uev4 = mem.alloc(32)
    mem.write_qword(uev4 + 0, 0x300)
    mem.write_word(uev4 + 8, 0xFFF9)
    mem.write_word(uev4 + 10, 0x25)
    mem.write_dword(uev4 + 12, 0x80000000)
    mem.write_qword(uev4 + 16, 0)
    mem.write_qword(uev4 + 24, 0)
    kevent(kq4, uev4, 1, nil, 0, 0)
    
    local out4 = mem.alloc(32)
    local ne4 = kevent(kq4, nil, 0, out4, 1, 0)
    if ne4 and ne4 > 0 then
        local d = tonn(mem.read_qword(out4 + 16))
        print(string.format("  kqueue #%d (fd=%d): data=%d", kq_num, kq4, d))
    end
    kevent(kq4, nil, 0, nil, 0, 0)
end

-- Test 5: Check if data is actually knote offset in kqueue or similar
print("\n[*] Test 5: Data value with 1 event vs rest\n")

local kq5 = tonn(S.kqueue())
-- Register only 1 EVFILT_USER
local uev5 = mem.alloc(32)
mem.write_qword(uev5 + 0, 0x400)
mem.write_word(uev5 + 8, 0xFFF9)
mem.write_word(uev5 + 10, 0x25)
mem.write_dword(uev5 + 12, 0x80000000)
mem.write_qword(uev5 + 16, 0)
mem.write_qword(uev5 + 24, 0)
kevent(kq5, uev5, 1, nil, 0, 0)

-- Read without triggering first to see if data is 0
local out5a = mem.alloc(32)
local ne5a = kevent(kq5, nil, 0, out5a, 1, 0)
print(string.format("  Before trigger: ne=%s", tostring(ne5a)))

-- Now trigger
local tev5 = mem.alloc(32)
mem.write_qword(tev5 + 0, 0x400)
mem.write_word(tev5 + 8, 0xFFF9)
mem.write_word(tev5 + 10, 0x25)
mem.write_dword(tev5 + 12, 0x80000000)
mem.write_qword(tev5 + 16, 0)
mem.write_qword(tev5 + 24, 0)
kevent(kq5, tev5, 1, nil, 0, 0)

local out5b = mem.alloc(32)
local ne5b = kevent(kq5, nil, 0, out5b, 1, 0)
if ne5b and ne5b > 0 then
    local d = tonn(mem.read_qword(out5b + 16))
    print(string.format("  Single event after trigger: data=%d", d))
end
kevent(kq5, nil, 0, nil, 0, 0)

-- Test 6: Multiple kqueues to see if data is global counter
print("\n[*] Test 6: Data cross-kqueue correlation\n")

local kqs = {}
for i = 1, 5 do
    kqs[i] = tonn(S.kqueue())
    local uev = mem.alloc(32)
    mem.write_qword(uev + 0, i)
    mem.write_word(uev + 8, 0xFFF9)
    mem.write_word(uev + 10, 0x25)
    mem.write_dword(uev + 12, 0x80000000)
    mem.write_qword(uev + 16, 0)
    mem.write_qword(uev + 24, 0)
    kevent(kqs[i], uev, 1, nil, 0, 0)
    
    -- Read each immediately
    local out = mem.alloc(32)
    local ne = kevent(kqs[i], nil, 0, out, 1, 0)
    if ne and ne > 0 then
        local d = tonn(mem.read_qword(out + 16))
        print(string.format("  kqueue[%d] (fd=%d): data=%d", i, kqs[i], d))
    end
end
for i = 1, 5 do
    kevent(kqs[i], nil, 0, nil, 0, 0)
end

print("\n[+] Analysis complete")
