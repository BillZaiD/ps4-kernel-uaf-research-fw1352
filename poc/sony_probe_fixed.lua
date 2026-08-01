--[[
    sony_probe_fixed.lua
    Sony syscall probe 452-599 with correct fcall API
    يستخدم ps4_utils.lua للـ fcall الصحيح
]]

local utils = require("lib.ps4_utils")
local M = rawget(_G, "memory")
local N = rawget(_G, "native")
local S = rawget(_G, "syscall")

utils.resolve()

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function has_wrapper(sc)
    return S.syscall_wrapper[sc] ~= nil
end

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

local function is_hptr(v)
    return v >= 0xFFFF000000000000 and v < 0xFFFF800000000000
end

local outbuf = M.alloc(4096)
M.write_qword(outbuf, 0)

-- Fill with known pattern
for j = 0, 4095 do
    M.write_byte(outbuf + j, 0xCC)
end

print("[+] Sony syscall 452-599 probe")
print("[+] Using fcall from ps4_utils\n")

local interesting = {}
local total_available = 0
local total_missing = 0

-- Test each syscall with zero args first
for sc = 452, 599 do
    if has_wrapper(sc) then
        total_available = total_available + 1
        
        -- Get wrapper bytes
        local w = tonn(S.syscall_wrapper[sc])
        local b0 = M.read_byte(w)
        
        -- Skip if not a valid wrapper (first byte should be 0x48 = mov)
        if b0 == 72 then
            local ret = utils.fcall(sc, 0, 0, 0, 0, 0, 0)
            
            if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= 0 then
                local analysis = ""
                if is_kptr(ret) then
                    analysis = " KERNEL POINTER!"
                elseif is_hptr(ret) then
                    analysis = " heap pointer"
                elseif ret > 0 and ret < 1000 then
                    analysis = " small positive (handle?)"
                elseif ret > 1000 then
                    analysis = " large: " .. ret
                else
                    analysis = " unknown: " .. ret
                end
                
                print(string.format("sc%d: ret=0x%x %s", sc, ret, analysis))
                
                table.insert(interesting, {sc = sc, ret = ret, analysis = analysis})
                
                -- Try with outbuf for info leak
                local ret2 = utils.fcall(sc, outbuf, 4096, 0, 0, 0, 0)
                if ret2 ~= -1 and ret2 ~= 0xFFFFFFFFFFFFFFFF then
                    print(string.format("  -> with outbuf: ret=0x%x", ret2))
                    -- Check outbuf for kernel ptrs
                    local kptrs = 0
                    for j = 0, 255, 8 do
                        local v = tonn(M.read_qword(outbuf + j))
                        if is_kptr(v) then
                            kptrs = kptrs + 1
                            if kptrs <= 5 then
                                print(string.format("     [!] KPTR at +0x%x: 0x%x", j, v))
                            end
                        end
                    end
                    if kptrs > 0 then
                        print(string.format("     [!] %d kernel pointers found!", kptrs))
                    end
                end
            end
        end
    else
        total_missing = total_missing + 1
    end
end

print(string.format("\n[+] Available: %d, Missing: %d", total_available, total_missing))

if #interesting == 0 then
    print("\n[-] No interesting syscalls found with zero args")
    print("[*] Now testing 452-599 with outbuf arg pattern...")
    
    -- Try each with outbuf in arg1
    for sc = 452, 599 do
        if has_wrapper(sc) then
            local w = tonn(S.syscall_wrapper[sc])
            local b0 = M.read_byte(w)
            if b0 == 72 then
                -- Clear outbuf
                for j = 0, 255 do
                    M.write_byte(outbuf + j, 0)
                end
                
                local ret = utils.fcall(sc, outbuf, 256, 0, 0, 0, 0)
                if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
                    print(string.format("sc%d (with buf): ret=0x%x", sc, ret))
                    -- Check buffer
                    local nonzero = 0
                    for j = 0, 63 do
                        if M.read_byte(outbuf + j) ~= 0 then
                            nonzero = nonzero + 1
                        end
                    end
                    if nonzero > 0 then
                        print(string.format("  -> buffer has %d non-zero bytes!", nonzero))
                    end
                end
            end
        end
    end
end

-- Also test fork (sc2) and ptrace (sc59)
print("\n[*] Testing fork (sc2)...")
if has_wrapper(2) then
    local ret = utils.fcall(2, 0, 0, 0, 0, 0, 0)
    print(string.format("fork() = %d (0=child, +=parent pid, -=error)", tonn(ret)))
end

print("\n[*] Testing ptrace (sc59)...")
if has_wrapper(59) then
    -- PT_TRACE_ME
    local ret1 = utils.fcall(59, 0, 0, 0, 0, 0, 0)
    print(string.format("ptrace(PT_TRACE_ME) = %d", tonn(ret1)))
    
    -- PT_ATTACH with invalid pid
    local ret2 = utils.fcall(59, 1, -1, 0, 0, 0, 0)
    print(string.format("ptrace(PT_ATTACH, -1) = %d", tonn(ret2)))
    
    -- PT_IO with invalid pid and kernel addr
    local ret3 = utils.fcall(59, 5, 999999, 0xFFFFFFFF80000000, outbuf, 8, 0)
    print(string.format("ptrace(PT_IO, 999999, kernel) = %d", tonn(ret3)))
end

print("\n[*] Testing chroot (sc12)...")
if has_wrapper(12) then
    local ret = utils.fcall(12, 0, 0, 0, 0, 0, 0)  -- chroot("") or chroot(NULL)
    print(string.format("chroot(0) = %d", tonn(ret)))
    
    local ret2 = utils.fcall(12, outbuf, 0, 0, 0, 0, 0)  -- chroot with empty string
    print(string.format("chroot(empty) = %d", tonn(ret2)))
end

print("\n[+] Probe complete")
