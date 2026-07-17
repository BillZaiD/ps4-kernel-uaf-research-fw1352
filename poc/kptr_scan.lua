--[[
    Kernel Pointer Scanner
    Scans all available sysctl paths for kernel pointers
    
    Tests: kern.* (OIDs 1-50), kern.proc.* (via fcall),
           random device, libkernel memory
--]]

local utils = require("lib.ps4_utils")

utils.banner("Kernel Pointer Scanner")

local S = rawget(_G, "syscall")
local M = rawget(_G, "memory")

utils.resolve()

print("\n[*] Scanning kern.* sysctl for kernel pointers")

local oid = M.alloc(16)
local out = M.alloc(4096)
local outlen = M.alloc(8)
local total_found = 0

for sub = 1, 50 do
    M.write_dword(oid, 1)       -- CTL_KERN
    M.write_dword(oid + 4, sub) -- kern.X
    M.write_qword(outlen, 4096)
    for j = 0, 4095 do M.write_byte(out + j, 0) end
    
    local r = utils.fcall(202, oid, 8, out, outlen)
    if r == 0 then
        local len = M.tonum(M.read_qword(outlen))
        if len > 0 then
            local kps = utils.scan_kptrs(out, len)
            if #kps > 0 then
                total_found = total_found + #kps
                print(string.format("[!] kern.%d: %d bytes, %d kernel ptrs", sub, len, #kps))
                for _, kp in ipairs(kps) do
                    print(string.format("    +0x%x: 0x%x", kp.offset, kp.value))
                end
            end
        end
    end
end

print(string.format("\n[*] Total kernel pointers found: %d", total_found))
if total_found == 0 then
    print("[!] Sony has sanitized all kern.* sysctl output")
end

-- Scan /dev/random
print("\n[*] Scanning /dev/random for kernel pointers")
local path = M.alloc(64)
utils.write_str(path, "/dev/random")
local fd = utils.fcall(5, path, 0, 0)
if fd >= 0 then
    local buf = M.alloc(4096)
    local r = utils.fcall(3, fd, buf, 4096)
    if r > 0 and r <= 4096 then
        local kps = utils.scan_kptrs(buf, r)
        print(string.format("[*] /dev/random: %d bytes, %d kernel ptrs", r, #kps))
        for _, kp in ipairs(kps) do
            print(string.format("    +0x%x: 0x%x", kp.offset, kp.value))
        end
    end
    utils.fcall(6, fd)
end

-- Scan libkernel
print("\n[*] Scanning libkernel for kernel pointers")
local libbase = 0x80a67c000
local kptrs = 0
for j = 0, 0x100000 - 8, 8 do
    local qv = M.tonum(M.mem.read_qword(libbase + j))
    if utils.is_kernel_ptr(qv) then
        kptrs = kptrs + 1
        if kptrs <= 10 then
            print(string.format("    +0x%x: 0x%x", j, qv))
        end
    end
end
print(string.format("[*] libkernel: scanned 1MB, %d kernel ptrs", kptrs))

print("\n[*] Scan complete")
