--[[
    test_mmap_rwx.lua
    Test if mmap with PROT_EXEC works on FW 13.52
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({close=6, getpid=20})

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
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then
            return i
        end
    end
    return 7
end

local function scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    local tr = (w ~= 0 and w + find_tramp(w)) or (toaddr(S.syscall_wrapper[20]) + 7)
    return tonn(nat.fcall_with_rax(tr, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] mmap RWX test - FW 13.52\n")

-- mmap(addr=0, len=0x4000, prot=7(RWX), flags=0x1002(MAP_ANON|MAP_PRIVATE), fd=-1, offset=0)
-- sc477 is mmap on PS4
print("[*] Calling mmap(0, 0x4000, 7, 0x1002, -1, 0)...\n")
local rwx = scall(477, 0, 0x4000, 7, 0x1002, -1, 0)
print(string.format("  mmap returned: 0x%x", rwx))

-- Check if valid
if rwx > 0x100000 and rwx < 0xFFFF800000000000 then
    print(string.format("[+] SUCCESS! RWX memory at 0x%x", rwx))
    
    -- Write simple shellcode: just RET (0xC3)
    mem.write_byte(rwx, 0xC3)
    print("[*] Wrote RET (0xC3) at start")
    
    -- Call it via fcall
    print("[*] Calling RWX memory via fcall...")
    local result = tonn(nat.fcall_with_rax(rwx, 0x42, 0, 0, 0, 0, 0, 0))
    print(string.format("  fcall returned: 0x%x (expect 0x42 = rax passthrough)", result))
    
    -- Now write shellcode: mov rax, 0xDEAD; ret (48 c7 c0 ad de ad de c3)
    mem.write_qword(rwx, 0)
    mem.write_byte(rwx, 0x48); mem.write_byte(rwx+1, 0xC7); mem.write_byte(rwx+2, 0xC0)
    mem.write_byte(rwx+3, 0xAD); mem.write_byte(rwx+4, 0xDE); mem.write_byte(rwx+5, 0xAD); mem.write_byte(rwx+6, 0xDE)
    mem.write_byte(rwx+7, 0xC3)  -- ret
    
    local result2 = tonn(nat.fcall_with_rax(rwx, 0, 0, 0, 0, 0, 0, 0))
    print(string.format("  Shellcode returned: 0x%x (expect 0xDEADDEAD)", result2))
    
    if result2 == 0xDEADDEAD then
        print("[+] SHELLCODE EXECUTION CONFIRMED!")
    end
else
    print(string.format("[-] mmap returned invalid address: 0x%x", rwx))
    print("[-] RWX allocation may be blocked by W^X policy")
end

-- Also try with PROT_READ|PROT_WRITE only (no exec)
print("\n[*] Testing mmap with PROT_READ|PROT_WRITE only...")
local rw = scall(477, 0, 0x4000, 3, 0x1002, -1, 0)
print(string.format("  mmap(RW) returned: 0x%x", rw))

print("\n[+] mmap test complete")
