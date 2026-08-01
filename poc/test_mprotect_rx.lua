--[[
    test_mprotect_rx.lua
    Try: allocate RW -> write shellcode -> mprotect to RX -> execute
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

local function scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    local tr = (w ~= 0 and (w + 7)) or (toaddr(S.syscall_wrapper[20]) + 7)
    return tonn(nat.fcall_with_rax(tr, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

local function check_wrapper(scno)
    local w = toaddr(S.syscall_wrapper[scno])
    return w ~= 0
end

print("[+] mprotect + shellcode test - FW 13.52\n")

-- Check common syscall wrappers
print("[*] Checking wrappers:\n")
local check_scnos = {73, 74, 75, 76, 77, 78, 79, 80, 477, 478}
for _, n in ipairs(check_scnos) do
    print(string.format("  sc%d: %s", n, check_wrapper(n) and "HAS WRAPPER" or "no wrapper"))
end

-- Step 1: mmap RW (no exec)
print("\n[*] mmap RW (prot=3)...")
local rw = scall(477, 0, 0x4000, 3, 0x1002, -1, 0)
print(string.format("  RW at 0x%x", rw))

-- Step 2: Write shellcode: mov rax, 0xDEAD; ret
print("[*] Writing shellcode...")
mem.write_byte(rw, 0x48); mem.write_byte(rw+1, 0xC7); mem.write_byte(rw+2, 0xC0)
mem.write_byte(rw+3, 0xAD); mem.write_byte(rw+4, 0xDE); mem.write_byte(rw+5, 0xAD); mem.write_byte(rw+6, 0xDE)
mem.write_byte(rw+7, 0xC3)  -- ret
print("  48 c7 c0 ad de ad de c3 (mov rax, 0xDEADDEAD; ret)")

-- Step 3: Try mprotect(scno=74) to add exec
print("[*] mprotect(addr, 0x4000, PROT_READ|PROT_EXEC=5)...")
local mp = scall(74, rw, 0x4000, 5, 0, 0, 0)
print(string.format("  mprotect returned: %d (expect 0 = success, -1 = blocked)", mp))

-- Step 4: Try execute
if mp == 0 then
    print("[*] mprotect SUCCESS! Executing shellcode...")
    local r = tonn(nat.fcall_with_rax(rw, 0, 0, 0, 0, 0, 0, 0))
    print(string.format("  Shellcode returned: 0x%x (expect 0xDEADDEAD)", r))
    if r == 0xDEADDEAD then
        print("[+] SHELLCODE EXECUTION CONFIRMED VIA mprotect!")
    end
else
    print("[-] mprotect failed or blocked")
    -- Try alternative mprotect scno
    for _, alt in ipairs({75, 471, 472, 473}) do
        if check_wrapper(alt) then
            print(string.format("[*] Trying mprotect at sc%d...", alt))
            local r2 = scall(alt, rw, 0x4000, 5, 0, 0, 0)
            print(string.format("  sc%d mprotect: %d", alt, r2))
            if r2 == 0 then
                local r3 = tonn(nat.fcall_with_rax(rw, 0, 0, 0, 0, 0, 0, 0))
                print(string.format("  Shellcode: 0x%x", r3))
                break
            end
        end
    end
end

-- Also test munmap (sc73) to clean up
print("\n[*] Cleanup test: munmap(sc73)...")
local mu = scall(73, rw, 0x4000, 0, 0, 0, 0)
print(string.format("  munmap: %d", mu))

print("\n[+] Test complete")
