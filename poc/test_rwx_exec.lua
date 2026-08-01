--[[
    test_rwx_exec.lua
    Test if RWX memory is truly executable by copying a known function to it
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

print("[+] RWX Execution Test - FW 13.52\n")

-- Step 1: mmap RWX
print("[*] mmap RWX...")
local rwx = scall(477, 0, 0x4000, 7, 0x1002, -1, 0)
print(string.format("  RWX at 0x%x", rwx))

-- Step 2: Verify it's readable and writable
mem.write_byte(rwx, 0xCC)
local rback = tonn(mem.read_byte(rwx))
print(string.format("  Write/read test: wrote 0xCC, read 0x%02x", rback))

-- Step 3: Copy the getpid wrapper's trampoline+syscall to RWX
-- The getpid wrapper is at S.syscall_wrapper[20]
-- At +7: mov r10, rcx (49 89 ca), at +10: 0f 05 (syscall), at +12: c3 (ret)
local gp = toaddr(S.syscall_wrapper[20])
print(string.format("  getpid wrapper at 0x%x", gp))

-- Dump the first 16 bytes
print("  getpid wrapper bytes:")
local hex = ""
for i = 0, 15 do
    hex = hex .. string.format("%02x ", tonn(mem.read_byte(gp + i)))
end
print("    " .. hex)

-- Copy exactly 16 bytes (should contain the entire wrapper stub)
print("  Copying wrapper to RWX...")
for i = 0, 15 do
    mem.write_byte(rwx + i, tonn(mem.read_byte(gp + i)))
end

-- Verify copy
print("  RWX copy bytes:")
local hex2 = ""
for i = 0, 15 do
    hex2 = hex2 .. string.format("%02x ", tonn(mem.read_byte(rwx + i)))
end
print("    " .. hex2)

-- Step 4: Call the COPIED version
-- The copied stub starts with mov rax, 0x14 (getpid=20) at offset 0
-- Then trampoline at +7, syscall at +10, ret at +12
-- We call at RWX+7 (trampoline, same pattern as our universal trampoline)
print("[*] Calling copied wrapper at RWX+7...")
local r = tonn(nat.fcall_with_rax(rwx + 7, 20, 0, 0, 0, 0, 0, 0))
print(string.format("  Result: %d (expect PID if exec works)", r))

-- Step 5: If that worked, try calling the copy FROM THE START (mov rax, 0x14 is first)
-- But we call with rax=0, so the mov rax, 0x14 in the copied code should set it to 20
print("[*] Calling copied wrapper from start (mov rax, 0x14)...")
-- Actually, the fcall_with_rax sets rax first, so we'd be overwriting the COPY's rax
-- Let's call it properly: fcall_with_rax sets rax=20 and we call at rwx+7 (trampoline)
-- But we already did that above. Let's try calling at RWX+0 (the mov rax, 0x14 instruction)
-- If we call at RWX+0 with rax=0, the wrapper will set rax=20, then trampoline, syscall
local r2 = tonn(nat.fcall_with_rax(rwx, 0, 0, 0, 0, 0, 0, 0))
print(string.format("  Result from start: %d (expect PID if wrapper copied correctly)", r2))

-- Step 6: Test simple shellcode: mov rax, 0x1234; ret
-- We know the copy worked above (maybe), so now let's write custom shellcode
print("[*] Writing custom shellcode: mov rax, 0x1234; ret")
mem.write_byte(rwx, 0x48)      -- REX.W prefix
mem.write_byte(rwx+1, 0xC7)    -- MOV r/m64, imm32
mem.write_byte(rwx+2, 0xC0)    -- ModRM: rax
mem.write_byte(rwx+3, 0x34)    -- imm32 low
mem.write_byte(rwx+4, 0x12)    -- 
mem.write_byte(rwx+5, 0x00)    -- 
mem.write_byte(rwx+6, 0x00)    -- imm32 high
mem.write_byte(rwx+7, 0xC3)    -- ret

-- Call it
local r3 = tonn(nat.fcall_with_rax(rwx, 0xFFFF, 0, 0, 0, 0, 0, 0))
print(string.format("  Shellcode returned: 0x%x (expect 0x1234 if exec works)", r3))

print("\n[+] Test complete")
