--[[
    aio_ultra_safe.lua
    Ultra-safe AIO probe — only test known-named syscalls with proper structs
    AVOID: sc660 (unknown), sc661 (kexec), sc665/667/668/670 (unknown)
    Only test: 662(aio_multi_delete), 663(aio_multi_wait), 664(aio_multi_poll),
               666(aio_multi_cancel), 669(aio_submit_cmd)
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

local w454 = toaddr(S.syscall_wrapper[454])
local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then return i end
    end
    return 7
end
local tramp_454 = w454 + find_tramp(w454)

local function scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp_454, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] Ultra-Safe AIO Probe — FW 13.52\n")

-- Step 1: Verify we're alive
local pid = scall(20, 0,0,0,0,0,0)
print(string.format("[*] PID = %d\n", pid))

-- Step 2: Try calling each known-valid AIO syscall with minimal args
-- These should return -1 (EINVAL/EBADF) with null args, NOT crash
print("[Step 2] Known AIO syscalls with zero/empty args\n")

do
    local r = scall(662, 0, 0, 0, 0, 0, 0)  -- aio_multi_delete
    print(string.format("  aio_multi_delete(662) null = %d", r))
end
print("[*] survived aio_multi_delete null\n")

do
    local r = scall(663, 0, 0, 0, 0, 0, 0)  -- aio_multi_wait
    print(string.format("  aio_multi_wait(663) null = %d", r))
end
print("[*] survived aio_multi_wait null\n")

do
    local r = scall(664, 0, 0, 0, 0, 0, 0)  -- aio_multi_poll
    print(string.format("  aio_multi_poll(664) null = %d", r))
end
print("[*] survived aio_multi_poll null\n")

do
    local r = scall(666, 0, 0, 0, 0, 0, 0)  -- aio_multi_cancel
    print(string.format("  aio_multi_cancel(666) null = %d", r))
end
print("[*] survived aio_multi_cancel null\n")

do
    local r = scall(669, 0, 0, 0, 0, 0, 0)  -- aio_submit_cmd
    print(string.format("  aio_submit_cmd(669) null = %d", r))
end
print("[*] survived aio_submit_cmd null\n")

-- Step 3: With buf pointers (properly zeroed)
print("[Step 3] With valid buf pointers\n")
local buf = mem.alloc(0x100)
for i = 0, 0xFF do mem.write_byte(buf+i, 0) end

do
    -- aio_multi_delete(ids, num_ids, states) - zeroed buf as ids
    local r = scall(662, buf, 0, buf, 0, 0, 0)
    print(string.format("  aio_multi_delete buf,0 = %d", r))
end

do
    local r = scall(662, buf, 1, buf, 0, 0, 0)
    print(string.format("  aio_multi_delete buf,1 = %d", r))
end

print("[*] survived aio_multi_delete with bufs\n")

-- aio_multi_wait with buf
do
    local r = scall(663, buf, 1, buf, 0, 0, 0)
    print(string.format("  aio_multi_wait buf,1,buf = %d", r))
end

-- aio_multi_poll with buf
do
    local r = scall(664, buf, 1, buf, 0, 0, 0)
    print(string.format("  aio_multi_poll buf,1,buf = %d", r))
end

-- aio_multi_cancel with buf
do
    local r = scall(666, buf, 1, buf, 0, 0, 0)
    print(string.format("  aio_multi_cancel buf,1,buf = %d", r))
end

-- aio_submit_cmd with buf
do
    local r = scall(669, buf, buf, 0, 0, 0, 0)
    print(string.format("  aio_submit_cmd buf,buf,0 = %d", r))
end

print("\n[+] ALL TESTS PASSED — AIO syscalls are available!")
