--[[
    aio_native_tramp.lua
    Call aio_submit_cmd via native trampoline (bypass S.resolve wrapper)
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

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

S.resolve({close=6, getpid=20, pipe=42})

-- Use native trampoline
local w454 = toaddr(S.syscall_wrapper[454])
local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then return i end
    end
    return 7
end
local tramp = w454 + find_tramp(w454)

local function native_call(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] AIO via Native Trampoline\n")

-- Create pipe
local pfds = mem.alloc(8)
native_call(42, pfds, 0, 0, 0, 0, 0)
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

-- Build cmd_req
local buf = mem.alloc(64)
for i = 0, 63 do mem.write_byte(buf+i, i) end

local cr = mem.alloc(0x40)
mem.write_qword(cr, 0)         -- offset
mem.write_qword(cr+8, buf)     -- buf
mem.write_qword(cr+0x10, 64)   -- nbytes
mem.write_qword(cr+0x18, p_wr) -- fd (qword not dword!)
mem.write_qword(cr+0x20, 8)    -- cmd (qword not dword!)

-- reqs = array of pointer to cmd_req
local reqs = mem.alloc(8)
mem.write_qword(reqs, cr)

local ids = mem.alloc(8)
mem.write_qword(ids, 0)

-- Try both dword and qword for fd/cmd fields
print("[*] Trying all combinations of struct field sizes\n")

-- Syscall args: aio_submit_cmd(cmd, reqs, num_reqs, mode, ids)
-- Try as-resolved-call too
S.resolve({
    aio_submit_cmd = 0x29d,
})

-- Via wrapper
for test = 1, 6 do
    local ids2 = mem.alloc(8)
    mem.write_qword(ids2, 0)
    local r, id
    if test == 1 then
        -- Both dword
        mem.write_dword(cr+0x18, p_wr)
        mem.write_dword(cr+0x1c, 8)
        r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids2))
    elseif test == 2 then
        -- fd=dword cmd=qword
        mem.write_dword(cr+0x18, p_wr)
        mem.write_qword(cr+0x1c, 8)
        r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids2))
    elseif test == 3 then
        -- fd=qword at 0x18, cmd=qword at 0x20
        mem.write_qword(cr+0x18, p_wr)
        mem.write_qword(cr+0x20, 8)
        r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids2))
    elseif test == 4 then
        -- Native trampoline with extra args
        r = native_call(669, reqs, reqs, 1, 3, ids2, 0)
    elseif test == 5 then
        -- cmd_req first, not reqs
        r = tonn(S.aio_submit_cmd(cr, reqs, 1, 3, ids2))
    elseif test == 6 then
        -- Try with mode=0 instead of 3
        r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 0, ids2))
    end
    id = tonn(mem.read_qword(ids2))
    print(string.format("  test%d = %d  id=0x%x\n", test, r, id))
end

-- Try calling with wrapper directly (use sc669's own wrapper)
print("\n[*] Using sc669's own wrapper\n")
local w669 = toaddr(S.syscall_wrapper[669])
if w669 ~= 0 then
    local tramp669 = w669 + find_tramp(w669) 
    local ids3 = mem.alloc(8)
    mem.write_qword(ids3, 0)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    local r = tonn(nat.fcall_with_rax(tramp669, 669, reqs, reqs, 1, 3, ids3, 0))
    local id = tonn(mem.read_qword(ids3))
    print(string.format("  sc669 wrapper: %d  id=0x%x\n", r, id))
end

-- Check if there's a sys_errlist or similar we can read
print("\n[*] Scanning for error code indicators\n")
-- The return value -1 means EINVAL or similar
-- Let's try to find what syscall goes before/after to check pattern
for scno = 668, 670 do
    local r = native_call(scno, 0, 0, 0, 0, 0, 0)
    print(string.format("  sc%d(0,0,0,0,0,0) = %d", scno, r))
end
print("\n")

-- Print all return values from 655-670 with native call
print("[*] All AIO syscalls native:\n")
for scno = 655, 670 do
    local r = native_call(scno, 0, 0, 0, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d = %d [*** NON -1 ***]", scno, r))
    end
end

print("\n[+] Done")
