--[[
    aio_read_write.lua
    Try alternative AIO creation syscalls (aio_read, aio_write, etc.)
    FreeBSD AIO syscalls are around 270-290
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")
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

S.resolve({close=6, getpid=20})

print("[+] Alternative AIO Creation Syscalls\n")

-- Use sc454 as universal trampoline
local w454 = toaddr(S.syscall_wrapper[454])
local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then return i end
    end
    return 7
end
local tramp = w454 + find_tramp(w454)

local function scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

-- Scan for wrappers in 270-290 range
print("[*] Wrappers in 260-300:\n")
local found = {}
for scno = 260, 300 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        found[#found+1] = scno
        print(string.format("  sc%d (0x%x): wrapper at 0x%x", scno, scno, w))
    end
end
print(string.format("\n[+] %d wrappers found\n", #found))

if #found > 0 then
    -- Test each wrapper with null args (safe check)
    print("[*] Testing with null args:\n")
    for _, scno in ipairs(found) do
        local r = scall(scno, 0, 0, 0, 0, 0, 0)
        if r ~= -1 then
            print(string.format("  sc%d(0,0,0,0,0,0) = %d [*** NON -1 ***]", scno, r))
        end
    end
    
    -- Test with aio-like args (buf, nbytes, fd, etc.)
    print("\n[*] Testing with AIO-like args:\n")
    local buf = mem.alloc(0x100)
    local pfds = mem.alloc(8)
    scall(42, pfds, 0, 0, 0, 0, 0)  -- pipe
    local p_rd = tonn(mem.read_dword(pfds))
    local p_wr = tonn(mem.read_dword(pfds+4))
    
    for _, scno in ipairs(found) do
        local r = scall(scno, buf, 64, p_wr, 0, 0, 0)
        if r ~= -1 then
            print(string.format("  sc%d(buf,64,fd,0,0,0) = %d [*** NON -1 ***]", scno, r))
        end
    end
end

-- Also check if there are AIO-related syscalls at different offsets
-- On FreeBSD 9: aio_read=275, aio_write=276, aio_mlock=277
-- But Sony may have renumbered them
print("\n[*] Also checking wrappers in 270-280 specifically:\n")
for scno = 270, 280 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        local r = scall(scno, 0, 0, 0, 0, 0, 0)
        print(string.format("  sc%d wrapper=0x%x call(0)=%d", scno, w, r))
    end
end

-- Last attempt: try calling aio_submit_cmd via its own wrapper
print("\n[*] aio_submit_cmd via sc669's own wrapper:\n")
local w669 = toaddr(S.syscall_wrapper[669])
if w669 ~= 0 then
    local t669 = w669 + find_tramp(w669)
    local buf2 = mem.alloc(0x40)
    mem.write_qword(buf2, 0)
    mem.write_qword(buf2+8, mem.alloc(64))
    mem.write_qword(buf2+0x10, 64)
    mem.write_qword(buf2+0x18, p_wr)
    mem.write_qword(buf2+0x20, 8)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    -- Try every possible arg mapping through sc669's wrapper
    for rdi_val = 0, 3 do
        for rsi_val = 0, 3 do
            local rdi = rdi_val == 0 and buf2 or (rdi_val == 1 and p_wr or (rdi_val == 2 and mem.alloc(8) or 0))
            local rsi = rsi_val == 0 and buf2 or (rsi_val == 1 and p_wr or (rsi_val == 2 and mem.alloc(8) or 0))
            local r = tonn(nat.fcall_with_rax(t669, 669, rdi, rsi, 1, 3, ids, 0))
            if r ~= -1 then
                print(string.format("  args(%d,%d,1,3): r=%d id=0x%x [*** INTERESTING ***]", rdi_val, rsi_val, r, tonn(mem.read_qword(ids))))
            end
        end
    end
end

print("\n[+] Done")
