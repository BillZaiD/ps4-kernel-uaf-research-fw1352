--[[
    aio_probe.lua
    Test AIO syscalls (655-670) — the critical untested range
    These are the syscalls that lapse.lua uses for exploitation:
      0x295 (661) = kexec
      0x296 (662) = aio_multi_delete
      0x297 (663) = aio_multi_wait
      0x298 (664) = aio_multi_poll
      0x29a (666) = aio_multi_cancel
      0x29d (669) = aio_submit_cmd
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

local function any_scall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    if w == 0 then return -2 end
    local tramp = w + find_tramp(w)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

-- Use sc454's wrapper as base trampoline
local w454 = toaddr(S.syscall_wrapper[454])
local tramp_454 = w454 + find_tramp(w454)

local function fcall_454(scno, rdi, rsi, rdx, rcx, r8, r9)
    return tonn(nat.fcall_with_rax(tramp_454, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] AIO Syscall Probe — FW 13.52\n")

-- Phase 1: Check which syscalls have wrappers (655-670)
print("[Phase 1] Wrapper scan (655-670)\n")

local wrappers = {}
for scno = 655, 670 do
    local w = toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        wrappers[#wrappers + 1] = scno
        print(string.format("  sc%d (0x%x): wrapper at 0x%x", scno, scno, w))
    end
end

if #wrappers == 0 then
    print("\n[!] NO WRAPPERS found in 655-670!\n")
    print("[*] Trying via sc454's universal trampoline instead...\n")
end

print(string.format("\n[+] %d wrappers found\n", #wrappers))

-- Phase 2: Try calling via sc454's trampoline (works even without wrappers)
print("[Phase 2] Calling via sc454 universal trampoline\n")

local buf = mem.alloc(0x1000)
local ids_buf = mem.alloc(0x200)  -- for AIO ID arrays
for i = 0, 0x1FF do mem.write_byte(ids_buf + i, 0) end

-- lapse.lua SYS mapping:
-- aio_submit_cmd = 0x29d (669), aio_multi_delete = 0x296 (662)
-- aio_multi_poll = 0x298 (664), aio_multi_wait = 0x297 (663)
-- aio_multi_cancel = 0x29a (666), kexec = 0x295 (661)

local test_scnos = {
    {660, "660 (0x294) — unknown aio"},
    {661, "661 (0x295) — kexec"},
    {662, "662 (0x296) — aio_multi_delete"},
    {663, "663 (0x297) — aio_multi_wait"},
    {664, "664 (0x298) — aio_multi_poll"},
    {665, "665 (0x299) — unknown"},
    {666, "666 (0x29a) — aio_multi_cancel"},
    {667, "667 (0x29b) — unknown"},
    {668, "668 (0x29c) — unknown"},
    {669, "669 (0x29d) — aio_submit_cmd"},
    {670, "670 (0x29e) — unknown"},
}

-- Pattern A: null args (test if syscall survives)
print("--- Pattern A: all zero ---\n")
for _, t in ipairs(test_scnos) do
    local scno = t[1]
    local desc = t[2]
    local r = fcall_454(scno, 0, 0, 0, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d (%s) = %d  [*** NON -1 ***]", scno, desc, r))
    end
end

-- Pattern B: buf+size (common kernel interface)
print("\n--- Pattern B: buf, 0x100 ---\n")
for _, t in ipairs(test_scnos) do
    local scno = t[1]
    local desc = t[2]
    local r = fcall_454(scno, buf, 0x100, 0, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d (%s) = %d  [*** NON -1 ***]", scno, desc, r))
    end
end

-- Pattern C: buf+size+flags
print("\n--- Pattern C: buf, 0x100, 1, 0, 0, 0 ---\n")
for _, t in ipairs(test_scnos) do
    local scno = t[1]
    local desc = t[2]
    local r = fcall_454(scno, buf, 0x100, 1, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d (%s) = %d  [*** NON -1 ***]", scno, desc, r))
    end
end

-- Pattern D: aio_multi_delete specific: (ids_buf, num_ids, states_buf)
print("\n--- Pattern D: aio-like args (ids_buf, count, states_buf) ---\n")
for _, t in ipairs(test_scnos) do
    local scno = t[1]
    local desc = t[2]
    local r = fcall_454(scno, ids_buf, 1, buf, 0, 0, 0)
    if r ~= -1 then
        print(string.format("  sc%d (%s) = %d  [*** NON -1 ***]", scno, desc, r))
    end
end

-- Phase 3: If wrappers exist, test directly too
if #wrappers > 0 then
    print("\n[Phase 3] Direct wrapper calls (if wrappers exist)\n")
    for _, scno in ipairs(wrappers) do
        local r1 = any_scall(scno, 0, 0, 0, 0, 0, 0)
        local r2 = any_scall(scno, buf, 0x100, 0, 0, 0, 0)
        local r3 = any_scall(scno, ids_buf, 1, buf, 0, 0, 0)
        print(string.format("  sc%d: zero=%d  buf=%d  aio=%d", scno, r1, r2, r3))
    end
end

-- Phase 4: Try sending a real AIO command then deleting it
print("\n[Phase 4] Real AIO test via socketpair + aio_submit\n")
-- First create a pipe for IO
local pipe_fds = mem.alloc(8)
local r_pipe = fcall_454(42, pipe_fds, 0, 0, 0, 0, 0)  -- pipe(pipe_fds)
print(string.format("pipe() = %d, fds: %d %d", r_pipe, tonn(mem.read_dword(pipe_fds)), tonn(mem.read_dword(pipe_fds+4))))

if r_pipe == 0 then
    local rfd = tonn(mem.read_dword(pipe_fds))
    local wfd = tonn(mem.read_dword(pipe_fds+4))
    
    -- Build a simple AIO command structure
    -- struct SceKernelAioCmdReq {
    --   int64_t offset;
    --   void *buf;
    --   size_t nbytes;
    --   int fd;
    --   int cmd;
    -- }
    -- aio_submit_cmd(cmd_reqs, reqs_array, num_reqs, mode, ids_out)
    
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)        -- offset = 0
    mem.write_qword(cmd_req+8, buf)     -- buf
    mem.write_qword(cmd_req+0x10, 64)   -- nbytes
    mem.write_dword(cmd_req+0x18, wfd)  -- fd = write end
    mem.write_dword(cmd_req+0x1c, 4)    -- cmd = LIO_WRITE
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids_out = mem.alloc(8)
    
    print("  Testing aio_submit_cmd (669)...\n")
    local r_submit = fcall_454(669, cmd_req, reqs, 1, 3, ids_out)
    print(string.format("  aio_submit_cmd = %d, ids_out = 0x%x", r_submit, tonn(mem.read_qword(ids_out))))
    
    if r_submit ~= -1 then
        local submitted_id = tonn(mem.read_qword(ids_out))
        print(string.format("  Submitted AIO ID: 0x%x", submitted_id))
        
        -- Test aio_multi_wait (663)
        local states = mem.alloc(4)
        mem.write_dword(states, 0)
        print("  Testing aio_multi_wait (663)...\n")
        local r_wait = fcall_454(663, ids_out, 1, states, 0, 0)
        print(string.format("  aio_multi_wait = %d, state=%d", r_wait, tonn(mem.read_dword(states))))
        
        -- Test aio_multi_delete (662) — THE KEY VULNERABILITY!
        print("  Testing aio_multi_delete (662)...\n")
        local r_del = fcall_454(662, ids_out, 1, buf)
        print(string.format("  aio_multi_delete = %d", r_del))
    end
end

print("\n[+] AIO probe complete")
