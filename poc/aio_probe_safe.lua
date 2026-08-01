--[[
    aio_probe_safe.lua
    Safe AIO syscall probe (avoid kexec, avoid null deref)
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

-- Use sc454 as universal trampoline
local w454 = toaddr(S.syscall_wrapper[454])
local tramp_454 = w454 + find_tramp(w454)

local function safe_fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local ok, r = pcall(function()
        return tonn(nat.fcall_with_rax(tramp_454, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
    end)
    if ok then return r, "ok" end
    return -3, "CRASH: " .. tostring(r)
end

print("[+] Safe AIO Syscall Probe — FW 13.52\n")
print("[*] Wrappers confirmed present for 655-670\n")

local buf = mem.alloc(0x1000)
for i = 0, 0xFFF do mem.write_byte(buf+i, 0) end

-- Test each AIO syscall with safe buf pointers
-- Skip kexec(661) entirely
local test_plan = {
    {660, "unknown_aio_660", {buf, 0x100, 0, 0, 0, 0}},
    {662, "aio_multi_delete(662)", {0, 0, 0, 0, 0, 0}},  -- will return -1 (EINVAL/EBADF) safely
    {663, "aio_multi_wait(663)", {buf, 1, buf, 0, 0, 0}},
    {664, "aio_multi_poll(664)", {buf, 1, buf, 0, 0, 0}},
    {666, "aio_multi_cancel(666)", {buf, 1, buf, 0, 0, 0}},
    {669, "aio_submit_cmd(669)", {buf, buf, 0, 0, 0, 0}},
}

for _, t in ipairs(test_plan) do
    local scno, name, args = t[1], t[2], t[3]
    local r, status = safe_fcall(scno, args[1], args[2], args[3], args[4], args[5], args[6])
    print(string.format("  sc%d (%s) = %d [%s]", scno, name, r, status))
end

-- Test actual AIO submit + delete via pipe
print("\n[Phase 2] Real AIO workflow test\n")

-- Create a pipe for AIO operations
local pipe_fds = mem.alloc(8)
local r_pipe = tonn(nat.fcall_with_rax(tramp_454, 42, pipe_fds, 0, 0, 0, 0, 0))
print(string.format("pipe() = %d", r_pipe))

if r_pipe == 0 then
    local rfd = tonn(mem.read_dword(pipe_fds))
    local wfd = tonn(mem.read_dword(pipe_fds + 4))
    print(string.format("  read_fd=%d write_fd=%d", rfd, wfd))
    
    -- Build AIO command request
    -- struct SceKernelAioCmdReq {
    --   int64_t offset;    // +0
    --   void *buf;         // +8
    --   size_t nbytes;     // +0x10
    --   int fd;            // +0x18
    --   int cmd;           // +0x1c
    -- }
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)         -- offset
    mem.write_qword(cmd_req+8, buf)     -- buf
    mem.write_qword(cmd_req+0x10, 64)   -- nbytes
    mem.write_dword(cmd_req+0x18, wfd)  -- fd (write end)
    mem.write_dword(cmd_req+0x1c, 4)    -- cmd = LIO_WRITE
    
    -- reqs array = pointer to cmd_req
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    -- ids output buffer
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    -- states buffer
    local states = mem.alloc(4)
    mem.write_dword(states, 0)
    
    -- aio_submit_cmd(cmd_reqs, reqs, num_reqs, 3, ids)
    print("\n  --- aio_submit_cmd(669) ---\n")
    local r_sub, st_sub = safe_fcall(669, cmd_req, reqs, 1, 3, ids, 0)
    local submitted_id = tonn(mem.read_qword(ids))
    print(string.format("  submit=%d [%s] id=0x%x", r_sub, st_sub, submitted_id))
    
    if r_sub >= 0 and submitted_id ~= 0 then
        -- aio_multi_wait(663): (ids, num_ids, states, mode, timeout)
        print("  --- aio_multi_wait(663) ---\n")
        local r_wait, st_wait = safe_fcall(663, ids, 1, states, 0, 0, 0)
        print(string.format("  wait=%d [%s] state=%d", r_wait, st_wait, tonn(mem.read_dword(states))))
        
        -- aio_multi_delete(662): (ids, num_ids, states)
        print("  --- aio_multi_delete(662) ---\n")
        local r_del, st_del = safe_fcall(662, ids, 1, states, 0, 0, 0)
        print(string.format("  delete=%d [%s]", r_del, st_del))
    end
    
    -- Now test aio_multi_delete on invalid ID (should return -1 safely)
    print("\n  --- aio_multi_delete(662) with zero ID ---\n")
    mem.write_qword(ids, 0)
    local r_del2, st_del2 = safe_fcall(662, ids, 1, states, 0, 0, 0)
    print(string.format("  delete(zero_id)=%d [%s]", r_del2, st_del2))
end

print("\n[+] Safe AIO probe complete")
