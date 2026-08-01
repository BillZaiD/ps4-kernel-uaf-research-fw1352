--[[
    aio_workflow.lua
    Test full AIO workflow: pipe → submit → wait → delete
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

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

S.resolve({
    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_poll = 0x298,
    aio_multi_cancel = 0x29a,
    aio_submit_cmd = 0x29d,
    kqueue = 362, kevent = 363,
    pipe = 42, close = 6, write = 4, read = 3,
    getpid = 20,
})

print("[+] AIO Workflow Test — FW 13.52\n")

-- Step 1: Create pipe
local pipe_fds = mem.alloc(8)
local r_pipe = tonn(S.pipe(pipe_fds))
print(string.format("pipe() = %d", r_pipe))

if r_pipe ~= 0 then
    print("[!] pipe failed\n")
    return
end

local rfd = tonn(mem.read_dword(pipe_fds))
local wfd = tonn(mem.read_dword(pipe_fds+4))
print(string.format("  read_fd=%d write_fd=%d\n", rfd, wfd))

-- Step 2: Prepare buffer with test data
local test_data = mem.alloc(64)
for i = 0, 63 do mem.write_byte(test_data+i, 0x41 + (i % 26)) end

-- Step 3: Build AIO command request
-- struct SceKernelAioCmdReq {
--   int64_t offset;    // +0x00
--   void *buf;         // +0x08
--   size_t nbytes;     // +0x10
--   int fd;            // +0x18
--   int cmd;           // +0x1c
-- }
local cmd_req = mem.alloc(0x40)
mem.write_qword(cmd_req, 0)          -- offset
mem.write_qword(cmd_req+8, test_data) -- buf
mem.write_qword(cmd_req+0x10, 64)    -- nbytes
mem.write_dword(cmd_req+0x18, wfd)   -- fd = write end of pipe
mem.write_dword(cmd_req+0x1c, 4)     -- cmd = LIO_WRITE

print(string.format("cmd_req at 0x%x\n", toaddr(cmd_req)))

-- reqs array pointing to cmd_req
local reqs = mem.alloc(8)
mem.write_qword(reqs, cmd_req)

-- ids output buffer
local ids = mem.alloc(8)
mem.write_qword(ids, 0)

-- states output buffer
local states = mem.alloc(4)
mem.write_dword(states, 0)

-- Step 4: aio_submit_cmd(cmd_reqs, reqs, num_reqs, mode, ids)
-- mode=3 means?
print("[*] Calling aio_submit_cmd(669)...\n")
local r_sub = tonn(S.aio_submit_cmd(cmd_req, reqs, 1, 3, ids))
local submitted_id = tonn(mem.read_qword(ids))
print(string.format("  submit=%d  id=0x%x (%d)\n", r_sub, submitted_id, submitted_id))

if r_sub < 0 then
    print("[!] submit failed — trying alternative arg patterns\n")
    
    -- Try different arg patterns from lapse.lua
    -- aio_submit_cmd(cmd, reqs, num_reqs, 3, ids)
    -- Pattern 2: cmd_req followed by reqs array
    local reqs2 = mem.alloc(0x40)
    mem.write_qword(reqs2, cmd_req)
    mem.write_qword(reqs2+8, 0)
    
    print("[*] Trying with larger reqs buffer...\n")
    r_sub = tonn(S.aio_submit_cmd(cmd_req, reqs2, 1, 3, ids))
    submitted_id = tonn(mem.read_qword(ids))
    print(string.format("  submit=%d  id=0x%x\n", r_sub, submitted_id))
end

if r_sub >= 0 and submitted_id ~= 0 then
    -- Step 5: aio_multi_wait(ids, num_ids, states, mode, timeout)
    print("\n[*] aio_multi_wait(663)...\n")
    local r_wait = tonn(S.aio_multi_wait(ids, 1, states, 0, 0))
    local state = tonn(mem.read_dword(states))
    print(string.format("  wait=%d  state=%d\n", r_wait, state))
    
    -- Read pipe data to see if write completed
    local read_buf = mem.alloc(64)
    for i = 0, 63 do mem.write_byte(read_buf+i, 0) end
    local r_read = tonn(S.read(rfd, read_buf, 64))
    print(string.format("  read from pipe: ret=%d\n", r_read))
    if r_read > 0 then
        local hex = ""
        for i = 0, r_read-1 do
            hex = hex .. string.format("%02x ", tonn(mem.read_byte(read_buf+i)))
        end
        print(string.format("  data: %s\n", hex))
    end
    
    -- Step 6: aio_multi_delete(ids, num_ids, states) — THE KEY!
    print("\n[*] aio_multi_delete(662) — KEY SYSCALL!\n")
    mem.write_dword(states, 0)
    local r_del = tonn(S.aio_multi_delete(ids, 1, states))
    local del_state = tonn(mem.read_dword(states))
    print(string.format("  delete=%d  state=%d\n", r_del, del_state))
    
    -- Step 7: Try double delete (should fail)
    print("\n[*] Double delete test...\n")
    local r_del2 = tonn(S.aio_multi_delete(ids, 1, states))
    print(string.format("  delete2=%d\n", r_del2))
end

-- Step 8: Test aio_multi_delete with invalid IDs
print("\n[*] aio_multi_delete with zeroed IDs...\n")
mem.write_qword(ids, 0)
local r_del3 = tonn(S.aio_multi_delete(ids, 1, states))
print(string.format("  delete(zero)=%d\n", r_del3))

-- Step 9: Test aio_multi_delete with 2 IDs
print("\n[*] aio_multi_delete with 2 IDs (like lapse.lua does)...\n")
local ids2 = mem.alloc(32)
for i = 0, 31 do mem.write_byte(ids2+i, 0) end
mem.write_qword(ids2, submitted_id)  -- first ID valid
mem.write_qword(ids2+8, 0)          -- second ID zero
local r_del4 = tonn(S.aio_multi_delete(ids2, 2, states))
print(string.format("  delete(2_ids)=%d\n", r_del4))

print("\n[+] AIO workflow test complete")
