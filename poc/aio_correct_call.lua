--[[
    aio_correct_call.lua
    Call aio_submit_cmd with CORRECT prototype:
    aio_submit_cmd(cmd_code, reqs_array, num_reqs, 3, ids)
    where cmd_code = AIO_CMD_READ=1 or AIO_CMD_WRITE=2
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

S.resolve({
    aio_submit_cmd = 0x29d,
    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    pipe = 42, close = 6, write = 4, read = 3,
    getpid = 20,
})

print("[+] AIO Correct Call Test\n")

-- Create pipe
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

-- Data buffer
local data = mem.alloc(64)
for i = 0, 63 do mem.write_byte(data+i, 0x41+(i%26)) end

-- Create cmd_req struct (SceKernelAioRWRequest is 0x20 bytes according to FreeBSD aiocb)
-- struct SceKernelAioRWRequest {
--   int64_t offset;    // +0x00
--   void *buf;         // +0x08
--   size_t nbytes;     // +0x10
--   int fd;            // +0x18
--   int cmd;           // +0x1c
-- };
local cmd_req = mem.alloc(0x20)
mem.write_qword(cmd_req, 0)          -- offset
mem.write_qword(cmd_req+8, data)     -- buf
mem.write_qword(cmd_req+0x10, 64)    -- nbytes
mem.write_dword(cmd_req+0x18, p_wr)  -- fd = pipe write end
mem.write_dword(cmd_req+0x1c, 8)     -- cmd = LIO_WRITE (8)

-- reqs = array of SceKernelAioRWRequest pointers
-- (8 bytes per entry, pointing to cmd_req structs)
local reqs = mem.alloc(8)
mem.write_qword(reqs, cmd_req)

-- IDs output
local ids = mem.alloc(8)
mem.write_qword(ids, 0)

-- CORRECT CALL:
-- aio_submit_cmd(cmd_code, reqs, num_reqs, prio, ids)
-- cmd_code = 2 = AIO_CMD_WRITE
print("[*] Testing with cmd=2 (AIO_CMD_WRITE)\n")
local r = tonn(S.aio_submit_cmd(2, reqs, 1, 3, ids))
local id = tonn(mem.read_qword(ids))
print(string.format("  aio_submit_cmd(2, reqs, 1, 3, ids) = %d  id=0x%x\n", r, id))

-- Try cmd=1 (AIO_CMD_READ)
if r == -1 then
    print("[*] Trying cmd=1 (AIO_CMD_READ)\n")
    local ids2 = mem.alloc(8)
    mem.write_qword(ids2, 0)
    r = tonn(S.aio_submit_cmd(1, reqs, 1, 3, ids2))
    id = tonn(mem.read_qword(ids2))
    print(string.format("  aio_submit_cmd(1, reqs, 1, 3, ids) = %d  id=0x%x\n", r, id))
end

-- Try with LIO_READ (cmd=4) on pipe read end
if r == -1 then
    print("[*] Trying LIO_READ on pipe_rd\n")
    local cr2 = mem.alloc(0x20)
    mem.write_qword(cr2, 0)
    mem.write_qword(cr2+8, data)
    mem.write_qword(cr2+0x10, 64)
    mem.write_dword(cr2+0x18, p_rd)  -- read fd
    mem.write_dword(cr2+0x1c, 4)     -- LIO_READ
    
    local reqs2 = mem.alloc(8)
    mem.write_qword(reqs2, cr2)
    local ids3 = mem.alloc(8)
    mem.write_qword(ids3, 0)
    r = tonn(S.aio_submit_cmd(1, reqs2, 1, 3, ids3))
    id = tonn(mem.read_qword(ids3))
    print(string.format("  aio_submit_cmd(1, reqs, 1, 3, ids) = %d  id=0x%x\n", r, id))
end

-- If submit succeeded, test complete AIO workflow!
if r ~= -1 and id ~= 0 then
    print("\n[+] AIO SUBMIT WORKED! Testing full workflow...\n")
    
    -- Wait for completion
    local states = mem.alloc(4)
    mem.write_dword(states, 0)
    local r_wait = tonn(S.aio_multi_wait(ids, 1, states, 0, 0))
    print(string.format("  aio_multi_wait = %d  state=%d\n", r_wait, tonn(mem.read_dword(states))))
    
    -- Read from pipe
    local read_buf = mem.alloc(64)
    local r_read = tonn(S.read(p_rd, read_buf, 64))
    print(string.format("  read from pipe: %d bytes\n", r_read))
    if r_read > 0 then
        local hex = ""
        for i = 0, math.min(r_read-1, 15) do
            hex = hex .. string.format("%02x ", tonn(mem.read_byte(read_buf+i)))
        end
        print(string.format("  data: %s\n", hex))
    end
    
    -- Delete
    local r_del = tonn(S.aio_multi_delete(ids, 1, states))
    print(string.format("  aio_multi_delete = %d\n", r_del))
else
    print("\n[*] Submit still failed. Trying with exact lapse.lua struct (0x40 bytes):\n")
    
    -- lapse.lua uses 0x40 byte cmd_req structs
    local cr3 = mem.alloc(0x40)
    mem.write_qword(cr3, 0)
    mem.write_qword(cr3+8, data)
    mem.write_qword(cr3+0x10, 64)
    mem.write_dword(cr3+0x18, p_wr)
    mem.write_dword(cr3+0x1c, 8)
    
    local reqs3 = mem.alloc(8)
    mem.write_qword(reqs3, cr3)
    local ids4 = mem.alloc(8)
    mem.write_qword(ids4, 0)
    
    for _, cmd in ipairs({1, 2, 0x1001, 0x1002}) do
        mem.write_qword(ids4, 0)
        r = tonn(S.aio_submit_cmd(cmd, reqs3, 1, 3, ids4))
        id = tonn(mem.read_qword(ids4))
        print(string.format("  cmd=0x%x (0x40 struct): r=%d id=0x%x\n", cmd, r, id))
        if r ~= -1 then break end
    end
end

print("\n[+] Done")
