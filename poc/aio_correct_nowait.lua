--[[
    aio_correct_nowait.lua
    Call aio_submit_cmd with mode=0 (non-blocking)
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
    pipe = 42, close = 6,
    getpid = 20,
})

print("[+] AIO Correct+Nowait\n")

-- Create pipe
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe wr=%d\n", p_wr))

-- Data buffer
local data = mem.alloc(64)

-- cmd_req struct (0x20 bytes)
local cmd_req = mem.alloc(0x20)
mem.write_qword(cmd_req, 0)
mem.write_qword(cmd_req+8, data)
mem.write_qword(cmd_req+0x10, 64)
mem.write_dword(cmd_req+0x18, p_wr)
mem.write_dword(cmd_req+0x1c, 8)

-- reqs = array of pointers
local reqs = mem.alloc(8)
mem.write_qword(reqs, cmd_req)

-- IDs output
local ids = mem.alloc(8)
mem.write_qword(ids, 0)

-- CORRECT: cmd=2 (AIO_CMD_WRITE), mode=0 (NOWAIT)
print("  calling aio_submit_cmd(2, reqs, 1, 0, ids)...\n")
local r = tonn(S.aio_submit_cmd(2, reqs, 1, 0, ids))
local id = tonn(mem.read_qword(ids))
print(string.format("  result=%d  id=0x%x\n", r, id))

-- Try cmd=1, mode=0 too
if r == -1 then
    mem.write_qword(ids, 0)
    print("  trying cmd=1, mode=0...\n")
    r = tonn(S.aio_submit_cmd(1, reqs, 1, 0, ids))
    id = tonn(mem.read_qword(ids))
    print(string.format("  result=%d  id=0x%x\n", r, id))
end

print("[+] Done")
