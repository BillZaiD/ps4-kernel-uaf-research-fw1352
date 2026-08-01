--[[
    aio_submit_variations.lua
    Try different arg patterns for aio_submit_cmd
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
    aio_submit_cmd = 0x29d,
    pipe = 42, close = 6, write = 4, read = 3,
    getpid = 20,
})

print("[+] AIO Submit Variations\n")

-- Create pipe
local pipe_fds = mem.alloc(8)
tonn(S.pipe(pipe_fds))
local rfd = tonn(mem.read_dword(pipe_fds))
local wfd = tonn(mem.read_dword(pipe_fds+4))
print(string.format("pipe: rfd=%d wfd=%d\n", rfd, wfd))

local data = mem.alloc(64)
for i = 0, 63 do mem.write_byte(data+i, 0x41 + (i%26)) end

-- Variation 1: cmd=8 (LIO_WRITE from lapse.lua)
print("[Var 1] cmd=8, direct reqs\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, wfd)
    mem.write_dword(cmd_req+0x1c, 8)  -- LIO_WRITE = 8
    
    -- reqs = pointer to cmd_req
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  submit(reqs,reqs,1,3,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Variation 2: cmd=4 instead of 8
print("[Var 2] cmd=4, direct reqs\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, wfd)
    mem.write_dword(cmd_req+0x1c, 4)
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  submit(reqs,reqs,1,3,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Variation 3: cmd_req as first arg (not reqs)
print("[Var 3] cmd_req as first arg, reqs as second\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, wfd)
    mem.write_dword(cmd_req+0x1c, 8)
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(cmd_req, reqs, 1, 3, ids))
    print(string.format("  submit(cmd,reqs,1,3,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Variation 4: mode=1 (instead of 3)
print("[Var 4] mode=1\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, wfd)
    mem.write_dword(cmd_req+0x1c, 8)
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 1, ids))
    print(string.format("  submit(reqs,reqs,1,1,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Variation 5: num_reqs as first arg?
print("[Var 5] Different arg order (n, reqs, cmd, mode, ids)\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, wfd)
    mem.write_dword(cmd_req+0x1c, 8)
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(1, reqs, cmd_req, 3, ids))
    print(string.format("  submit(1,reqs,cmd,3,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Variation 6: Using a kqueue fd instead of ids array?
print("[Var 6] Try with read_fd as fd, not write_fd\n")
do
    local cmd_req = mem.alloc(0x40)
    mem.write_qword(cmd_req, 0)
    mem.write_qword(cmd_req+8, data)
    mem.write_qword(cmd_req+0x10, 64)
    mem.write_dword(cmd_req+0x18, rfd)  -- read_fd instead of write_fd
    mem.write_dword(cmd_req+0x1c, 4)    -- LIO_READ
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cmd_req)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  submit(LIO_READ) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

print("\n[+] Done")
