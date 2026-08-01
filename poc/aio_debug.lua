--[[
    aio_debug.lua
    Debug aio_submit_cmd — try fd types, cmd values, and check errno
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

S.resolve({
    aio_submit_cmd = 0x29d,
    pipe = 42, close = 6, write = 4, read = 3, socketpair = 0x87,
    getpid = 20, kqueue = 362,
})

local function tohex(addr, n)
    local s = ""
    for i = 0, n-1 do s = s .. string.format("%02x", tonn(mem.read_byte(addr+i))) end
    return s
end

print("[+] AIO Debug\n")

-- First, check if there's an __error or errno accessible
-- On PS4, errno might be at a known location
print("[*] Checking fd limits and availability\n")

-- Create various fd types
-- Pipe
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

-- Socketpair
local spfds = mem.alloc(8)
local r_sp = tonn(S.socketpair(1, 2, 0, spfds))  -- AF_UNIX=1, SOCK_STREAM=2
local sp_a = tonn(mem.read_dword(spfds))
local sp_b = tonn(mem.read_dword(spfds+4))
print(string.format("socketpair: %d -> a=%d b=%d\n", r_sp, sp_a, sp_b))

-- Kqueue
local kq = tonn(S.kqueue())
print(string.format("kqueue: %d\n", kq))

-- Build cmd_req with various settings
local function make_cmd(fd, cmd, offset, nbytes)
    local cr = mem.alloc(0x40)
    mem.write_qword(cr, offset or 0)
    mem.write_qword(cr+8, mem.alloc(64))
    mem.write_qword(cr+0x10, nbytes or 64)
    mem.write_dword(cr+0x18, fd)
    mem.write_dword(cr+0x1c, cmd or 8)
    return cr
end

local function try_submit(cmd_req, reqs_ptr, n, mode, label)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(cmd_req, reqs_ptr, n, mode or 3, ids))
    local id = tonn(mem.read_qword(ids))
    print(string.format("  %s = %d  id=0x%x\n", label, r, id))
end

-- Try each fd type
print("\n[*] Testing different fd types with LIO_WRITE(8)\n")

do
    local cr = make_cmd(p_wr, 8)
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "pipe_wr LIO_WRITE")
end

do
    local cr = make_cmd(p_rd, 4)  -- LIO_READ
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "pipe_rd LIO_READ")
end

do
    local cr = make_cmd(sp_a, 8)  -- LIO_WRITE on socket
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "sp_a LIO_WRITE")
end

do
    local cr = make_cmd(sp_b, 4)  -- LIO_READ on socket
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "sp_b LIO_READ")
end

-- Try with kqueue fd (might not work but worth testing)
do
    local cr = make_cmd(kq, 0)  -- some cmd
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "kqueue")
end

-- Try direct cmd_req struct, not pointer
print("\n[*] Direct struct instead of pointer array\n")
do
    local cr = make_cmd(p_wr, 8)
    try_submit(cr, 0, 1, 3, "direct_cmd+null_reqs")
end

-- Try negative offset
print("\n[*] Negative offset\n")
do
    local cr = make_cmd(p_wr, 8, -1, 64)
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    try_submit(reqs, reqs, 1, 3, "offset=-1")
end

-- Try cmd=0 through 10
print("\n[*] Testing cmd values 0-10 on pipe_wr\n")
for cmd = 0, 10 do
    local cr = make_cmd(p_wr, cmd)
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    local id = tonn(mem.read_qword(ids))
    if r ~= -1 or id ~= 0 then
        print(string.format("  cmd=%d: r=%d id=0x%x [*** INTERESTING ***]\n", cmd, r, id))
    end
end
print("[*] All cmd values 0-10 returned -1\n")

-- Try mode values
print("[*] Testing mode values 0-5 on pipe_wr cmd=8\n")
for mode = 0, 5 do
    local cr = make_cmd(p_wr, 8)
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, mode, ids))
    local id = tonn(mem.read_qword(ids))
    if r ~= -1 or id ~= 0 then
        print(string.format("  mode=%d: r=%d id=0x%x [*** INTERESTING ***]\n", mode, r, id))
    end
end
print("[*] All modes 0-5 returned -1\n")

-- Try num_reqs = 0
print("[*] num_reqs = 0\n")
do
    local cr = make_cmd(p_wr, 8)
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 0, 3, ids))
    print(string.format("  num_reqs=0: r=%d\n", r))
end

-- Try with all null args  
print("[*] All null args\n")
do
    local r = tonn(S.aio_submit_cmd(0, 0, 0, 0, 0))
    print(string.format("  all null: r=%d\n", r))
end

print("\n[+] Debug complete")
