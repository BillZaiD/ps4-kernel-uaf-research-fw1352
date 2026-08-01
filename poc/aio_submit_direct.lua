--[[
    aio_submit_direct.lua  
    Test aio_submit_cmd with completely different struct layouts
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

print("[+] AIO Submit Direct\n")

-- Pipe
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

local buf = mem.alloc(64)
for i = 0, 63 do mem.write_byte(buf+i, 0x41+(i%26)) end

-- Hypothesis 1: First arg is DIRECT cmd_req struct, not pointer to ptr array
-- Layout: offset(8) + buf(8) + nbytes(8) + fd+dword + cmd+dword = 0x20 total
print("[H1] Direct struct layout\n")
do
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)          -- offset
    mem.write_qword(cr+8, buf)      -- buf
    mem.write_qword(cr+0x10, 64)    -- nbytes
    mem.write_dword(cr+0x18, p_wr)  -- fd
    mem.write_dword(cr+0x1c, 8)     -- cmd=LIO_WRITE
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    -- (cmd_req_struct, reqs_out, num, mode, ids)
    local r = tonn(S.aio_submit_cmd(cr, 0, 1, 3, ids))
    print(string.format("  cmd=cr, reqs=0, n=1, mode=3: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 2: Like H1 but second arg = buf for req IDs returned
do
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    
    local reqs_out = mem.alloc(8)
    mem.write_qword(reqs_out, 0)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(cr, reqs_out, 1, 3, ids))
    print(string.format("  cmd=cr, reqs=out, n=1: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 3: first arg = pointer to array of CR pointers, second = same
do
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  ptr_array, ptr_array, n=1: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 4: cmd struct at first arg is 0x40 bytes with more fields
print("[H4] 0x40 byte struct\n")
do
    local cr = mem.alloc(0x40)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    -- rest zeroed
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  0x40_struct: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 5: Different field order
print("[H5] fd first, then cmd, then rest\n")
do
    local cr = mem.alloc(0x20)
    mem.write_dword(cr, p_wr)       -- fd first
    mem.write_dword(cr+4, 8)         -- cmd
    mem.write_qword(cr+8, 0)         -- offset
    mem.write_qword(cr+0x10, buf)    -- buf
    mem.write_qword(cr+0x18, 64)     -- nbytes
    
    local reqs = mem.alloc(8)
    mem.write_qword(reqs, cr)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
    print(string.format("  fd_first: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 6: No pointer array, both first and second = direct struct
do
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(cr, cr, 1, 3, ids))
    print(string.format("  cr, cr, n=1: r=%d id=0x%x\n", r, tonn(mem.read_qword(ids))))
end

-- Hypothesis 7: mode = LIO_NOWAIT (0) instead of LIO_WAIT (3?)  
print("[H7] mode=0 (LIO_NOWAIT)\n")
do
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(cr, 0, 1, 0, ids))
    print(string.format("  cr,0,1,0,ids: r=%d\n", r))
end

-- Just see what happens if we call it with all buf pointers
print("[H8] Extra large struct\n")
do
    local cr = mem.alloc(0x100)
    for i = 0, 0xFF do mem.write_byte(cr+i, 0) end
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    
    local r = tonn(S.aio_submit_cmd(cr, 0, 1, 3, ids))
    print(string.format("  0x100_struct: r=%d\n", r))
end

print("\n[+] Done")
