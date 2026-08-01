--[[
    aio_alternatives_v2.lua
    Find AIO read/write syscalls using S.resolve() only, no native trampoline
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

-- Resolve potential aio_read/write/fsync syscalls + needed helpers
S.resolve({
    aio_read = 272,      -- guess
    aio_write = 273,     -- guess
    aio_fsync = 274,     -- guess
    aio_mlock = 289,     -- guess
    aio_error = 290,     -- guess
    aio_return = 291,    -- guess
    aio_cancel = 292,    -- guess
    pipe = 42, close = 6, write = 4, read = 3,
    getpid = 20,
})

print("[+] AIO Alternatives v2\n")

-- Test each resolved syscall
local test_scnos = {
    {S.aio_read, "aio_read(272)"},
    {S.aio_write, "aio_write(273)"},
    {S.aio_fsync, "aio_fsync(274)"},
    {S.aio_mlock, "aio_mlock(289)"},
    {S.aio_error, "aio_error(290)"},
    {S.aio_return, "aio_return(291)"},
    {S.aio_cancel, "aio_cancel(292)"},
}

for _, t in ipairs(test_scnos) do
    local fn = t[1]
    local name = t[2]
    if fn ~= nil then
        local ok, r = pcall(function() return tonn(fn(0, 0, 0, 0, 0)) end)
        if ok then
            print(string.format("  %s = %d", name, r))
        else
            print(string.format("  %s = ERROR: %s", name, tostring(r)))
        end
    else
        print(string.format("  %s = NOT RESOLVED", name))
    end
end

-- Try aio_submit_cmd one more time with a completely different first arg
print("\n[*] aio_submit_cmd last attempts\n")
local buf = mem.alloc(64)
for i = 0, 63 do mem.write_byte(buf+i, 0x41+(i%26)) end

-- Create a pipe
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

-- Try 4 more hypotheses
do
    -- H9: Use kqueue as fd (not pipe)
    S.resolve({kqueue=362, kevent=363})
    local kq = tonn(S.kqueue())
    
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, kq)   -- kqueue as fd??
    mem.write_dword(cr+0x1c, 8)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(cr, 0, 1, 3, ids))
    print(string.format("  kqueue fd: r=%d\n", r))
end

do
    -- H10: Use read end of pipe with LIO_READ
    local cr = mem.alloc(0x20)
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_rd)
    mem.write_dword(cr+0x1c, 4)  -- LIO_READ
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(cr, 0, 1, 3, ids))
    print(string.format("  LIO_READ on pipe_rd: r=%d\n", r))
end

do
    -- H11: All args as pointers to structs
    local cr = mem.alloc(0x100)
    for i = 0, 0xFF do mem.write_byte(cr+i, 0) end
    mem.write_qword(cr, 0)
    mem.write_qword(cr+8, buf)
    mem.write_qword(cr+0x10, 64)
    mem.write_dword(cr+0x18, p_wr)
    mem.write_dword(cr+0x1c, 8)
    
    local ids = mem.alloc(8)
    mem.write_qword(ids, 0)
    local r = tonn(S.aio_submit_cmd(cr, cr, 1, 3, ids))
    print(string.format("  cr, cr: r=%d\n", r))
end

do
    -- H12: Completely zero struct, null args
    local r = tonn(S.aio_submit_cmd(0, 0, 0, 0, 0))
    print(string.format("  all zero: r=%d\n", r))
end

-- Test aio_multi_delete with various IDs to understand its behavior
print("\n[*] aio_multi_delete behavior\n")
do
    local ids = mem.alloc(8)
    local states = mem.alloc(4)
    
    for _, id in ipairs({0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0xDEAD, 0x1000, 0x41414141}) do
        mem.write_qword(ids, id)
        mem.write_dword(states, 0)
        local r = tonn(S.aio_multi_delete(ids, 1, states))
        local s = tonn(mem.read_dword(states))
        print(string.format("  delete id=0x%x: r=%d state=%d", id, r, s))
    end
end

print("\n[+] Done")
