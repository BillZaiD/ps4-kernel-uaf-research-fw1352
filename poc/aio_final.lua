--[[
    aio_final_test.lua
    Final AIO tests + aio_multi_delete deep probe
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

S.resolve({
    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_poll = 0x298,
    aio_multi_cancel = 0x29a,
    aio_submit_cmd = 0x29d,
    pipe = 42, close = 6, write = 4, read = 3,
    getpid = 20,
})

-- Verify S.aio_submit_cmd exists
print(string.format("[*] aio_submit_cmd resolved = %s\n", tostring(S.aio_submit_cmd)))

-- Last try: exact lapse.lua struct
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe: rd=%d wr=%d\n", p_rd, p_wr))

local data = mem.alloc(64)
for i = 0, 63 do mem.write_byte(data+i, i) end

-- EXACT lapse.lua struct (cmd_req = 0x40 bytes)
local cmd_req = mem.alloc(0x40)
mem.write_qword(cmd_req, 0)         -- lio_offset
mem.write_qword(cmd_req + 8, data)   -- lio_buf
mem.write_qword(cmd_req + 0x10, 64)  -- lio_nbytes
mem.write_dword(cmd_req + 0x18, p_wr) -- lio_fd
mem.write_dword(cmd_req + 0x1c, 8)   -- lio_cmd = LIO_WRITE

-- reqs = array of pointers to cmd_reqs
local reqs = mem.alloc(8)
mem.write_qword(reqs, cmd_req)
local ids = mem.alloc(8)
mem.write_qword(ids, 0)

-- Call EXACTLY like lapse.lua: aio_submit_cmd(cmd, reqs, num_reqs, 3, ids)
-- Where cmd=reqs (same pointer)
print("[*] Exact lapse.lua call\n")
local r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 3, ids))
print(string.format("  aio_submit_cmd(reqs,reqs,1,3,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids))))

-- Try with mode=1 (LIO_WAIT) too
if r == -1 then
    local ids2 = mem.alloc(8)
    mem.write_qword(ids2, 0)
    r = tonn(S.aio_submit_cmd(reqs, reqs, 1, 1, ids2))
    print(string.format("  aio_submit_cmd(reqs,reqs,1,1,ids) = %d  id=0x%x\n", r, tonn(mem.read_qword(ids2))))
end

-- Deep aio_multi_delete probe
print("\n[*] Deep aio_multi_delete probe\n")

-- Single IDs
local ids_buf = mem.alloc(8)
local states = mem.alloc(4)
for _, id_val in ipairs({0, 1, 2, 0x100, 0x1000, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF, 0xDEADBEEF}) do
    mem.write_qword(ids_buf, id_val)
    mem.write_dword(states, 0)
    local r = tonn(S.aio_multi_delete(ids_buf, 1, states))
    print(string.format("  delete(id=0x%x, 1) = %d", id_val, r))
end

-- Multiple IDs
print("\n[*] Multiple IDs\n")
local multi_ids = mem.alloc(32)  -- 4 * 8 bytes
for i = 0, 3 do
    mem.write_qword(multi_ids + i*8, 0)
end
local r = tonn(S.aio_multi_delete(multi_ids, 4, states))
print(string.format("  delete(4x zero) = %d\n", r))

-- Thread race test (aio_multi_delete from single thread, sequential)
print("[*] Sequential double-delete same ID\n")
mem.write_qword(ids_buf, 0x100)
r = tonn(S.aio_multi_delete(ids_buf, 1, states))
print(string.format("  first delete = %d", r))
r = tonn(S.aio_multi_delete(ids_buf, 1, states))
print(string.format("  second delete = %d", r))

-- aio_multi_wait with various args
print("\n[*] aio_multi_wait behavior\n")
mem.write_qword(ids_buf, 0)
r = tonn(S.aio_multi_wait(ids_buf, 1, states, 0, 0))
print(string.format("  wait(zero,1,buf,0,0) = %d", r))

-- Try different numbers
mem.write_qword(ids_buf, 0)
r = tonn(S.aio_multi_wait(ids_buf, 0, states, 0, 0))
print(string.format("  wait(buf,0,buf,0,0) = %d", r))

-- aio_multi_poll
r = tonn(S.aio_multi_poll(ids_buf, 1, states))
print(string.format("  poll(buf,1,buf) = %d", r))

-- aio_multi_cancel
r = tonn(S.aio_multi_cancel(ids_buf, 1, states))
print(string.format("  cancel(buf,1,buf) = %d", r))

print("\n[+] Final AIO test complete")
