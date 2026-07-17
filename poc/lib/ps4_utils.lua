--[[
    PS4 Kernel Research Utilities
    Shared helper library for kqueue UAF research
    
    Platform: PlayStation 4 FW 13.52
    Requires: Remote Lua Loader (n0llptr/remote_lua_loader)
--]]

local M = {}

-- Module references
M.mem = rawget(_G, "memory")
M.native = rawget(_G, "native")
M.syscall = rawget(_G, "syscall")
M.thread = rawget(_G, "thread")

-- Constants
M.EVFILT_READ   = 0xFFFF  -- -1 as uint16
M.EVFILT_WRITE  = 0xFFFE  -- -2 as uint16
M.EVFILT_USER   = 0xFFF9  -- -7 as uint16 (PS4-SPECIFIC!)
M.EV_ADD        = 0x0001
M.EV_DELETE     = 0x0002
M.EV_ENABLE     = 0x0004
M.EV_DISABLE    = 0x0008
M.EV_ONESHOT    = 0x0010
M.EV_CLEAR      = 0x0020
M.EV_EOF        = 0x8000
M.EVFILT_USER_CMD_DISABLE = 0x0001
M.EVFILT_USER_CMD_ENABLE  = 0x0002
M.EVFILT_USER_CMD_TRIGGER = 0x0004

-- Syscall numbers (PS4 FW 13.52)
M.SYS = {
    read = 3, write = 4, open = 5, close = 6,
    pipe = 42, ioctl = 54, mmap = 477, munmap = 73,
    sysctl = 202, kqueue = 362, kevent = 363,
    socket = 97, connect = 53, setsockopt = 105, getsockopt = 106,
    getpid = 20, nanosleep = 240,
}

--- Convert cdata/table value to Lua number
function M.tonum(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 0x100000000 + v.l end
    if type(v) == "number" then return v end
    return tonumber(tostring(v))
end

--- Convert to address (handling cdata uint64)
function M.toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 0x100000000 + v.l end
    if type(v) == "number" then return v end
    return tonumber(tostring(v))
end

--- Write null-terminated string to memory
function M.write_str(addr, s)
    for i = 1, #s do
        M.mem.write_byte(addr + i - 1, string.byte(s, i))
    end
    M.mem.write_byte(addr + #s, 0)
end

--- Create a kevent structure in memory
function M.mkkevent(filter, ident, flags, fflags, data, udata)
    local ev = M.mem.alloc(32)
    M.mem.write_qword(ev + 0, ident or 0)
    M.mem.write_word(ev + 8, filter)
    M.mem.write_word(ev + 10, flags or 0)
    M.mem.write_dword(ev + 12, fflags or 0)
    M.mem.write_qword(ev + 16, data or 0)
    M.mem.write_qword(ev + 24, udata or 0)
    return ev
end

--- Parse a kevent structure from memory
function M.parse_kevent(buf, index)
    local off = index * 32
    return {
        ident   = M.tonum(M.mem.read_qword(buf + off)),
        filter  = M.tonum(M.mem.read_word(buf + off + 8)),
        flags   = M.tonum(M.mem.read_word(buf + off + 10)),
        fflags  = M.tonum(M.mem.read_dword(buf + off + 12)),
        data    = M.tonum(M.mem.read_qword(buf + off + 16)),
        udata   = M.tonum(M.mem.read_qword(buf + off + 24)),
    }
end

--- Check if a value looks like a kernel pointer (>0xFFFF000000000000)
function M.is_kernel_ptr(val)
    return val > 0xFFFF000000000000
end

--- Scan a memory region for kernel pointers
function M.scan_kptrs(buf, len)
    local ptrs = {}
    for j = 0, len - 8, 8 do
        local qv = M.tonum(M.mem.read_qword(buf + j))
        if M.is_kernel_ptr(qv) then
            table.insert(ptrs, { offset = j, value = qv })
        end
    end
    return ptrs
end

--- Hex dump of memory region
function M.hexdump(buf, len)
    local hex = ""
    for j = 0, len - 1 do
        hex = hex .. string.format("%02x", M.tonum(M.mem.read_byte(buf + j)))
    end
    return hex
end

--- ASCII dump of memory region
function M.asciidump(buf, len)
    local s = ""
    for j = 0, len - 1 do
        local ch = M.tonum(M.mem.read_byte(buf + j))
        if ch >= 32 and ch < 127 then
            s = s .. string.char(ch)
        else
            s = s .. "."
        end
    end
    return s
end

--- Find the mov r10,rcx instruction in a syscall wrapper
function M.find_trampoline(wrapper_addr)
    local w = M.toaddr(wrapper_addr)
    for i = 0, 35 do
        if M.tonum(M.mem.read_byte(w + i))     == 0x49 and
           M.tonum(M.mem.read_byte(w + i + 1)) == 0x89 and
           M.tonum(M.mem.read_byte(w + i + 2)) == 0xCA then
            return i
        end
    end
    return 7  -- default
end

--- Call a syscall via the trampoline (for syscalls without direct wrappers)
function M.fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local wrappers = M.syscall.syscall_wrapper
    local w = M.toaddr(wrappers[scno])
    local jump
    if w ~= 0 then
        jump = w + M.find_trampoline(w)
    else
        -- Use getpid wrapper as universal trampoline
        local tramp_w = M.toaddr(wrappers[M.SYS.getpid])
        jump = tramp_w + M.find_trampoline(tramp_w)
    end
    return M.tonum(M.native.fcall_with_rax(
        jump, scno,
        rdi or 0, rsi or 0, rdx or 0,
        rcx or 0, r8 or 0, r9 or 0
    ))
end

--- Initialize required syscalls via S.resolve()
function M.resolve()
    M.syscall.resolve(M.SYS)
end

--- Print a banner
function M.banner(title)
    print(string.rep("=", 60))
    print("  " .. title)
    print("  PS4 FW 13.52 - kqueue UAF Research")
    print(string.rep("=", 60))
end

return M
