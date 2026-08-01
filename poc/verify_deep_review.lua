--[[
    verify_deep_review.lua
    Systematic verification of DEEP_REVIEW.md claims on FW 13.52
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({close=6, getpid=20, open=5, pipe=42, kqueue=362, kevent=363, socket=97, connect=53, fcntl=92, ioctl=54, getsockopt=106, setsockopt=105, read=3, write=4, nanosleep=240, bind=104})

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

local function find_tramp(w)
    for i = 0, 35 do
        if mem.read_byte(w+i)==0x49 and mem.read_byte(w+i+1)==0x89 and mem.read_byte(w+i+2)==0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    local tramp
    if w == 0 then
        local gp = toaddr(S.syscall_wrapper[20])
        tramp = gp + find_tramp(gp)
    else
        tramp = w + find_tramp(w)
    end
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

local function hexdump(buf, n)
    local s = ""
    for i = 0, n-1 do
        s = s .. string.format("%02x ", tonn(mem.read_byte(buf + i)))
    end
    return s
end

print("[+] DEEP_REVIEW.md Verification - FW 13.52\n")

-- Test 1: fcntl claims
print("[1] fcntl claims\n")

-- F_GETLK (cmd=11) on pipe
local pipefds = mem.alloc(8)
fcall(42, pipefds, 0, 0, 0, 0, 0) -- pipe(pipefds)
local prd = tonn(mem.read_dword(pipefds))
local pwr = tonn(mem.read_dword(pipefds + 4))
print(string.format("  pipe rd=%d wr=%d", prd, pwr))

-- F_GETLK struct
local flock = mem.alloc(40)
local r_getlk = fcall(92, prd, 11, flock, 0, 0, 0)  -- fcntl(fd, F_GETLK, &flock)
print(string.format("  F_GETLK on pipe = %d (expect -1 = BLOCKED)", r_getlk))

-- F_GETFL (cmd=3)
local r_getfl = fcall(92, prd, 3, 0, 0, 0, 0)
print(string.format("  F_GETFL on pipe = %d (expect 2 = O_RDWR)", r_getfl))

-- F_SETOWN (cmd=6)
local r_setown = fcall(92, pwr, 6, 20, 0, 0, 0)
print(string.format("  F_SETOWN on pipe = %d (expect -1 = BLOCKED)", r_setown))

-- F_GETOWN (cmd=5)
local r_getown = fcall(92, pwr, 5, 0, 0, 0, 0)
print(string.format("  F_GETOWN on pipe = %d (expect 0 = no sigio)", r_getown))

-- Test 2: ioctl FIOASYNC claim
print("\n[2] ioctl FIOASYNC claim\n")
-- FIONBIO (0x8004667E)
local val = mem.alloc(4)
mem.write_dword(val, 1)
local r_fionbio = fcall(54, prd, 0x8004667E, val, 0, 0, 0)
print(string.format("  FIONBIO on pipe = %d (expect 0 = OK)", r_fionbio))

-- FIOCLEX (0x20006601)
local r_fioclex = fcall(54, prd, 0x20006601, 0, 0, 0, 0)
print(string.format("  FIOCLEX on pipe = %d (expect 0 = OK)", r_fioclex))

-- FIOASYNC (0x20006602)
local r_fioasync = fcall(54, prd, 0x20006602, 0, 0, 0, 0)
print(string.format("  FIOASYNC on pipe = %d (expect 0 = triggers fsetown)", r_fioasync))

-- F_GETOWN after FIOASYNC
local r_getown2 = fcall(92, prd, 5, 0, 0, 0, 0)
print(string.format("  F_GETOWN after FIOASYNC = %d (expect 0xFFFFFFFFFFFFFFFF = BLOCKED)", r_getown2))

-- F_SETFL + FASYNC
local r_setfl = fcall(92, prd, 4, 0x42, 0, 0, 0)  -- F_SETFL, O_RDWR|FASYNC
print(string.format("  F_SETFL(FASYNC) on pipe = %d", r_setfl))
local r_getfl2 = fcall(92, prd, 3, 0, 0, 0, 0)
print(string.format("  F_GETFL after = %d (expect 66=0x42)", r_getfl2))

local r_getown3 = fcall(92, prd, 5, 0, 0, 0, 0)
print(string.format("  F_GETOWN after FASYNC = %d (expect -1 = BLOCKED)", r_getown3))

-- Test 3: Socket getsockopt claims
print("\n[4] Getsockopt claims\n")
-- Create a socket
local sock = fcall(97, 2, 2, 0, 0, 0, 0)  -- socket(AF_INET=2, SOCK_DGRAM=2, 0)
print(string.format("  socket(AF_INET, DGRAM) = %d", sock))

local buf4 = mem.alloc(256)
for i = 0, 63 do mem.write_byte(buf4 + i, 0x41) end

-- Test SO_TYPE on DGRAM socket
local optlen = mem.alloc(4)
mem.write_dword(optlen, 4)
local r_sotype = fcall(106, sock, 0xFFFF, 3, buf4, optlen, 0)  -- getsockopt SOL_SOCKET, SO_TYPE
print(string.format("  getsockopt(SO_TYPE) = %d, buf[0..3]: %s", r_sotype, hexdump(buf4, 8)))

-- Test SO_RCVBUF
for i = 0, 63 do mem.write_byte(buf4 + i, 0x41) end
mem.write_dword(optlen, 4)
local r_rcvbuf = fcall(106, sock, 0xFFFF, 8, buf4, optlen, 0)
print(string.format("  getsockopt(SO_RCVBUF) = %d, buf[0..7]: %s", r_rcvbuf, hexdump(buf4, 8)))

-- Test SO_SNDBUF
for i = 0, 63 do mem.write_byte(buf4 + i, 0x41) end
mem.write_dword(optlen, 4)
local r_sndbuf = fcall(106, sock, 0xFFFF, 9, buf4, optlen, 0)
print(string.format("  getsockopt(SO_SNDBUF) = %d, buf[0..7]: %s", r_sndbuf, hexdump(buf4, 8)))

-- Test: bind() claim from DEEP_REVIEW (bind works on AF_INET DGRAM)
print("\n[5] bind claim\n")
local sin = mem.alloc(16)
mem.write_word(sin, 2)       -- sin_family = AF_INET
mem.write_word(sin + 2, 0)   -- sin_port (htons(0) = any)
for i = 4, 7 do mem.write_byte(sin + i, 0) end  -- sin_addr = INADDR_ANY
for i = 8, 15 do mem.write_byte(sin + i, 0) end -- padding
local r_bind = fcall(104, sock, sin, 16, 0, 0, 0)
print(string.format("  bind(AF_INET, INADDR_ANY, port=0) = %d", r_bind))

-- Test: sysarch claims
-- Test 9: getsockopt on actual TCP socket (fd=21 is our connection)
print("\n[7] getsockopt on live TCP socket (fd=21)\n")
local buf5 = mem.alloc(256)
for i = 0, 63 do mem.write_byte(buf5 + i, 0x41) end
mem.write_dword(optlen, 4)
local r_so_type21 = fcall(106, 21, 0xFFFF, 3, buf5, optlen, 0)
print(string.format("  getsockopt(fd=21, SO_TYPE) = %d, buf: %s", r_so_type21, hexdump(buf5, 8)))

for i = 0, 63 do mem.write_byte(buf5 + i, 0x41) end
mem.write_dword(optlen, 4)
local r_so_err21 = fcall(106, 21, 0xFFFF, 4, buf5, optlen, 0)
print(string.format("  getsockopt(fd=21, SO_ERROR) = %d, buf: %s", r_so_err21, hexdump(buf5, 8)))

-- socketpair claim (DEEP_REVIEW: AF_UNIX SOCK_STREAM works)
print("\n[8] socketpair claim\n")
local sp = mem.alloc(8)
local r_sp = fcall(135, 1, 1, 0, sp, 0, 0)  -- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, &fds)
print(string.format("  socketpair(AF_UNIX, STREAM) = %d", r_sp))
if r_sp == 0 then
    local sp0 = tonn(mem.read_dword(sp))
    local sp1 = tonn(mem.read_dword(sp + 4))
    print(string.format("    fds = {%d, %d}", sp0, sp1))
    fcall(6, sp0, 0, 0, 0, 0, 0)
    fcall(6, sp1, 0, 0, 0, 0, 0)
end

fcall(6, prd, 0, 0, 0, 0, 0)
fcall(6, pwr, 0, 0, 0, 0, 0)
fcall(6, sock, 0, 0, 0, 0, 0)

print("\n[+] Verification complete - game survived")
