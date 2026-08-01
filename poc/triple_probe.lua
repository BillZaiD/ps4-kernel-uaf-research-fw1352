--[[
    triple_probe.lua
    Test 3 HIGH-priority paths from exploit-dev:
    1. /proc filesystem
    2. Sony syscall 452 (sbl_map_self) with proper args
    3. Socket getsockopt with unexpected options
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({
    kqueue = 362, kevent = 363, close = 6,
    open = 5, read = 3, write = 4,
    socket = 97, getsockopt = 106,
})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function is_kptr(v)
    return v > 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

-- Syscall trampoline helpers
local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

local function find_trampoline(w, limit)
    limit = limit or 35
    for i = 0, limit do
        local b1 = mem.read_byte(w + i)
        local b2 = mem.read_byte(w + i + 1)
        local b3 = mem.read_byte(w + i + 2)
        if b1 == 0x49 and b2 == 0x89 and b3 == 0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(S.syscall_wrapper[scno])
    if w == 0 then
        return nil, "no wrapper"
    end
    local tramp = w + find_trampoline(w)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

print("[+] Triple Probe\n")

--==========================================
-- TEST 1: /proc filesystem
--==========================================
print("[*] Test 1: /proc filesystem\n")

local proc_paths = {
    "/proc/curproc/map",
    "/proc/curproc/status",
    "/proc/0/map",
    "/proc/1/map",
    "/proc/self/map",
    "/proc/stat",
    "/proc/meminfo",
    "/proc/cpuinfo",
}

for _, path in ipairs(proc_paths) do
    local pb = mem.alloc(64)
    for j = 1, #path do
        mem.write_byte(pb + j - 1, string.byte(string.sub(path, j, j)))
    end
    mem.write_byte(pb + #path, 0)
    
    local fd = tonn(S.open(pb, 0, 0))  -- O_RDONLY
    if fd >= 0 then
        local buf = mem.alloc(4096)
        local r = tonn(S.read(fd, buf, 4096))
        print(string.format("  %s: fd=%d read=%d", path, fd, r))
        if r > 0 then
            local str = ""
            for j = 0, math.min(r-1, 255) do
                local b = tonn(mem.read_byte(buf + j))
                if b >= 32 and b < 127 then
                    str = str .. string.char(b)
                end
            end
            if #str > 0 then
                print(string.format("  Content: %s", str))
            end
        end
    end
end

--==========================================
-- TEST 2: Sony syscall 452 (sbl_map_self)
--==========================================
print("\n[*] Test 2: Sony syscall 452 with proper args\n")

-- Try with fd=0 (stdin)
local info = mem.alloc(0x100)

-- First try: just fd=0
local r, err = fcall(452, 0, 0, 0, 0, 0, 0)
print(string.format("  sc452(0,0,0,0,0,0) = %s", tostring(r)))

-- With info struct: sbl_map_self(fd, &info, size)
mem.write_dword(info + 0, 1)
mem.write_dword(info + 4, 0)
mem.write_qword(info + 8, 0)
mem.write_qword(info + 16, 0)
r = fcall(452, 0, info, 0x18, 0, 0, 0)
print(string.format("  sc452(0, info, 0x18) = %s", tostring(r)))

-- With different fds
for fd_test = 0, 5 do
    r = fcall(452, fd_test, info, 0x18, 0, 0, 0)
    print(string.format("  sc452(fd=%d, info,0x18): %s", fd_test, tostring(r)))
end

-- sc454 (sbl_get_self_auth_info)
r = fcall(454, 0, 0, 0, 0, 0, 0)
print(string.format("  sc454(0,0,0,0,0,0) = %s", tostring(r)))

r = fcall(454, info, 0x18, 0, 0, 0, 0)
print(string.format("  sc454(info,0x18) = %s", tostring(r)))

-- sc460 (sbl_key_bag)
r = fcall(460, 0, 0, 0, 0, 0, 0)
print(string.format("  sc460 = %s", tostring(r)))

-- sc530-535
for sc = 530, 535 do
    r = fcall(sc, info, 0x100, 0, 0, 0, 0)
    print(string.format("  sc%d(info,0x100): %s", sc, tostring(r)))
end

--==========================================
-- TEST 3: Socket option scanning
--==========================================
print("\n[*] Test 3: Socket option probing\n")

local sock = tonn(S.socket(2, 2, 0))  -- AF_INET, SOCK_DGRAM
print(string.format("  socket(fd=%d)\n", sock))

if sock >= 0 then
    local val = mem.alloc(256)
    local len = mem.alloc(8)
    
    for opt = 0, 50 do
        mem.write_qword(len, 256)
        local r = tonn(S.getsockopt(sock, 1, opt, val, len))  -- SOL_SOCKET=1
        if r == 0 then
            local v = tonn(mem.read_qword(val))
            local l = tonn(mem.read_qword(len))
            if is_kptr(v) then
                print(string.format("  [!] KPTR: SOL_SOCKET opt=%d val=0x%x len=%d", opt, v, l))
            elseif v ~= 0 then
                print(string.format("  SOL_SOCKET opt=%d val=0x%x len=%d", opt, v, l))
            end
        end
    end
    
    -- Try non-standard levels (IPPROTO_IP=0, IPPROTO_TCP=6, etc.)
    for _, lv in ipairs({0, 2, 6, 41, 132, 136, 255}) do
        for opt = 0, 20 do
            mem.write_qword(len, 256)
            local r = tonn(S.getsockopt(sock, lv, opt, val, len))
            if r == 0 then
                local v = tonn(mem.read_qword(val))
                if is_kptr(v) then
                    print(string.format("  [!] KPTR: level=%d opt=%d val=0x%x", lv, opt, v))
                elseif v ~= 0 then
                    print(string.format("  level=%d opt=%d val=0x%x", lv, opt, v))
                end
            end
        end
    end
    
    S.close(sock)
end

print("\n[+] All done")
