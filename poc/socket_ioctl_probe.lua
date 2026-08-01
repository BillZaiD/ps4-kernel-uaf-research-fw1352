--[[
    socket_ioctl_probe.lua
    Try raw socket ioctls for kernel data
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

S.resolve({
    socket = 97, getsockopt = 106, setsockopt = 105,
    ioctl = 54, close = 6, pipe = 42, write = 4, read = 3,
    kqueue = 362, kevent = 363
})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function is_kptr(v)
    return v > 0xFFFF000000000000
end

print("[+] Raw socket + ioctl probe\n")

-- Create raw socket
local sock = tonn(S.socket(2, 3, 0))  -- AF_INET=2, SOCK_RAW=3
print(string.format("[+] raw socket = %d", sock))

if sock < 0 then
    sock = tonn(S.socket(2, 2, 0))  -- SOCK_DGRAM=2
    print(string.format("[+] Trying DGRAM socket = %d", sock))
end

if sock >= 0 then
    local buf = mem.alloc(4096)
    for j = 0, 4095 do mem.write_byte(buf + j, 0xCC) end
    
    -- SIOCGIFCONF = 0xC00C6924 on FreeBSD
    local SIOCGIFCONF = 0xC00C6924
    local ifc_len = mem.alloc(4)
    mem.write_dword(ifc_len, 4096)
    
    local ifc_req = mem.alloc(4 + 4096)
    mem.write_dword(ifc_req + 0, 4096)  -- ifc_len
    mem.write_qword(ifc_req + 4, buf)   -- ifc_buf
    
    print("[*] Trying SIOCGIFCONF...")
    local r1 = tonn(S.ioctl(sock, SIOCGIFCONF, ifc_req))
    print(string.format("  ioctl(SIOCGIFCONF) = %d", r1))
    
    if r1 == 0 then
        local len = tonn(mem.read_dword(ifc_req))
        print(string.format("  Returned length: %d", len))
        if len > 0 and len < 4096 then
            for j = 0, len - 1, 8 do
                local v = tonn(mem.read_qword(buf + j))
                if is_kptr(v) then
                    print(string.format("  [!] KPTR at +0x%x: 0x%x", j, v))
                end
            end
            -- Print first 32 bytes of interface data
            local str = ""
            for j = 0, math.min(63, len-1) do
                local b = tonn(mem.read_byte(buf + j))
                if b >= 32 and b < 127 then
                    str = str .. string.char(b)
                end
            end
            if #str > 0 then
                print(string.format("  ASCII: %s", str))
            end
        end
    else
        -- Try more ioctls
        local ioctls = {
            {0x80004501, "SIOCGIFADDR"},
            {0x8000450F, "SIOCGIFNETMASK"},
            {0x80004510, "SIOCGIFBRDADDR"},
            {0x80004502, "SIOCGIFFLAGS"},
            {0x80006900, "SIOCGSCOPE6"},
        }
        for _, ioc in ipairs(ioctls) do
            for j = 0, 4095 do mem.write_byte(buf + j, 0) end
            local r = tonn(S.ioctl(sock, ioc[1], buf))
            if r == 0 then
                print(string.format("  [!] %s returned 0!", ioc[2]))
                local kptrs = 0
                for j = 0, 255, 8 do
                    local v = tonn(mem.read_qword(buf + j))
                    if is_kptr(v) then
                        kptrs = kptrs + 1
                        if kptrs <= 3 then
                            print(string.format("    KPTR at +0x%x: 0x%x", j, v))
                        end
                    end
                end
                if kptrs == 0 then
                    local h = ""
                    for jj = 0, 31 do
                        h = h .. string.format("%02x", tonn(mem.read_byte(buf + jj)))
                    end
                    print(string.format("    First 32 bytes: %s", h))
                end
            end
        end
    end
    
    -- Try getsockopt with various levels/options
    print("\n[*] Trying getsockopt on raw socket...\n")
    local levels = {
        {1, "SOL_SOCKET"},
        {0, "IPPROTO_IP"},
        {6, "IPPROTO_TCP"},
        {255, "unknown"},
    }
    local opts = {
        {4, "SO_LINGER"},     {7, "SO_SNDBUF"},
        {8, "SO_RCVBUF"},    {15, "SO_PEERCRED"},
        {27, "SO_TIMESTAMP"}, {35, "SO_BINTIME"},
        {37, "SO_TS_CLOCK"}, 
    }
    
    for _, lv in ipairs(levels) do
        for _, op in ipairs(opts) do
            for j = 0, 255 do mem.write_byte(buf + j, 0) end
            local optlen = mem.alloc(4)
            mem.write_dword(optlen, 256)
            local r = tonn(S.getsockopt(sock, lv[1], op[1], buf, optlen))
            if r == 0 then
                local len = tonn(mem.read_dword(optlen))
                if len > 0 and len <= 256 then
                    local kptrs = 0
                    for j = 0, len - 1, 8 do
                        local v = tonn(mem.read_qword(buf + j))
                        if is_kptr(v) then
                            kptrs = kptrs + 1
                            if kptrs <= 3 then
                                print(string.format("  [!] %s/%s KPTR: 0x%x", lv[2], op[2], v))
                            end
                        end
                    end
                    if kptrs == 0 and len > 4 then
                        local firstq = tonn(mem.read_qword(buf))
                        print(string.format("  %s/%s: ret=0 len=%d first=0x%x", lv[2], op[2], len, firstq))
                    end
                end
            end
        end
    end
    
    S.close(sock)
end

-- Try /dev/dri devices
print("\n[*] Trying /dev/dri devices...\n")
for _, dev in ipairs({"dri/card0", "dri/control64", "dri/renderD128"}) do
    local path = mem.alloc(64)
    for j = 1, #dev do
        mem.write_byte(path + j - 1, string.byte(dev, j))
    end
    mem.write_byte(path + #dev, 0)
    local fd = tonn(S.open(path, 2, 0))  -- O_RDWR=2
    if fd >= 0 then
        print(string.format("  [+] /dev/%s opened: fd=%d", dev, fd))
        local buf2 = mem.alloc(4096)
        local r = tonn(S.ioctl(fd, 0xC0106409, buf2))  -- DRM_IOCTL_VERSION
        if r == 0 then
            print("  [!] DRM_IOCTL_VERSION works!")
            for j = 0, 255, 8 do
                local v = tonn(mem.read_qword(buf2 + j))
                if is_kptr(v) then
                    print(string.format("    KPTR at +0x%x: 0x%x", j, v))
                end
            end
        end
        S.close(fd)
    else
        local dev2 = "/dev/" .. dev
        local path2 = mem.alloc(64)
        for j = 1, #dev2 do
            mem.write_byte(path2 + j - 1, string.byte(dev2, j))
        end
        mem.write_byte(path2 + #dev2, 0)
        local fd2 = tonn(S.open(path2, 2, 0))
        if fd2 >= 0 then
            print(string.format("  [+] (alt) /%s opened: fd=%d", dev2, fd2))
            S.close(fd2)
        end
    end
end

print("\n[+] Done")
