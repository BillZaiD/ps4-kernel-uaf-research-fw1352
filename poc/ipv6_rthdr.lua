--[[
    ipv6_rthdr.lua
    Test IPV6_RTHDR (51) and IPV6_PKTINFO (46) with correct PS4 option numbers
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

S.resolve({
    socket = 0x61, close = 6, setsockopt = 0x69,
    getsockopt = 0x76, bind = 0x68,
    getpid = 20,
})

print("[+] IPv6 RTHDR/PKTINFO Test\n")

-- Create IPv6 socket
local sd = tonn(S.socket(28, 2, 17))
print(string.format("socket(AF_INET6) = %d\n", sd))

-- Test IPV6_PKTINFO (opt=46)
print("[*] IPV6_PKTINFO (opt=46):\n")
do
    local pktinfo = mem.alloc(0x20)
    for i = 0, 0x1F do mem.write_byte(pktinfo+i, 0) end
    local r = tonn(S.setsockopt(sd, 41, 46, pktinfo, 0x20))
    print(string.format("  setsockopt(41, 46, struct, 0x20) = %d\n", r))
end

-- Test IPV6_RTHDR (opt=51)
print("[*] IPV6_RTHDR (opt=51):\n")
do
    -- Build a minimal routing header struct
    -- struct ip6_rthdr {
    --   uint8_t  ip6r_nxt;    // next header
    --   uint8_t  ip6r_len;    // length in 8-byte units (not incl this header)
    --   uint8_t  ip6r_type;   // routing type
    --   uint8_t  ip6r_segleft;// segments left
    -- };
    local rthdr = mem.alloc(0x40)
    for i = 0, 0x3F do mem.write_byte(rthdr+i, 0) end
    mem.write_byte(rthdr, 0)      -- next header (0 = hop-by-hop)
    mem.write_byte(rthdr+1, 0)    -- len
    mem.write_byte(rthdr+2, 0)    -- type 0
    mem.write_byte(rthdr+3, 0)    -- segleft
    
    local r = tonn(S.setsockopt(sd, 41, 51, rthdr, 0x40))
    print(string.format("  setsockopt(41, 51, rthdr, 0x40) = %d\n", r))
    
    if r ~= -1 then
        -- Try larger struct
        local rthdr2 = mem.alloc(0x100)
        for i = 0, 0xFF do mem.write_byte(rthdr2+i, 0) end
        r = tonn(S.setsockopt(sd, 41, 51, rthdr2, 0x100))
        print(string.format("  setsockopt(41, 51, rthdr, 0x100) = %d\n", r))
        
        -- Try with specific sizes
        for _, size in ipairs({8, 0x20, 0x40, 0x80, 0xC0}) do
            local buf = mem.alloc(size)
            for i = 0, size-1 do mem.write_byte(buf+i, 0x42) end
            r = tonn(S.setsockopt(sd, 41, 51, buf, size))
            print(string.format("  size=0x%x: r=%d", size, r))
        end
    end
end

-- Test IPV6 options 46-55 with struct
print("\n[*] Scanning options 46-55 with struct:\n")
for opt = 46, 55 do
    local buf = mem.alloc(0x40)
    for i = 0, 0x3F do mem.write_byte(buf+i, 0) end
    local r = tonn(S.setsockopt(sd, 41, opt, buf, 0x40))
    if r ~= -1 then
        print(string.format("  opt=%d size=0x40: r=%d [*** WORKS ***]", opt, r))
    end
end

-- Test getsockopt for the same range
print("\n[*] getsockopt scan 46-55:\n")
for opt = 46, 55 do
    local buf = mem.alloc(0x40)
    local size = mem.alloc(4)
    mem.write_dword(size, 0x40)
    local r = tonn(S.getsockopt(sd, 41, opt, buf, size))
    if r ~= -1 then
        print(string.format("  opt=%d: r=%d [*** WORKS ***]", opt, r))
    end
end

print("\n[+] Done")
