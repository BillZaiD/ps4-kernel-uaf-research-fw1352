--[[
    ipv6_spray.lua
    Find setsockopt option that allocates kernel memory (PKTOPTS spray)
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
    bind = 0x68, getsockopt = 0x76,
    getpid = 20,
})

print("[+] IPv6 Spray Test\n")

-- Create multiple IPv6 sockets
local sds = {}
for i = 1, 10 do
    local sd = tonn(S.socket(28, 2, 17))
    if sd >= 0 then
        sds[#sds+1] = sd
    end
end
print(string.format("Created %d IPv6 sockets\n", #sds))

if #sds == 0 then
    print("[-] No IPv6 sockets\n")
    return
end

-- Test various optnames with different sizes
-- IPV6 options on FreeBSD/PS4:
-- IPV6_PKTOPTS = 57 (some systems), IPV6_RTHDR = ?
-- Also try: 56 (IPV6_NEXTHOP), 59 (IPV6_RECVPKTINFO), etc.

local test_opts = {56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71}
local test_sizes = {4, 8, 0x20, 0x40, 0x80, 0x100}

for _, opt in ipairs(test_opts) do
    for _, size in ipairs(test_sizes) do
        local optval = mem.alloc(size)
        for i = 0, size-1 do mem.write_byte(optval+i, 0x41 + (i%26)) end
        
        local r = tonn(S.setsockopt(sds[1], 41, opt, optval, size))
        if r ~= -1 then
            print(string.format("  setsockopt(41, %d, size=0x%x) = %d [*** WORKS ***]", opt, size, r))
        end
    end
end

-- Also try different IPPROTO_* levels
print("\n[*] Trying different levels with opt=57\n")
for level = 0, 50 do
    local optval = mem.alloc(0x80)
    for i = 0, 0x7F do mem.write_byte(optval+i, 0x42) end
    local r = tonn(S.setsockopt(sds[1], level, 57, optval, 0x80))
    if r ~= -1 then
        print(string.format("  level=%d opt=57 size=0x80: r=%d [*** WORKS ***]", level, r))
    end
end

-- Test if we can bind + connect IPv6
print("\n[*] Testing IPv6 connect\n")
local sdo = sds[#sds]
local sa = mem.alloc(28)
for i = 0, 27 do mem.write_byte(sa+i, 0) end
mem.write_word(sa, 28)
mem.write_byte(sa+1, 28)  -- AF_INET6
mem.write_word(sa+2, 0x1234)  -- port

-- Try connect (sending data not possible but let's see)
S.resolve({connect = 0x62})
local r_con = tonn(S.connect(sdo, sa, 28))
print(string.format("connect(loopback) = %d\n", r_con))

print("\n[+] Done")
