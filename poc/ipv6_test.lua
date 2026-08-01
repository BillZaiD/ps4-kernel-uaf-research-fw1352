--[[
    ipv6_test.lua
    Test IPv6 socket creation and setsockopt IPV6_PKTOPTS
    Key primitive for lapse.lua's spray/aliasing technique
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

print("[+] IPv6 + PKTOPTS Test\n")

-- AF_INET6 = 28, SOCK_DGRAM = 2, IPPROTO_UDP = 17
local sd = tonn(S.socket(28, 2, 17))
print(string.format("socket(AF_INET6, DGRAM, UDP) = %d\n", sd))

if sd < 0 then
    print("[-] IPv6 socket failed\n")
    -- Try AF_INET
    local sd4 = tonn(S.socket(2, 2, 0))
    print(string.format("socket(AF_INET, DGRAM, 0) = %d\n", sd4))
    
    -- Try setsockopt on AF_INET
    if sd4 >= 0 then
        print("[*] Testing setsockopt on AF_INET socket\n")
        local optval = mem.alloc(4)
        mem.write_dword(optval, 1)
        -- SOL_SOCKET=0xFFFF, SO_REUSEADDR=4
        local r = tonn(S.setsockopt(sd4, 0xFFFF, 4, optval, 4))
        print(string.format("setsockopt(SO_REUSEADDR) = %d\n", r))
    end
else
    -- IPv6 socket created! Try setsockopt with IPV6_PKTOPTS
    print("[+] IPv6 socket created!\n")
    
    -- Test various setsockopt options
    local optval = mem.alloc(4)
    mem.write_dword(optval, 1)
    
    -- IPPROTO_IPV6 = 41
    -- IPV6_PKTOPTS = 71 (or 57 on some systems)
    local ipv6_opts = {1, 57, 71, 0x1001, 0x1002, 0x1007}
    for _, opt in ipairs(ipv6_opts) do
        mem.write_dword(optval, 0x41414141)
        local r = tonn(S.setsockopt(sd, 41, opt, optval, 4))
        print(string.format("setsockopt(IPV6, %d, val, 4) = %d", opt, r))
    end
    
    -- Try with larger optval (like a pktopts struct)
    print("\n[*] Testing with larger optval (like PKTOPTS struct)...\n")
    local pktopts = mem.alloc(0x100)
    for i = 0, 0xFF do mem.write_byte(pktopts+i, 0x41 + (i%26)) end
    
    for _, opt in ipairs({57, 71, 0x1007}) do
        local r = tonn(S.setsockopt(sd, 41, opt, pktopts, 0x100))
        print(string.format("setsockopt(IPV6, %d, struct, 0x100) = %d", opt, r))
    end
    
    -- Try bind
    print("\n[*] Testing bind on IPv6 socket...\n")
    local sa = mem.alloc(28)  -- sockaddr_in6
    for i = 0, 27 do mem.write_byte(sa+i, 0) end
    mem.write_word(sa, 28)     -- sin6_len
    mem.write_byte(sa+1, 28)   -- AF_INET6
    local r_bind = tonn(S.bind(sd, sa, 28))
    print(string.format("bind(IN6ADDR_ANY) = %d\n", r_bind))
    
    -- Try getsockopt
    local val_out = mem.alloc(4)
    local size = mem.alloc(4)
    mem.write_dword(size, 4)
    local r_get = tonn(S.getsockopt(sd, 41, 57, val_out, size))
    print(string.format("getsockopt(IPV6, 57) = %d\n", r_get))
end

print("\n[+] Done")
