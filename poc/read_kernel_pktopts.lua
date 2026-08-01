-- Read kernel.lua to check pktopts exploit
print("=== Read kernel.lua (pktopts section) ===\n")

local f = io.open("/savedata0/kernel.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    
    -- Search for pktopts-related code
    local start = content:find("pktopts")
    if start then
        local pre = content:sub(math.max(1, start - 100), math.min(#content, start + 1500))
        print("--- pktopts exploit section ---")
        print(pre)
    end
    
    -- Also search for IPv6
    local ipv6_start = content:find("IPv6")
    if ipv6_start then
        local pre = content:sub(math.max(1, ipv6_start - 100), math.min(#content, ipv6_start + 1500))
        print("\n--- IPv6 exploit section ---")
        print(pre)
    end
    
    -- Get architecture: check for version checks
    local ver_start = content:find("9[.][0-9][0-9]")
    if ver_start then
        local pre = content:sub(math.max(1, ver_start - 200), math.min(#content, ver_start + 200))
        print("\n--- Version check section ---")
        print(pre)
    end
    
    print(string.format("\nTotal file size: %d bytes", #content))
else
    print("Cannot open kernel.lua")
end

return "ok"
