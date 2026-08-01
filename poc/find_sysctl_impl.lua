-- Find sysctl implementation
print("=== Find sysctl code ===\n")

local f = io.open("/savedata0/misc.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    
    local start = content:find("sysctlbyname")
    if start then
        local snippet = content:sub(start, start + 500)
        print(snippet)
    end
    
    -- Also search for sysctl_raw
    local raw_start = content:find("sysctl_raw")
    if raw_start then
        local snippet = content:sub(raw_start, raw_start + 500)
        print("\n--- sysctl_raw ---")
        print(snippet)
    end
end

return "ok"
