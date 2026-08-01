-- Read native.lua source
print("=== Read native.lua ===\n")

local f = io.open("/savedata0/native.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print(string.format("File size: %d bytes\n", #content))
    
    -- Search for fcall_with_rax definition
    local start = content:find("fcall_with_rax")
    if start then
        local snippet = content:sub(start, start + 800)
        print("--- fcall_with_rax implementation ---")
        print(snippet)
    else
        print("fcall_with_rax not found in native.lua!")
    end
    
    -- Also look for fcall function
    local fstart = content:find("function fcall")
    if not fstart then
        fstart = content:find("fcall =")
    end
    if fstart then
        local snippet = content:sub(fstart, fstart + 500)
        print("\n--- fcall implementation ---")
        print(snippet)
    end
else
    print("Cannot open /savedata0/native.lua")
    -- Try alternative paths
    local alt_paths = {"/savedata0/native.lua", "/app0/native.lua"}
    for _, p in ipairs(alt_paths) do
        local f2 = io.open(p, "r")
        if f2 then
            print(string.format("Found at: %s", p))
            f2:close()
        end
    end
end

return "done"
