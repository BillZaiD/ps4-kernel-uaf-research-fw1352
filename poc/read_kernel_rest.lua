--[[
    read_kernel_rest.lua
    Read kernel.lua continuation and kernel_offset.lua
]]
print("[+] Reading kernel.lua continuation and kernel_offset.lua\n")

local function read_file_range(path, start_line, count)
    local ok, fh = pcall(io.open, path, "r")
    if not ok or not fh then return nil end
    for i = 1, start_line - 1 do fh:read("*l") end
    local lines = {}
    for i = 1, count do
        local line = fh:read("*l")
        if line == nil then break end
        lines[#lines + 1] = line
    end
    fh:close()
    return lines
end

-- kernel.lua from line 300
local kl = read_file_range("/savedata0/kernel.lua", 300, 300)
if kl then
    print(string.format("--- kernel.lua lines 300-%d ---\n", 300 + #kl - 1))
    for i, line in ipairs(kl) do
        print(line)
    end
end

print("\n========================================\n")

-- kernel_offset.lua
local ko = read_file_range("/savedata0/kernel_offset.lua", 1, 300)
if ko then
    print(string.format("--- kernel_offset.lua (%d lines) ---\n", #ko))
    for i, line in ipairs(ko) do
        print(line)
    end
else
    print("kernel_offset.lua not found\n")
end
