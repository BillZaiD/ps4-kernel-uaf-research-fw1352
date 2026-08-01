--[[
    read_kernel_files.lua
    Read kernel.lua and kernel_offset.lua
]]
print("[+] Reading kernel files\n")

local function read_file_range(path, start_line, count)
    local ok, fh = pcall(io.open, path, "r")
    if not ok or not fh then return nil, tostring(fh) end
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

-- Try kernel.lua first
local kl = read_file_range("/savedata0/kernel.lua", 1, 300)
if kl then
    print(string.format("--- kernel.lua (%d lines) ---\n", #kl))
    for i, line in ipairs(kl) do
        print(line)
    end
else
    print("kernel.lua not found or error\n")
end
