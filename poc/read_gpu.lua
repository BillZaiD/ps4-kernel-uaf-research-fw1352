--[[
    read_gpu.lua
    Read gpu.lua for physical memory access
]]
print("[+] Reading gpu.lua\n")

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

-- Read gpu.lua completely (I'll estimate ~300 lines)
local l = read_file_range("/savedata0/gpu.lua", 1, 400)
if l then
    print(string.format("--- gpu.lua (%d lines) ---\n", #l))
    for i, line in ipairs(l) do print(line) end
end
