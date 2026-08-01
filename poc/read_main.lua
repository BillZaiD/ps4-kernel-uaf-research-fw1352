--[[
    read_main.lua
    Read main.lua header for exploit chain
]]
print("[+] Reading main.lua\n")

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

local lines = read_file_range("/savedata0/main.lua", 1, 300)
if lines then
    print(string.format("--- main.lua (%d lines) ---\n", #lines))
    for i, line in ipairs(lines) do
        print(line)
    end
else
    print("Failed to read\n")
end
