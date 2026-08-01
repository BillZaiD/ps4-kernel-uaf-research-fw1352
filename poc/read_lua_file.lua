--[[
    read_lua_file.lua
    Read lua.lua - the primitives setup file
]]
print("[+] Reading lua.lua\n")

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

local l = read_file_range("/savedata0/lua.lua", 1, 300)
if l then
    print(string.format("--- lua.lua (%d lines) ---\n", #l))
    for i, line in ipairs(l) do print(line) end
end
