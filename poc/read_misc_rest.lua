--[[
    read_misc_rest.lua
    Read lines 500-1000 of misc.lua
]]
print("[+] Reading misc.lua continuation\n")

local function read_file_range(path, start_line, count)
    local ok, fh = pcall(io.open, path, "r")
    if not ok or not fh then
        return nil, tostring(fh)
    end
    -- Skip to start_line
    for i = 1, start_line - 1 do
        fh:read("*l")
    end
    local lines = {}
    for i = 1, count do
        local line = fh:read("*l")
        if line == nil then break end
        lines[#lines + 1] = line
    end
    fh:close()
    return lines
end

local lines = read_file_range("/savedata0/misc.lua", 500, 500)
if lines then
    print(string.format("--- misc.lua lines 500-%d ---\n", 500 + #lines - 1))
    for i, line in ipairs(lines) do
        print(line)
    end
else
    print("Failed\n")
end
