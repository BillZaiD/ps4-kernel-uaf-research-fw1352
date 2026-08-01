--[[
    read_offset_rest.lua
    Read rest of kernel_offset.lua (PS4 offsets for 11.00+)
]]
print("[+] Reading kernel_offset.lua continuation\n")

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

local ko = read_file_range("/savedata0/kernel_offset.lua", 300, 300)
if ko then
    print(string.format("--- kernel_offset.lua lines 300-%d ---\n", 300 + #ko - 1))
    for i, line in ipairs(ko) do
        print(line)
    end
else
    print("No more lines\n")
end

-- Also check total line counts of key files
print("\n[*] File sizes:\n")
local files = {"/savedata0/main.lua", "/savedata0/misc.lua", "/savedata0/kernel.lua", 
               "/savedata0/kernel_offset.lua", "/savedata0/globals.lua", "/savedata0/offsets.lua"}
for _, f in ipairs(files) do
    local ok, fh = pcall(io.open, f, "r")
    if ok and fh then
        local count = 0
        while fh:read("*l") do count = count + 1 end
        fh:close()
        print(string.format("  %s: %d lines", f:match("([^/]+)$"), count))
    end
end
