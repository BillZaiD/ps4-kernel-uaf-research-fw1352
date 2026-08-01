-- Read ropchain.lua
print("=== Read ropchain.lua ===\n")

local f = io.open("/savedata0/ropchain.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print(content)
end

return "done"
