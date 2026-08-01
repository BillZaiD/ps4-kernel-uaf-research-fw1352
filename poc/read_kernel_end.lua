-- Read end of kernel.lua
print("=== Read kernel.lua end ===\n")

local f = io.open("/savedata0/kernel.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print(content:sub(6000))
end

return "ok"
