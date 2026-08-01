-- Read middle of kernel.lua for exploit primitives
print("=== Read kernel.lua middle ===\n")

local f = io.open("/savedata0/kernel.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    
    -- Print from char 2000 to 6000
    print(content:sub(2000, 6000))
end

return "ok"
