-- Read full kernel.lua in chunks
print("=== Read kernel.lua start ===\n")

local f = io.open("/savedata0/kernel.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    
    -- First 2000 chars
    print(content:sub(1, 2000))
end

return "ok"
