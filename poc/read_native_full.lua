-- Read more of native.lua and find RAX handling
print("=== Read native.lua full ===\n")

local f = io.open("/savedata0/native.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print(content)
end

return "done"
