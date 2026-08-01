-- Read memory.lua from PS4
print("=== memory.lua ===\n")
local ok, f = pcall(io.open, "/savedata0/memory.lua", "r")
if ok and f then
    local c = f:read("*all")
    f:close()
    print(c)
else
    print("NOT FOUND")
end

print("\nDone!")
