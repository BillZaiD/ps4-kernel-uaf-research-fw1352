-- explore lua table
print("=== lua table ===")
for k, v in pairs(lua) do
    print("lua." .. tostring(k) .. " = " .. type(v))
end

print("\n=== str_hacky_list ===")
for i, v in ipairs(str_hacky_list) do
    print("str_hacky_list[" .. i .. "] = " .. tostring(v))
end

print("\n=== FW_VERSION ===")
print(FW_VERSION)
print("\n=== PLATFORM ===")
print(PLATFORM)
