-- enumerate all available globals
for k, v in pairs(_G) do
    print(tostring(k) .. ": " .. type(v))
end
