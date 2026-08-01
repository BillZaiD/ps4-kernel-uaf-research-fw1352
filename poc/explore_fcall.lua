-- explore fcall and see how to call native functions
print("=== fcall table ===")
for k, v in pairs(fcall) do
    print("  " .. tostring(k) .. " = " .. type(v))
    if type(v) == "table" then
        for k2, v2 in pairs(v) do
            print("    " .. tostring(k2) .. " = " .. type(v2) .. " " .. tostring(v2))
        end
    end
end

print("\n=== native.fcall ===")
print("type: " .. type(native.fcall))
if type(native.fcall) == "table" then
    for k, v in pairs(native.fcall) do
        print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
    end
end

print("\n=== native.read_buffer ===")
print("type: " .. type(native.read_buffer))
if type(native.read_buffer) == "table" then
    for k, v in pairs(native.read_buffer) do
        print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
    end
else
    print(tostring(native.read_buffer))
end

print("\n=== syscall.sysctl structure ===")
if type(syscall.sysctl) == "table" then
    for k, v in pairs(syscall.sysctl) do
        if type(v) == "function" then
            print("  " .. tostring(k) .. " = function")
        elseif type(v) == "table" then
            print("  " .. tostring(k) .. " = table")
            for k2, v2 in pairs(v) do
                print("    " .. tostring(k2) .. " = " .. type(v2) .. " " .. tostring(v2))
            end
        else
            print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
        end
    end
end
