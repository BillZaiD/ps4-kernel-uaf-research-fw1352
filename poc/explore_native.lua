-- explore native and syscall tables
print("=== native table ===")
for k, v in pairs(native) do
    print("native." .. tostring(k) .. " = " .. type(v))
end

print("\n=== syscall table ===")
for k, v in pairs(syscall) do
    print("syscall." .. tostring(k) .. " = " .. type(v))
end

print("\n=== native_cmd table ===")
for k, v in pairs(native_cmd) do
    print("native_cmd." .. tostring(k) .. " = " .. type(v))
end

print("\n=== native_cmd_handler ===")
print(type(native_cmd_handler))
