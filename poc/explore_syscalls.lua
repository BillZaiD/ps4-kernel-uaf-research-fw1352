-- explore syscall tables deeply
print("=== syscall.syscall_wrapper ===")
for k, v in pairs(syscall.syscall_wrapper) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.mprotect ===")
for k, v in pairs(syscall.mprotect) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.is_in_sandbox ===")
for k, v in pairs(syscall.is_in_sandbox) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.dlsym ===")
for k, v in pairs(syscall.dlsym) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.sysctl ===")
for k, v in pairs(syscall.sysctl) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.mmap ===")
for k, v in pairs(syscall.mmap) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.dynlib_load_prx ===")
for k, v in pairs(syscall.dynlib_load_prx) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.dynlib_unload_prx ===")
for k, v in pairs(syscall.dynlib_unload_prx) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.netgetiflist ===")
for k, v in pairs(syscall.netgetiflist) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end

print("\n=== syscall.getsockopt ===")
for k, v in pairs(syscall.getsockopt) do
    print("  " .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
end
