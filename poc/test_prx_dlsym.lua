-- test dynlib_load_prx 
-- Try to load a PRX from a known path
print("Testing dynlib_load_prx...")

-- syscall 594 = dynlib_load_prx
local wrapper594 = syscall.syscall_wrapper[594]
if wrapper594 then
    -- dynlib_load_prx(const char *name, uint64_t *handle, uint64_t flags)
    -- Try with different paths
    local paths = {
        "/system/common/libkernel.sprx",
        "/system/common/libSceLibcInternal.sprx",
        "/app0/eboot.bin",
    }
    for _, path in ipairs(paths) do
        local ok, ret = pcall(native.fcall, wrapper594, path, 0, 0)
        print("load " .. path .. ": " .. tostring(ok) .. " " .. tostring(ret))
    end
end

-- Also try dlsym to see if it still fails
print("\nTesting dlsym (syscall 591)...")
local wrapper591 = syscall.syscall_wrapper[591]
if wrapper591 then
    local ok, ret = pcall(native.fcall, wrapper591, "system_libkernel_shared", "sysctlbyname", 0, 0)
    print("dlsym: " .. tostring(ok) .. " " .. tostring(ret))
end
