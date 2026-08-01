-- Find libkernel.sprx on filesystem and read kernel.lua fully
print("=== Find libkernel and read kernel exploit code ===\n")

local function read_file(path)
    local ok, f = pcall(io.open, path, "r")
    if ok and f then
        local content = f:read("*all")
        f:close()
        return content
    end
    return nil
end

-- Search for libkernel paths
local paths = {
    "/system/common/lib/libkernel.sprx",
    "/system/lib/libkernel.sprx",
    "/lib/libkernel.sprx",
    "/system/common/lib/libkernel.so",
    "/system/common/lib/libSceLibkernelInternal.sprx",
    "/system/common/lib/libkernel.sel",
    "/savedata0/libkernel.sprx",
    "/savedata0/libkernel.bin",
    "/system/common/module/libkernel.sprx",
    "/system/module/libkernel.sprx",
}

-- Use file_exists to check
print("--- Searching for libkernel ---")
for _, p in ipairs(paths) do
    local exists = file_exists(p)
    print(string.format("  %s: %s", p, tostring(exists)))
end

-- Read kernel.lua fully
print("\n--- kernel.lua full ---")
local k = read_file("/savedata0/kernel.lua")
if k then
    print(k)
end

print("\nDone!")
