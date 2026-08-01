-- Debug io and os.execute
print("=== Debug I/O ===\n")

-- Check io functions
print("--- io table ---")
for k, v in pairs(io) do
    print(string.format("  io.%s = %s", tostring(k), type(v)))
end

-- Check WRITABLE_PATH
print(string.format("\nWRITABLE_PATH = %s", tostring(WRITABLE_PATH)))

-- Try io.open with different paths
local paths = {
    WRITABLE_PATH,
    "/savedata0/",
    "/data/",
    "/tmp/",
    "/app0/",
    "/preinst/",
    "/system/",
}

for _, p in ipairs(paths) do
    if p then
        local ok, f = pcall(io.open, p .. "test_write_" .. tostring(os.time()) .. ".txt", "w")
        if ok and f then
            print(string.format("io.open(%s, w): OK", p))
            f:close()
            pcall(os.execute, "rm " .. p .. "test_write_*")
        else
            print(string.format("io.open(%s, w): FAIL", p))
        end
    end
end

-- Actually try os.execute with echo to /savedata0
print("\n--- os.execute echo test ---")
local ok, r = pcall(os.execute, "echo HELLO > /savedata0/exec_test.txt 2>&1")
print(string.format("os.execute(echo): ret=%s", tostring(r)))

local ok, f = pcall(io.open, "/savedata0/exec_test.txt", "r")
if ok and f then
    local c = f:read("*all")
    print(string.format("File contents: '%s'", c))
    f:close()
else
    print("Could not open file for reading")
end

-- List savedata0 files
print("\n--- List /savedata0/ ---")
pcall(os.execute, "ls -la /savedata0/ > /savedata0/dir_list.txt")
local ok, f = pcall(io.open, "/savedata0/dir_list.txt", "r")
if ok and f then
    local c = f:read("*all")
    print(c)
    f:close()
else
    print("Could not list directory")
end

print("Done!")
