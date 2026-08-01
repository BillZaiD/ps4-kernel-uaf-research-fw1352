-- Verify os.execute actually does something
print("=== Verify os.execute ===\n")

-- Try to create a file via os.execute touch
local fname = "/av_contents/content_tmp/exec_proof_" .. tostring(os.time()) .. ".txt"
print(string.format("Trying: touch %s", fname))
local ok, r = pcall(os.execute, "touch " .. fname)
print(string.format("os.execute(touch) ret=%s", tostring(r)))

-- Check if file exists
local fok, f = pcall(io.open, fname, "r")
if fok and f then
    print("File exists! os.execute WORKS!")
    f:close()
else
    print("File does not exist. os.execute may be a stub.")
end

-- Try simpler: just echo exit codes
print("\n--- Test os.execute return values ---")
local r1 = os.execute("true")
print(string.format("os.execute(true) = %s", tostring(r1)))
local r2 = os.execute("false")
print(string.format("os.execute(false) = %s", tostring(r2)))
local r3 = os.execute("exit 42")
print(string.format("os.execute(exit 42) = %s", tostring(r3)))
local r4 = os.execute("exit 1")
print(string.format("os.execute(exit 1) = %s", tostring(r4)))

-- Try to write using file_write (from globals)
print("\n--- Test file_write ---")
print(string.format("file_write type: %s", type(file_write)))
local fw_ok, fw_r = pcall(file_write, fname, "test content")
print(string.format("file_write: %s", tostring(fw_r)))

-- Check if file exists now
local f2_ok, f2 = pcall(io.open, fname, "r")
if f2_ok and f2 then
    local c = f2:read("*all")
    print(string.format("file_write content: '%s'", c or "nil"))
    f2:close()
end

print("\nDone!")
