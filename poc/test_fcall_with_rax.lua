-- Try native.fcall_with_rax with syscall 597
print("=== native.fcall_with_rax test ===\n")

-- Check if the function exists
if native.fcall_with_rax then
    print("native.fcall_with_rax EXISTS!\n")
else
    print("native.fcall_with_rax DOES NOT EXIST\n")
end

-- List all native functions
print("--- native functions ---")
for k, v in pairs(native) do
    print(string.format("  native.%s = %s", k, type(v)))
end

print("\n--- Checking rawsyscall gadget ---")
local raw_syscall = libkernel_base + 0x2ba7  -- mov r10, rcx; syscall; ret

-- Read the bytes to verify
local b = memory.read_buffer(raw_syscall, 8)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("Bytes at +0x2ba7: %s", hex))

-- Also try +0x2baa (syscall; ret only)
local raw_syscall2 = libkernel_base + 0x2baa
local b2 = memory.read_buffer(raw_syscall2, 4)
local hex2 = ""
for i = 1, #b2 do hex2 = hex2 .. string.format("%02x", string.byte(b2, i)) end
print(string.format("Bytes at +0x2baa: %s", hex2))

-- Try to call syscall 597 with no arguments
if native.fcall_with_rax then
    print("\n--- Calling syscall 597 (FSC2H) ---")
    print("Using rawsyscall gadget at +0x2ba7")
    
    -- Arguments for FSC2H based on reverse engineering:
    -- a1 = cmd (0=resolve, 1=wait, 2=complete?)
    -- a2 = fd?
    -- a3 = path buffer?
    -- a4 = flags?
    
    local ok, result = pcall(function()
        return native.fcall_with_rax(raw_syscall, 597, 0, 0, 0, 0, 0, 0)
    end)
    
    if ok then
        print(string.format("Result 1 (cmd=0): type=%s", type(result)))
        if type(result) == "table" then
            print(string.format("  h=0x%x, l=0x%x (0x%x)", result.h, result.l, result.h * 4294967296 + result.l))
        else
            print(string.format("  value=%s", tostring(result)))
        end
    else
        print(string.format("FAILED: %s", tostring(result)))
    end
    
    -- Try cmd=2
    local ok2, result2 = pcall(function()
        return native.fcall_with_rax(raw_syscall, 597, 2, 0, 0, 0, 0, 0)
    end)
    if ok2 then
        print(string.format("Result 2 (cmd=2): type=%s", type(result2)))
        if type(result2) == "table" then
            print(string.format("  h=0x%x, l=0x%x (0x%x)", result2.h, result2.l, result2.h * 4294967296 + result2.l))
        else
            print(string.format("  value=%s", tostring(result2)))
        end
    end
else
    print("\nnative.fcall_with_rax not available. Trying alternative...")
    print("Checking for ropchain module...")
    if ropchain then
        print("ropchain EXISTS!")
        for k, v in pairs(ropchain) do
            print(string.format("  ropchain.%s = %s", k, type(v)))
        end
    end
end

print("\nDone!")
