-- Method 1: Patch SC598 wrapper to call syscall 597 instead
-- SC598 wrapper at libkernel_base + 0x1d70 has: mov rax, 0x256 (598)
-- Change to: mov rax, 0x255 (597) by writing 0x55 at offset +3

print("=== Method 1: Patch SC597 into SC598's slot ===\n")

local base = libkernel_base
local sc598_addr = base + 0x1d70

print(string.format("SC598 wrapper at: 0x%x", tonumber(tostring(sc598_addr):sub(3), 16) or 0))

-- Read current bytes
local b = memory.read_buffer(sc598_addr, 8)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("Current bytes: %s (syscall 598)", hex))

-- The syscall number bytes are at offsets 3-6 from wrapper start
-- Offset +3 contains the low byte of the syscall number
local patch_addr = sc598_addr + 3
local current_val = memory.read_byte(patch_addr)
print(string.format("Byte at +3: 0x%02x (need to change to 0x55 for syscall 597)", current_val.l))

-- Try to write the new value
print("\nAttempting to patch byte...")
local ok, err = pcall(function()
    memory.write_byte(patch_addr, 0x55)
end)

if ok then
    local new_val = memory.read_byte(patch_addr)
    print(string.format("SUCCESS! Byte at +3: 0x%02x", new_val.l))
    
    -- Verify the full instruction
    local b2 = memory.read_buffer(sc598_addr, 8)
    local hex2 = ""
    for i = 1, #b2 do hex2 = hex2 .. string.format("%02x", string.byte(b2, i)) end
    print(string.format("Patched bytes: %s (should be syscall 597)", hex2))
    
    -- Now try calling syscall 597!
    -- Use the WRAPPER address directly, but we need to pass it through native.fcall
    -- Actually, we can't use fcall because the wrapper starts with mov rax
    -- We need to use the raw address
    print("\nAttempting to call patched syscall 597 (FSC2H)...")
    print("Using SC598 wrapper address (now patched to syscall 597)")
    
    -- Arguments for FSC2H: check libctl function
    -- Based on the FSC2H research, the syscall typically takes:
    -- a1 = cmd (0 = resolve, 1 = wait, 2 = complete, etc.)
    -- a2 = fd or handle
    -- a3 = path or data buffer
    -- a4 = flags
    
    -- Try with cmd=0 (resolve), no other args
    local r1 = native.fcall(sc598_addr, 0, 0, 0, 0, 0, 0)
    print(string.format("Result 1 (cmd=0): type=%s", type(r1)))
    if r1 then
        if type(r1) == "table" then
            print(string.format("  h=0x%x, l=0x%x (raw 0x%x)", r1.h, r1.l, r1.h * 4294967296 + r1.l))
        else
            print(string.format("  value=%s", tostring(r1)))
        end
    end
    
    -- Try with cmd=2 (complete?)
    local r2 = native.fcall(sc598_addr, 2, 0, 0, 0, 0, 0)
    print(string.format("\nResult 2 (cmd=2): type=%s", type(r2)))
    if r2 then
        if type(r2) == "table" then
            print(string.format("  h=0x%x, l=0x%x (raw 0x%x)", r2.h, r2.l, r2.h * 4294967296 + r2.l))
        else
            print(string.format("  value=%s", tostring(r2)))
        end
    end
    
    -- Restore the original value
    print("\nRestoring original value (0x56 for syscall 598)...")
    memory.write_byte(patch_addr, 0x56)
    local restored = memory.read_byte(patch_addr)
    print(string.format("Restored byte: 0x%02x", restored.l))
else
    print(string.format("FAILED to patch: %s", err))
    print("libkernel is likely RX (not writable)")
    print("Trying alternative approach...")
    
    -- Check if we can find the wrapper address and modify it
    -- Try via /proc/self/map or similar
end

print("\nDone!")
