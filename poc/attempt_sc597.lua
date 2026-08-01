-- First, try the patch and also explore other approaches
print("=== Patch SC597 + Alternatives ===\n")

local base = libkernel_base
local sc598_addr = base + 0x1d70

-- Check if we can write to libkernel
print("--- Attempt 1: Direct patch ---")
local patch_addr = sc598_addr + 3
local current_val = memory.read_byte(patch_addr)
print(string.format("Byte at SC598+3 (syscall number low byte): 0x%02x", current_val.l))

local ok, err = pcall(function()
    memory.write_byte(patch_addr, 0x55)
end)

if ok then
    local new_val = memory.read_byte(patch_addr)
    print(string.format("PATCHED! Now: 0x%02x", new_val.l))
    
    -- Try calling what's now syscall 597
    print("\nCalling patched syscall 597 (FSC2H)...")
    local r = native.fcall(sc598_addr, 0, 0, 0, 0, 0, 0)
    print(string.format("Result: %s", tostring(r or "nil")))
    if type(r) == "table" then
        print(string.format("  h=0x%x, l=0x%x", r.h, r.l))
    end
    
    -- Restore
    memory.write_byte(patch_addr, 0x56)
else
    print("Cannot patch (likely RX only)")
    print(err)
    
    -- Attempt 2: Try to find the wrapper table in memory (Lua table -> might be writable)
    print("\n--- Attempt 2: Check if we can find syscall_wrapper table ---")
    -- The wrapper table maps syscall# to address. If we can add entry for 597 -> SC598's address
    -- But this is a Lua table, not C memory...
    
    -- Attempt 3: Search for syscall; ret anywhere in executable memory
    print("\n--- Attempt 3: Search syscall;ret in all mapped memory ---")
    -- We know the pattern 0f 05 XX XX exists in wrappers as 0f 05 72 01
    -- Let's search more broadly
    for off = 0, 0x50000, 0x1000 do
        local chunk = memory.read_buffer(base + off, 0x1000)
        if chunk and #chunk > 0 then
            local pos = 1
            while true do
                pos = chunk:find("\x0f\x05", pos, 1)
                if not pos then break end
                local abs_offset = off + pos - 1
                
                -- Check what follows
                local after = memory.read_byte(base + abs_offset + 2)
                local after2 = memory.read_byte(base + abs_offset + 3)
                local after3 = memory.read_byte(base + abs_offset + 4)
                
                if abs_offset < 0x1d70 + 10 and abs_offset > 0x1d70 + 10 - 5 then
                    -- This IS syscall instruction inside the wrapper
                    pos = pos + 1
                else
                    print(string.format("  Found extra syscall at offset 0x%x, followed by: 0x%02x 0x%02x 0x%02x", 
                        abs_offset, after.l, after2 and after2.l or 0, after3 and after3.l or 0))
                end
                pos = pos + 1
                if off + pos > 0x50000 then break end
            end
        end
    end
end

-- Attempt 4: Use a DIFFERENT approach entirely
-- The native.fcall calls ANY function. What about calling the syscall directly
-- via the kernel's syscall handler, using a SYS_syscall syscall?
-- Actually, we could try using the lua.lua fake primitive to modify the wrapper table

print("\n--- Attempt 4: Check if syscall table data is in writable mem ---")
-- The wrapper addresses are stored in the Lua runtime heap
-- But the ACTUAL syscall entry point table (in the kernel) might be accessible

-- Check if we can read the kernel's syscall table
-- On FreeBSD, the syscall table is at a fixed address exported by the kernel
-- But we don't have kernel memory access...

print("\nDone!")
