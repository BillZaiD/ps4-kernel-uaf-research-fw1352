-- Find universal syscall gadget in libkernel
print("=== Search for syscall gadget ===\n")

-- The wrapper pattern: mov r10, rcx; syscall; ret = 49 89 ca 0f 05 c3
-- or just: syscall; ret = 0f 05 c3

-- Search libkernel for syscall;ret pattern
local base = libkernel_base
local pattern = "\x0f\x05\xc3"  -- syscall; ret

print("Searching for syscall;ret (0f 05 c3)...")
local found = {}
for offset = 0, 0x50000, 1 do
    local b = memory.read_byte(base + offset)
    if b.l == 0x0f then
        local b2 = memory.read_byte(base + offset + 1)
        if b2.l == 0x05 then
            local b3 = memory.read_byte(base + offset + 2)
            if b3.l == 0xc3 then
                table.insert(found, offset)
            end
        end
    end
end

print(string.format("Found %d occurrences\n", #found))
for i, off in ipairs(found) do
    -- Show surrounding bytes
    local ctx = memory.read_buffer(base + off - 4, 12)
    local hex = ""
    for j = 1, #ctx do hex = hex .. string.format("%02x", string.byte(ctx, j)) end
    print(string.format("  0x%x: ...%s...", off, hex))
    if i >= 20 then
        print("  ... (showing first 20)")
        break
    end
end

print("\n--- Checking known wrapper offsets for pattern ---")
-- Check SC585 wrapper address
local w585 = syscall.syscall_wrapper[585]
if w585 then
    local addr = 0
    if type(w585) == "table" then addr = w585.h * 4294967296 + w585.l
    else addr = w585 end
    local off = addr - (base.h * 4294967296 + base.l)
    print(string.format("SC585 at offset 0x%x", off))
    local b = memory.read_buffer(w585, 32)
    local hex = ""
    for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
    print(string.format("  %s", hex))
end

-- Check SC598 wrapper
local w598 = syscall.syscall_wrapper[598]
if w598 then
    local addr = 0
    if type(w598) == "table" then addr = w598.h * 4294967296 + w598.l
    else addr = w598 end
    local off = addr - (base.h * 4294967296 + base.l)
    print(string.format("SC598 at offset 0x%x", off))
    local b = memory.read_buffer(w598, 32)
    local hex = ""
    for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
    print(string.format("  %s", hex))
end

-- Search for mov rax, imm32 pattern near syscall;ret (wrapper start)
print("\n--- Finding mov rax, imm32 (48 c7 c0 XX XX XX 00) pattern ---")
for offset = 0, 0x50000, 1 do
    local b = memory.read_byte(base + offset)
    if b.l == 0x48 then
        local b2 = memory.read_byte(base + offset + 1)
        if b2.l == 0xc7 then
            local b3 = memory.read_byte(base + offset + 2)
            if b3.l == 0xc0 then
                -- This looks like mov rax, imm32
                -- Check if followed by mov r10, rcx; syscall; ret
                local check = memory.read_buffer(base + offset + 7, 5)
                if #check >= 5 then
                    local c1 = string.byte(check, 1)
                    local c2 = string.byte(check, 2) 
                    local c3 = string.byte(check, 3)
                    local c4 = string.byte(check, 4)
                    local c5 = string.byte(check, 5)
                    if c1 == 0x49 and c2 == 0x89 and c3 == 0xca and c4 == 0x0f and c5 == 0x05 then
                        local sys_num = memory.read_dword(base + offset + 3)
                        local num = (sys_num.h or 0) * 4294967296 + (sys_num.l or 0)
                        print(string.format("  syscall wrapper at offset 0x%x: syscall %d", offset, num))
                    end
                end
            end
        end
    end
end

print("\nDone!")
