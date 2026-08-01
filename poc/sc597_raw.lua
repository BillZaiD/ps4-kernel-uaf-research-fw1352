-- Check if SC597 wrapper exists at expected libkernel offset
print("=== SC597 wrapper raw check ===\n")

print(string.format("libkernel_base = %s", tostring(libkernel_base)))

-- Calculate expected offset: 0x2A10 + syscall_num * 32
local base_num = tonumber(tostring(libkernel_base):sub(3), 16)
if not base_num then
    base_num = libkernel_base.h * 4294967296 + libkernel_base.l
end

local sc597_off = 0x2A10 + 597 * 32
print(string.format("Expected SC597 wrapper at offset 0x%x", sc597_off))

-- Read the expected wrapper bytes
local addr = libkernel_base + sc597_off
local bytes = memory.read_buffer(addr, 32)
local hex = ""
for i = 1, #bytes do hex = hex .. string.format("%02x", string.byte(bytes, i)) end
print(string.format("Bytes at expected SC597: %s", hex))

-- Compare with known wrapper (SC585 for reference)
local sc585_off = 0x2A10 + 585 * 32
local addr585 = libkernel_base + sc585_off
local bytes585 = memory.read_buffer(addr585, 32)
local hex585 = ""
for i = 1, #bytes585 do hex585 = hex585 .. string.format("%02x", string.byte(bytes585, i)) end
print(string.format("Bytes at SC585 (for ref): %s", hex585))

-- Check the actual wrapper at wt[598] to calculate its offset
local w598 = syscall.syscall_wrapper[598]
if w598 then
    local w598_num = 0
    if type(w598) == "table" then w598_num = w598.h * 4294967296 + w598.l
    else w598_num = w598 end
    local w598_off = w598_num - base_num
    print(string.format("\nSC598 wrapper addr: 0x%x (offset 0x%x)", w598_num, w598_off))
    
    -- Expected offset for SC598: 0x2A10 + 598*32 = 0x2A10 + 0x4AD0 = 0x74E0
    local expected_598 = 0x2A10 + 598 * 32
    print(string.format("Expected SC598 offset: 0x%x", expected_598))
    print(string.format("Match: %s", tostring(w598_off == expected_598)))
end

-- Check what bytes are at SC597's expected offset
-- A syscall wrapper should start with B8 (mov eax, imm32) followed by the syscall number
print("\n--- Raw wrapper bytes analysis ---")
for num in ipairs({585, 586, 591, 596, 597, 598, 599, 602, 606}) do
    local off = 0x2A10 + num * 32
    local b = memory.read_buffer(libkernel_base + off, 32)
    local hex_b = ""
    for i = 1, #b do hex_b = hex_b .. string.format("%02x", string.byte(b, i)) end
    local first_byte = string.byte(b, 1) if not first_byte then first_byte = 0 end
    local syscall_num = string.byte(b, 2) or 0
    if first_byte == 0xB8 then
        print(string.format("  SC%03d (0x%x): %s <- VALID (eax=0x%02x)", num, off, hex_b, syscall_num))
    else
        print(string.format("  SC%03d (0x%x): %s <- NOT syscall wrapper", num, off, hex_b))
    end
end

print("\nDone!")
