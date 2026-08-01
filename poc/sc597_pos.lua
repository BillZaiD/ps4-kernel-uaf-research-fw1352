-- Check SC597 position between SC596 and SC598
print("=== SC597 position check ===\n")

local base = libkernel_base

-- Read bytes at the expected SC597 position
local sc596_addr = 0x83e7d1d50
local sc597_addr = sc596_addr + 32  -- 0x83e7d1d60
local sc598_addr = sc596_addr + 64  -- 0x83e7d1d70

print(string.format("SC596 addr: 0x%x", sc596_addr))
print(string.format("SC597 addr: 0x%x (expected)", sc597_addr))
print(string.format("SC598 addr: 0x%x", sc598_addr))

-- Read 32 bytes at SC596, SC597 position, SC598
local b596 = memory.read_buffer(sc596_addr, 32)
local b597 = memory.read_buffer(sc597_addr, 32)
local b598 = memory.read_buffer(sc598_addr, 32)

local function to_hex(b)
    local hex = ""
    for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
    return hex
end

print(string.format("\nSC596: %s", to_hex(b596)))
print(string.format("SC597: %s", to_hex(b597)))
print(string.format("SC598: %s", to_hex(b598)))

-- Check if SC597 position has a valid wrapper
local b1 = string.byte(b597, 1) or 0
if b1 == 0x48 and string.byte(b597, 2) == 0xc7 and string.byte(b597, 3) == 0xc0 then
    -- Valid mov rax, imm32
    local sc_num = string.byte(b597, 4) + string.byte(b597, 5) * 256 + string.byte(b597, 6) * 65536 + string.byte(b597, 7) * 16777216
    print(string.format("\nSC597 position has VALID wrapper for syscall %d (0x%x)", sc_num, sc_num))
elseif b1 == 0x00 or b1 == 0xFF then
    print(string.format("\nSC597 position is EMPTY/ZERO"))
else
    print(string.format("\nSC597 position has code (not a wrapper)"))
end

-- Check ALL addresses between SC585 and SC677 for wrappers
print("\n--- Complete wrapper scan 585-677 ---")
local sc_585_addr = 0x83e7d1c30  -- SC585 address

for i = 585, 677 do
    local addr = sc_585_addr + (i - 585) * 32
    local b = memory.read_buffer(addr, 7)  -- Just first 7 bytes for mov rax
    
    local b1 = string.byte(b, 1) or 0
    local b2 = string.byte(b, 2) or 0
    local b3 = string.byte(b, 3) or 0
    
    if b1 == 0x48 and b2 == 0xc7 and b3 == 0xc0 then
        local sc_num = string.byte(b, 4) + string.byte(b, 5) * 256 + string.byte(b, 6) * 65536 + string.byte(b, 7) * 16777216
        if sc_num ~= i then
            print(string.format("  SC%03d position: syscall %d (MISMATCH!)", i, sc_num))
        end
    else
        print(string.format("  SC%03d position: NO wrapper (0x%02x%02x%02x...)", i, b1, b2, b3))
    end
end

print("\nDone!")
