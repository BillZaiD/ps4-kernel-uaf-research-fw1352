-- Call libkernel functions directly via native.fcall
print("=== Direct libkernel function calls ===\n")

-- libkernel_base = 0x82e018000
print(string.format("libkernel_base = 0x%x", libkernel_base.l + libkernel_base.h * 4294967296))

-- Verify by reading first bytes
local magic = memory.read_buffer(libkernel_base, 16)
local hex = ""
for i = 1, #magic do hex = hex .. string.format("%02x", string.byte(magic, i)) end
print(string.format("First 16 bytes: %s", hex))

-- known libkernel string offsets from earlier analysis
-- strings at ~0x36000
local str_off = 0x36000
local str_addr = libkernel_base + str_off

-- Read strings from libkernel
print("\n--- Strings at 0x36000 ---")
for i = 0, 5 do
    local str = memory.read_null_terminated_string(str_addr + i * 100)
    if str and #str > 1 and #str < 100 then
        print(string.format("  0x%x: '%s'", str_off + i * 100, str))
    end
end

-- Try to find sysctl implementation in libkernel
-- The sysctl function in libkernel likely looks up the name and calls syscall 202
-- Let's search for "sysctl" string
print("\n--- Searching for sysctl string in libkernel ---")
for offset = 0, 0x40000, 0x10 do
    local str = memory.read_null_terminated_string(libkernel_base + offset)
    if str == "sysctl" then
        print(string.format("  Found 'sysctl' at offset 0x%x", offset))
    end
end

-- Let's inspect the syscall wrappers we know about
-- syscall 202 wrapper at libkernel offset ~0x2A10 + 202*32
local sc202_offset = 0x2A10 + 202 * 32
print("\n--- syscall 202 wrapper at 0x%x ---", sc202_offset)
local wrapper = memory.read_buffer(libkernel_base + sc202_offset, 32)
local hex = ""
for i = 1, #wrapper do hex = hex .. string.format("%02x", string.byte(wrapper, i)) end
print(hex)

-- Check what's at offset 0 (entry point)
print("\n--- libkernel offset 0 (entry) ---")
local entry = memory.read_buffer(libkernel_base, 64)
local hex = ""
for i = 1, #entry do hex = hex .. string.format("%02x", string.byte(entry, i)) end
print(hex)

-- Interesting: try to call libkernel's internal sleep or delay functions
-- Look for "nanosleep" or "sleep" references
print("\n--- Searching for strings near 0x36000 ---")
for offset = 0x36000, 0x37000, 0x40 do
    local str = memory.read_null_terminated_string(libkernel_base + offset)
    if str and #str > 0 then
        print(string.format("  0x%x: '%s'", offset, str))
    end
end

print("\nDone!")
