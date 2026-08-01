--[[
    write_byte_overflow_test.lua
    Verify mem.write_byte writes 8 bytes
]]

local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[*] Testing mem.write_byte overflow\n")

-- Allocate a buffer and fill with known values using write_dword (safe)
local buf = mem.alloc(32)
for i = 0, 7 do
    mem.write_dword(buf + i * 4, 0x41414141 + i)
end

print("[*] Before:")
local str = ""
for i = 0, 31 do
    str = str .. string.format("%02x ", tonn(mem.read_byte(buf + i)))
end
print(str)

-- write a byte at buf+0
print("\n[*] mem.write_byte(buf+0, 0xCC)")
mem.write_byte(buf + 0, 0xCC)

str = ""
for i = 0, 31 do
    str = str .. string.format("%02x ", tonn(mem.read_byte(buf + i)))
end
print(str)

-- Count how many bytes == 0xCC
local count_cc = 0
for i = 0, 31 do
    if tonn(mem.read_byte(buf + i)) == 0xCC then count_cc = count_cc + 1 end
end
print(string.format("  bytes == 0xCC: %d (expected 1 for single-byte write, 8 for double write)", count_cc))

if count_cc >= 5 then
    print("[!] CONFIRMED: mem.write_byte writes " .. count_cc .. " bytes (overflow!)")
else
    print("[-] mem.write_byte writes approximately 1 byte (no significant overflow)")
end

print("\n[+] Done")
