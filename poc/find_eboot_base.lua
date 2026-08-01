-- Verify eboot base address calculation
local function to_hex(v)
  if type(v) == "table" and v.h then return string.format("0x%x", uint64(v):tonumber()) end
  return tostring(v)
end

-- Known values
local luaB_addr = eboot_addrofs.luaB_auxwrap
local luaB_num = uint64(luaB_addr):tonumber()
print(string.format("luaB_auxwrap runtime: 0x%x", luaB_num))

-- Possible base addresses from offset subtraction
local offset = luaB_num - 0x13600000
print(string.format("If base = 0x13600000, offset = 0x%x", offset))

-- Try reading at various potential base addresses
local candidates = {
  0x13600000,
  0x135FF000,
  0x13601000,
  0x13500000,
  0x140000000,
}

print("\n=== Testing candidate base addresses ===")
for _, base in ipairs(candidates) do
  local ok, result = pcall(memory.read_byte, base)
  local b0 = ok and result or -1
  local b1 = (ok and base + 1) and pcall(memory.read_byte, base + 1) or -1
  local b1v = select(2, pcall(memory.read_byte, base + 1))
  local b2v = select(2, pcall(memory.read_byte, base + 2))
  local b3v = select(2, pcall(memory.read_byte, base + 3))
  
  print(string.format("  0x%x: byte0=%d byte1=%d byte2=%d byte3=%d", 
    base, ok and result or -1, 
    b1v or -1, b2v or -1, b3v or -1))
end

-- Scan for ELF magic in the 0x13000000 - 0x14000000 range
print("\n=== Scanning for ELF magic (0x13000000 - 0x14000000) ===")
for base = 0x13000000, 0x14000000, 0x100000 do
  local b0 = select(2, pcall(memory.read_byte, base))
  local b1 = select(2, pcall(memory.read_byte, base + 1))
  local b2 = select(2, pcall(memory.read_byte, base + 2))
  local b3 = select(2, pcall(memory.read_byte, base + 3))
  if b0 == 0x7f and b1 == 0x45 and b2 == 0x4c and b3 == 0x46 then
    print(string.format("  ELF FOUND at 0x%x!", base))
  end
end

print("\n=== Try reading at luaB_auxwrap itself ===")
local b0 = select(2, pcall(memory.read_byte, luaB_num))
local b1 = select(2, pcall(memory.read_byte, luaB_num + 1))
local b2 = select(2, pcall(memory.read_byte, luaB_num + 2))
local b3 = select(2, pcall(memory.read_byte, luaB_num + 3))
print(string.format("  luaB_auxwrap bytes: %02x %02x %02x %02x", 
  b0 or 0, b1 or 0, b2 or 0, b3 or 0))

-- Try using luaB_auxwrap pointer directly  
local u8_fn = eboot_addrofs.lua_pushcclosure
local u8_num = uint64(u8_fn):tonumber()
print(string.format("lua_pushcclosure: 0x%x", u8_num))
local c0 = select(2, pcall(memory.read_byte, u8_num))
local c1 = select(2, pcall(memory.read_byte, u8_num + 1))
local c2 = select(2, pcall(memory.read_byte, u8_num + 2))
local c3 = select(2, pcall(memory.read_byte, u8_num + 3))
print(string.format("  bytes: %02x %02x %02x %02x", 
  c0 or 0, c1 or 0, c2 or 0, c3 or 0))

print("[+] Done")
