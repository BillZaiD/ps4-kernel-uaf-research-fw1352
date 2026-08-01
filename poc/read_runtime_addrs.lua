-- Read runtime addresses from the framework
print("=== EBOOT (game binary) ===")
local function to_hex(v)
  if type(v) == "table" and v.h then
    return string.format("0x%x", uint64(v):tonumber())
  end
  return tostring(v)
end

local function print_table(name, t)
  print(name .. " table exists")
  for k, v in pairs(t) do
    print(string.format("  %s: %s", k, to_hex(v)))
  end
  -- Check for __base
  if t.__base then
    print(string.format("  [BASE]: %s", to_hex(t.__base)))
  end
end

print("=== EBOOT (game binary) ===")
if eboot_addrofs then
  print_table("eboot_addrofs", eboot_addrofs)
end

print("=== LIBC (libkernel) ===")
if libc_addrofs then
  print_table("libc_addrofs", libc_addrofs)
end

print("=== GLOBALS ===")
print(string.format("game_name: %s", game_name or "nil"))
print(string.format("FW_VERSION: %s", FW_VERSION or "nil"))

-- Try to get the actual eboot base
-- The luaB_auxwrap function's runtime address minus its offset = eboot base
local eboot_base = nil
for k, v in pairs(eboot_addrofs) do
  if k:find("luaB") then
    print(string.format("Found luaB function: %s = 0x%x", k, v))
    -- Try to get the runtime address of this function
    -- The runtime table has __base if we're lucky
  end
end

local eboot_base = nil
if eboot_addrofs and eboot_addrofs.__base then
  eboot_base = uint64(eboot_addrofs.__base):tonumber()
  print(string.format("EBOOT BASE: 0x%x", eboot_base))
  -- Read ELF header to confirm
  local b0 = memory.read_byte(eboot_base)
  local b1 = memory.read_byte(eboot_base + 1)
  local b2 = memory.read_byte(eboot_base + 2)
  local b3 = memory.read_byte(eboot_base + 3)
  print(string.format("  ELF magic: %02x %02x %02x %02x", b0, b1, b2, b3))
  
  -- Read first 256 bytes of eboot
  print("=== EBOOT header (first 256 bytes) ===")
  local buf = memory.read_buffer(eboot_base, 256)
  for i = 1, #buf do
    io.write(string.format("%02x ", string.byte(buf, i)))
    if i % 16 == 0 then io.write("\n") end
  end
  io.write("\n")
end

print("[+] Done")
