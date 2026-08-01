-- Debug luaB_auxwrap address
local lb = eboot_addrofs.luaB_auxwrap
print("luaB type: " .. type(lb))

-- Print raw table fields
if type(lb) == "table" then
  print("  h (hex): 0x" .. string.format("%x", lb.h or 0))
  print("  l (hex): 0x" .. string.format("%x", lb.l or 0))
  print("  h (dec): " .. tostring(lb.h or 0))
  print("  l (dec): " .. tostring(lb.l or 0))
  
  local via_tonumber = uint64(lb):tonumber()
  print("  via tonumber: 0x" .. string.format("%x", via_tonumber))
  print("  via tonumber (dec): " .. tostring(via_tonumber))
  
  -- Try using h*2^32 + l
  local computed = lb.h * 4294967296 + lb.l
  print("  via h*2^32+l: 0x" .. string.format("%x", computed))
  
  -- Try lua.resolve_value
  local resolved = lua.resolve_value(lb)
  print("  via resolve_value: " .. tostring(resolved))
  if type(resolved) == "table" then
    print("    h: 0x" .. string.format("%x", resolved.h or 0))
    print("    l: 0x" .. string.format("%x", resolved.l or 0))
  end
end

-- Safe byte reader
local function safe_rb(addr)
  local ok, v = pcall(memory.read_byte, addr)
  if ok and type(v) == "number" then return v end
  return nil
end

-- Direct read buffer - try to get raw bytes
local addr = uint64(lb):tonumber()
print("\nRead buffer at luaB_auxwrap (0x" .. string.format("%x", addr) .. "):")

local ok, buf = pcall(memory.read_buffer, addr, 32)
if ok and buf then
  print("  OK, length=" .. tostring(#buf))
  for i = 1, #buf do
    io.write(string.format("%02x ", string.byte(buf, i)))
    if i % 16 == 0 then io.write("\n") end
  end
  io.write("\n")
else
  print("  FAILED: " .. tostring(buf))
  -- Try with smaller read
  local ok2, buf2 = pcall(memory.read_buffer, addr, 1)
  if ok2 and buf2 then
    print("  1-byte read: byte=0x" .. string.format("%02x", string.byte(buf2, 1)))
  else
    print("  1-byte read also FAILED: " .. tostring(buf2))
  end
end

-- Try base candidate
local base = addr - 0x1a7420
print("\nRead buffer at base (0x" .. string.format("%x", base) .. "):")
local ok3, buf3 = pcall(memory.read_buffer, base, 16)
if ok3 and buf3 then
  print("  OK, length=" .. tostring(#buf3))
  for i = 1, #buf3 do
    io.write(string.format("%02x ", string.byte(buf3, i)))
    if i % 16 == 0 then io.write("\n") end
  end
  io.write("\n")
  -- Show ASCII
  io.write("  ASCII: ")
  for i = 1, #buf3 do
    local c = string.byte(buf3, i)
    if c >= 32 and c < 127 then io.write(string.char(c)) else io.write(".") end
  end
  io.write("\n")
else
  print("  FAILED")
end

-- Also try to read libkernel address to sanity-check memory.read_buffer
print("\n=== Sanity check: read from libkernel ===")
local lk_base = 0x813758000
local ok4, buf4 = pcall(memory.read_buffer, lk_base, 4)
if ok4 and buf4 then
  print("  libkernel bytes: " .. string.format("%02x %02x %02x %02x", string.byte(buf4,1), string.byte(buf4,2), string.byte(buf4,3), string.byte(buf4,4)))
end

print("[+] Done")


print("[+] Done")
