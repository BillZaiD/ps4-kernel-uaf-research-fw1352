-- Step 1: Explore game memory map and /app0/
print("=== Game Memory Map ===")
local f = io.open("/proc/self/map", "r")
if f then
  local content = f:read("*a")
  f:close()
  print(content)
else
  print("[-] /proc/self/map not accessible")
end

print("=== /app0/ files ===")
local f2 = io.open("/app0/", "r")
if f2 then
  local entries = f2:read("*a")
  print(entries)
  f2:close()
else
  print("[-] /app0/ not accessible as file")
end

-- try reading eboot.bin header
print("=== eboot.bin (first 256 bytes) ===")
local f3 = io.open("/app0/eboot.bin", "rb")
if f3 then
  local header = f3:read(256)
  f3:close()
  for i = 1, #header do
    io.write(string.format("%02x ", string.byte(header, i)))
    if i % 16 == 0 then io.write("\n") end
  end
  io.write("\n")
else
  print("[-] /app0/eboot.bin not accessible")
end

print("=== /savedata0/ files ===")
local f4 = io.open("/savedata0/", "r")
if f4 then
  local entries = f4:read("*a")
  print(entries)
  f4:close()
else
  print("[-] /savedata0/ not accessible as file")
end

-- List savedata files individually  
local dirs = {"kernel.lua", "native.lua", "syscall.lua", "misc.lua", "offsets.lua", "ropchain.lua"}
for _, fn in ipairs(dirs) do
  local f5 = io.open("/savedata0/" .. fn, "r")
  if f5 then
    local content = f5:read(128)
    print("/savedata0/" .. fn .. " (" .. #(f5:read("*a") or "") .. " bytes): OK")
    f5:close()
  else
    print("/savedata0/" .. fn .. ": NOT FOUND")
  end
end

print("[+] Done")
