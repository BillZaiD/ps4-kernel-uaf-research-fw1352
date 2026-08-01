-- Read offsets.lua to find game base address
local f = io.open("/savedata0/offsets.lua", "r")
if f then
  local content = f:read("*a")
  f:close()
  -- Print lines containing "eboot" or "EBOOT" or "base"
  for line in content:gmatch("[^\r\n]+") do
    if line:lower():find("eboot") or line:lower():find("game") or line:lower():find("base") or line:lower():find("addrofs") then
      print(line)
    end
  end
  print("--- Total offsets.lua size: " .. #content .. " bytes ---")
else
  print("[-] Cannot read offsets.lua")
end
