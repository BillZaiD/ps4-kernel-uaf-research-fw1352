-- Read memory.lua to understand the API
local f = io.open("/savedata0/memory.lua", "r")
if f then
  local content = f:read("*a")
  f:close()
  print(content)
else
  print("[-] Cannot read memory.lua")
end

-- Also read native.lua for fcall API
local f2 = io.open("/savedata0/native.lua", "r")
if f2 then
  local content = f2:read("*a")
  f2:close()
  print(content)
else
  print("[-] Cannot read native.lua")
end
