print("hello from termux")
print(type(memory))
print(type(syscall))
print(type(native))
local S = rawget(_G, "syscall")
S.resolve({getpid=20, getuid=24, close=6})
local function tonn(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
print("getpid=" .. tonn(S.getpid()))
print("getuid=" .. tonn(S.getuid()))
print("done")
