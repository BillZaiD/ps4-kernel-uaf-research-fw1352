print("alive")
local S = rawget(_G, "syscall")
S.resolve({getpid=20})
print("pid=" .. tostring(S.getpid()))
