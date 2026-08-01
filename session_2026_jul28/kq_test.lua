-- TEST: kqueue via S.resolve vs gadget
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rd(a) return t(mem.read_dword(a)) end
local function rb(a) return t(mem.read_byte(a)) end

print("=== KQUEUE TEST ===")

-- Try S.resolve for kqueue
print("[A] S.resolve kqueue...")
local ok, err = pcall(S.resolve, {kqueue = 362, kevent = 363, close = 6})
print(string.format("  resolve: %s %s", tostring(ok), tostring(err)))

if ok then
  print("[B] S.kqueue() named call...")
  local kq = pcall(function() return t(S.kqueue()) end)
  print(string.format("  kqueue via named = %d", kq))
  if kq > 0 then
    -- kevent test
    local ev = mem.alloc(32)
    for i=0,31 do mem.write_byte(ev+i, 0) end
    mem.write_qword(ev+0, 0x42)
    mem.write_word(ev+8, 0xFFF9)
    mem.write_word(ev+10, 0x0011)
    local r = pcall(function() return t(S.kevent(kq, ev, 1, nil, 0, 0)) end)
    print(string.format("  kevent ADD = %d", r))
    S.close(kq)
  end
end

-- Try gadget approach with different gadget offset
print("[C] Try gadget with offset scan...")
pcall(function()
  local waddr = t(S.syscall_wrapper[20])
  for i = 0, 30 do
    if rb(waddr+i) == 0x0F and rb(waddr+i+1) == 0x05 then
      local g = waddr + i
      local r = t(nat.fcall_with_rax(g, 362, 0, 0, 0, 0, 0, 0))
      print(string.format("  gadget+%d (0x%x): kqueue=%d", i, g, r))
      break
    end
  end
end)

print("=== DONE ===")
