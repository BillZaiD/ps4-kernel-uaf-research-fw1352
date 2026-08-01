-- PS4 FW 13.52 - RE-ARM VOLATILITY DIFF (r9am)
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
pcall(S.resolve, { ioctl = 54, mmap = 477 })
local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end
print("=== R9AM START ===")
pcall(function()
  local buf = mem.alloc(0x400)
  local win = mem.alloc(0x1000)
  local base = 0x2ec48000
  local function arm()
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x400), 0x400)
    mem.write_qword(buf, base)
    mem.write_qword(buf + 8, 0x100000)
    t(S.ioctl(5, 0x80108002, buf))
    return t(S.mmap(base, 0x100000, 3, 0x0001, 5, 0))
  end
  local m1 = arm()
  for i = 0, 0x1ff do mem.write_qword(win + i * 8, rq(m1 + i * 8)) end
  local m2 = arm()
  local ch = {}
  for i = 0, 0x1ff do
    if rq(m2 + i * 8) ~= rq(win + i * 8) then ch[#ch + 1] = i * 8 end
  end
  print("arm1=" .. string.format("%x", m1) .. " arm2=" .. string.format("%x", m2))
  print("changed_qwords_0x1000=" .. #ch)
  if #ch > 0 then
    local out = {}
    for k, v in ipairs(ch) do out[#out + 1] = string.format("%04x", v) end
    print(table.concat(out, ","))
  end
  local r1 = {}
  for i = 0, 0x30 do r1[i + 1] = rq(m2 + 0xf000 + i * 8) end
  local r2 = {}
  for i = 0, 0x30 do r2[i + 1] = rq(m1 + 0xf000 + i * 8) end
  local nch = 0
  for i = 1, 0x31 do if r1[i] ~= r2[i] then nch = nch + 1 end end
  print("f000_region_changed=" .. nch)
end)
print("=== R9AM DONE ===")
