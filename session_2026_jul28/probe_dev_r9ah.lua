-- PS4 FW 13.52 - 16MB SWEEP via read_buffer + byte-scan (r9ah) — FAST
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end

print("=== R9AH START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x1000000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x1000000, 3, 0x0001, 5, 0))
  print("arm=" .. rarm .. " map=0x" .. string.format("%x", m))

  local pat = string.char(255, 255, 255, 255)
  local hits = {}
  local CH = 0x40000
  for ci = 0, 15 do
    local base = m + ci * CH
    local ok, bytes = pcall(mem.read_buffer, base, CH)
    if not ok then print("CHUNK_READ_FAIL " .. ci) break end
    local p = 1
    while true do
      p = string.find(bytes, pat, p, true)
      if not p then break end
      if p >= 5 then
        local v = t(mem.read_qword(base + (p - 5)))
        if v >= 0xfffffff000000000 then
          local rel = ci * CH + (p - 5)
          hits[#hits + 1] = string.format("%07x=%016x", rel, v)
        end
      end
      p = p + 1
    end
  end
  print("kernel_hits=" .. #hits)
  for _, h in ipairs(hits) do print("K" .. h) end
end)
print("=== R9AH DONE ===")
