-- Focused fuzz on SC609, SC614, SC621 + pattern exploration
print("=== SC609/614/621 Deep Fuzz ===\n")

local wt = syscall.syscall_wrapper

local function to_num(v)
  if v == nil then return 0 end
  if type(v) == "table" then
    if v.h then return v.h * 4294967296 + (v.l or 0) end
    if v.l then return v.l end
    return tonumber(tostring(v)) or 0
  end
  return tonumber(tostring(v)) or 0
end

local function run_sc(num, a1, a2, a3, a4, a5, a6)
  local w = wt[num]
  if not w then return -1, "NO_WRAPPER" end
  local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
  if not ok then return -1, "CRASH" end
  return to_num(ret), "OK"
end

-- Test SC609, SC614, SC621 with many patterns
local target_sc = {609, 614, 621}
local patterns = {
  {name="zero", {0,0,0,0,0,0}},
  {name="a1=1", {1,0,0,0,0,0}},
  {name="a1=-1", {-1,0,0,0,0,0}},
  {name="a1=buf", {memory.alloc(0x40),0,0,0,0,0}},
  {name="a1=buf+a2=1", {memory.alloc(0x40),1,0,0,0,0}},
  {name="a1=buf+a2=0x40", {memory.alloc(0x40),0x40,0,0,0,0}},
  {name="a1=buf+a2=0x100", {memory.alloc(0x40),0x100,0,0,0,0}},
  {name="bigbuf", {memory.alloc(0x1000),0x1000,0,0,0,0}},
  {name="a1=pid", {186,0,0,0,0,0}},
  {name="a1=0xdee", {0xdee,0,0,0,0,0}},
  {name="a1=pid,a2=buf", {186,memory.alloc(0x40),0x40,0,0,0}},
  {name="a1=1,a2=buf", {1,memory.alloc(0x40),0,0,0,0}},
  {name="a3=buf", {0,0,memory.alloc(0x40),0,0,0}},
  {name="a3=buf,a4=0x40", {0,0,memory.alloc(0x40),0x40,0,0}},
  {name="a5=buf", {0,0,0,0,memory.alloc(0x40),0}},
  {name="a5=buf,a6=0x40", {0,0,0,0,memory.alloc(0x40),0x40}},
  {name="a2=1,a3=buf", {0,1,memory.alloc(0x40),0x40,0,0}},
  {name="a2=1,a5=buf", {0,1,0,0,memory.alloc(0x40),0x40}},
  {name="a1=scno", {609,0,0,0,0,0}},  -- try with its own number
  -- Try with non-zero small values
  {name="1,2,3,4,5,6", {1,2,3,4,5,6}},
  {name="0x100,0x200", {0x100,0x200,0,0,0,0}},
}

for _, sc in ipairs(target_sc) do
  print(string.format("\n=== SC%03d ===", sc))
  for _, p in ipairs(patterns) do
    local ret, status = run_sc(sc, p[1][1], p[1][2], p[1][3], p[1][4], p[1][5], p[1][6])
    local anal = ""
    if ret == 0xFFFFFFFFFFFFFFFF then anal = "(-1)"
    elseif ret == 0xFFFFFFFFFFFFFC19 then anal = "(ERR -999)"
    elseif ret == 0 then anal = "(0)"
    elseif ret > 0 and ret < 0x10000 then anal = "(small)"
    else anal = "(0x" .. string.format("%x", ret) .. ")"
    end
    print(string.format("  %25s -> 0x%x %s", p.name, ret, anal))
  end
end

-- Also test SC638 and SC657 with more specific patterns
print("\n=== SC638/SC657: Alternative arg layouts ===")
local alt_pats = {
  {name="a2=buf(1)", {0, memory.alloc(0x40), 0x40, 0, 0, 0}},
  {name="a3=buf(1)", {0, 0, memory.alloc(0x40), 0x40, 0, 0}},
  {name="a4=buf(1)", {0, 0, 0, memory.alloc(0x40), 0x40, 0}},
  {name="a5=buf(1)", {0, 0, 0, 0, memory.alloc(0x40), 0x40}},
  {name="buf,buf,buf", {memory.alloc(0x40), memory.alloc(0x40), memory.alloc(0x40), 0, 0, 0}},
  {name="pid,buf,sz", {186, memory.alloc(0x40), 0x40, 0, 0, 0}},
  {name="buf,pid,sz", {memory.alloc(0x40), 186, 0x40, 0, 0, 0}},
}

for _, sc in ipairs({638, 657}) do
  print(string.format("\n--- SC%03d:", sc))
  for _, p in ipairs(alt_pats) do
    local ret, _ = run_sc(sc, p[1][1], p[1][2], p[1][3], p[1][4], p[1][5], p[1][6])
    print(string.format("  %25s -> 0x%x", p[1], ret))
  end
end

-- Test all 600-677 with buffer and check for modifications
print("\n=== SC600-SC677: buffer modification scan ===")
for sc = 600, 677 do
  local buf = memory.alloc(0x100)
  -- Fill with pattern
  for i = 0, 0xFF do memory.write_byte(buf + i, i % 256) end
  local ret, _ = run_sc(sc, buf, 0x100, 0, 0)
  
  -- Quick check first 8 bytes
  local mods = {}
  for i = 0, 0x7F do
    local b = to_num(memory.read_byte(buf + i))
    if b ~= (i % 256) then table.insert(mods, {i, b}) end
  end
  
  if #mods > 0 then
    print(string.format("  SC%03d ret=0x%x: %d bytes changed!", sc, ret, #mods))
    for _, m in ipairs(mods) do
      print(string.format("    [+0x%x] was 0x%02x now 0x%02x", m[1], m[1] % 256, m[2]))
    end
  end
end

print("\n[+] Done")
