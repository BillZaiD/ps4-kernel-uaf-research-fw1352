-- Comprehensive fuzz of SC638 and SC657
print("=== SC638 / SC657 Comprehensive Fuzz ===\n")

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
  if not w then return -999, "NO_WRAPPER" end
  local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
  if not ok then return -999, "CRASH" end
  return to_num(ret), "OK"
end

-- Test SC638 with buffer + sizes
print("=== SC638: Buffer+Size Fuzz ===")
local pats_638 = {
  {name="zero", buf=nil, sz=0, a3=0, a4=0},
  {name="buf+0", buf=memory.alloc(0x40), sz=0, a3=0, a4=0},
  {name="buf+1", buf=memory.alloc(0x40), sz=1, a3=0, a4=0},
  {name="buf+4", buf=memory.alloc(0x40), sz=4, a3=0, a4=0},
  {name="buf+0x40", buf=memory.alloc(0x40), sz=0x40, a3=0, a4=0},
  {name="buf+0x100", buf=memory.alloc(0x40), sz=0x100, a3=0, a4=0},
  {name="bigbuf+0x40", buf=memory.alloc(0x1000), sz=0x40, a3=0, a4=0},
  {name="bigbuf+0x1000", buf=memory.alloc(0x1000), sz=0x1000, a3=0, a4=0},
  {name="a1=1", buf=nil, sz=0, a3=1, a4=0},
  {name="a1=-1", buf=nil, sz=0, a3=-1, a4=0},
}

for _, p in ipairs(pats_638) do
  local ret, status = run_sc(638, p.buf or p.sz, p.buf and p.sz or 0, p.a3, p.a4)
  print(string.format("  %20s -> ret=0x%x (%s)", p.name, ret, status))
end

-- Check if SC638 modifies buffer
print("\n--- SC638 buffer content check ---")
for sz = 0, 0x100, 0x10 do
  local buf = memory.alloc(0x100)
  -- Fill with 0xAA
  for i = 0, 0xFF do memory.write_byte(buf + i, 0xAA) end
  local ret, _ = run_sc(638, buf, sz, 0, 0)
  
  -- Check for modifications
  local modified_bytes = {}
  for i = 0, 0x3F do
    local b = to_num(memory.read_byte(buf + i))
    if b ~= 0xAA then
      table.insert(modified_bytes, {off=i, val=b})
    end
  end
  
  if #modified_bytes > 0 then
    print(string.format("  sz=0x%x ret=0x%x: %d bytes modified", sz, ret, #modified_bytes))
    for _, mb in ipairs(modified_bytes) do
      print(string.format("    [+0x%x] = 0x%02x (%s)", mb.off, mb.val, 
        mb.val >= 32 and mb.val < 127 and string.char(mb.val) or "."))
    end
  else
    print(string.format("  sz=0x%x ret=0x%x: no changes", sz, ret))
  end
end

-- Test SC657 with buffer + sizes
print("\n=== SC657: Buffer+Size Fuzz ===")
for _, p in ipairs(pats_638) do
  local ret, status = run_sc(657, p.buf or p.sz, p.buf and p.sz or 0, p.a3, p.a4)
  print(string.format("  %20s -> ret=0x%x (%s)", p.name, ret, status))
end

-- Check if SC657 modifies buffer
print("\n--- SC657 buffer content check ---")
for sz = 0, 0x100, 0x10 do
  local buf = memory.alloc(0x100)
  for i = 0, 0xFF do memory.write_byte(buf + i, 0xAA) end
  local ret, _ = run_sc(657, buf, sz, 0, 0)
  
  local modified_bytes = {}
  for i = 0, 0x7F do
    local b = to_num(memory.read_byte(buf + i))
    if b ~= 0xAA then
      table.insert(modified_bytes, {off=i, val=b})
    end
  end
  
  if #modified_bytes > 0 then
    print(string.format("  sz=0x%x ret=0x%x: %d bytes modified", sz, ret, #modified_bytes))
    for _, mb in ipairs(modified_bytes) do
      print(string.format("    [+0x%x] = 0x%02x (%s)", mb.off, mb.val, 
        mb.val >= 32 and mb.val < 127 and string.char(mb.val) or "."))
    end
  else
    print(string.format("  sz=0x%x ret=0x%x: no changes", sz, ret))
  end
end

-- Test crash conditions
print("\n=== Edge case tests ===")
local edge_cases = {
  {name="null buf", sc=638, args={0, 0x40, 0, 0}},
  {name="null buf2", sc=657, args={0, 0x40, 0, 0}},
  {name="kptr buf", sc=638, args={0xFFFFFFFF80000000, 0x40, 0, 0}},
  {name="kptr buf2", sc=657, args={0xFFFFFFFF80000000, 0x40, 0, 0}},
  {name="huge sz", sc=638, args={memory.alloc(0x10), 0x7FFFFFFF, 0, 0}},
  {name="huge sz2", sc=657, args={memory.alloc(0x10), 0x7FFFFFFF, 0, 0}},
  {name="neg sz", sc=638, args={memory.alloc(0x10), -1, 0, 0}},
  {name="neg sz2", sc=657, args={memory.alloc(0x10), -1, 0, 0}},
  {name="a3=dee", sc=638, args={0, 0, 0xdee, 0}},
  {name="a3=dee2", sc=657, args={0, 0, 0xdee, 0}},
}

for _, ec in ipairs(edge_cases) do
  local ret, status = run_sc(ec.sc, ec.args[1], ec.args[2], ec.args[3], ec.args[4])
  print(string.format("  SC%03d %15s -> ret=0x%x (%s)", ec.sc, ec.name, ret, status))
end

-- Also test SC600-SC677 for completeness 
print("\n=== Quick scan SC600-SC677 ===")
for num = 600, 677 do
  local ret, status = run_sc(num, 0, 0, 0, 0)
  if ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= -1 and ret ~= 0 then
    print(string.format("  SC%03d (zero): 0x%x <-- INTERESTING", num, ret))
  end
end

-- Test with buffer+size for all
print("\n=== SC600-SC677 with buf+0x40 ===")
for num = 600, 677 do
  local buf = memory.alloc(0x40)
  local ret, status = run_sc(num, buf, 0x40, 0, 0)
  if ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= -1 then
    print(string.format("  SC%03d (buf): ret=0x%x", num, ret))
  end
end

print("\n[+] Done")
