-- Recalculate eboot base from luaB_auxwrap
local luaB = uint64(eboot_addrofs.luaB_auxwrap):tonumber()
-- Guess offset: compare to known offsets
local known_offsets = {0x1a7bb0, 0x1aeb90, 0x1ad170, 0x1a7420, 0x1a75d0, 0x195280, 0x19f600, 0x1aed80, 0x1A0660, 0x1BBB10, 0x1bd410, 0x1A12E0}

local eboot_base = nil
for _, off in ipairs(known_offsets) do
  local candidate = luaB - off
    if candidate % 0x1000 == 0 then  -- page-aligned
    eboot_base = candidate
    print(string.format("EBOOT BASE found: 0x%x (offset 0x%x)", eboot_base, off))
    break
  end
end

if not eboot_base then
  -- Try all offsets and find the one that gives page-aligned result
  for _, off in ipairs(known_offsets) do
    local candidate = luaB - off
    if candidate % 0x1000 == 0 then
      eboot_base = candidate
      print(string.format("EBOOT BASE: 0x%x (offset 0x%x, page-aligned)", eboot_base, off))
      break
    end
  end
end

if not eboot_base then
  print("Could not find eboot base! luaB_auxwrap = 0x" .. string.format("%x", luaB))
  return
end

-- Now read the ELF header
print(string.format("\n=== ELF HEADER at 0x%x ===", eboot_base))

-- Use pcall for all reads in case of invalid addresses
local function safe_read_byte(addr)
  local ok, v = pcall(memory.read_byte, addr)
  return ok and v or nil
end

local function safe_read_word(addr)
  local ok, v = pcall(memory.read_word, addr)
  if ok and v then return uint64(v):tonumber() end
  return nil
end

local function safe_read_dword(addr)
  local ok, v = pcall(memory.read_dword, addr)  
  if ok and v then return uint64(v):tonumber() end
  return nil
end

local function safe_read_qword(addr)
  local ok, v = pcall(memory.read_qword, addr)
  if ok and v then return uint64(v):tonumber() end
  return nil
end

-- Read ELF ident
local b0 = safe_read_byte(eboot_base + 0)
local b1 = safe_read_byte(eboot_base + 1)
local b2 = safe_read_byte(eboot_base + 2)
local b3 = safe_read_byte(eboot_base + 3)

if not b0 or b0 ~= 0x7f or not b1 or b1 ~= 0x45 or not b2 or b2 ~= 0x4c or not b3 or b3 ~= 0x46 then
  print(string.format("  NOT an ELF! Bytes: %s %s %s %s", tostring(b0), tostring(b1), tostring(b2), tostring(b3)))
  print("  Raw bytes at base:")
  for i = 0, 31 do
    local b = safe_read_byte(eboot_base + i)
    io.write(string.format("%02x ", b or 0))
    if i % 16 == 15 then io.write("\n") end
  end
  io.write("\n")
  return
end

print(string.format("  Magic: %02x %02x %02x %02x", b0, b1, b2, b3))

local e_ident_4 = safe_read_byte(eboot_base + 4)
local e_ident_5 = safe_read_byte(eboot_base + 5)
local e_ident_6 = safe_read_byte(eboot_base + 6)
local e_ident_7 = safe_read_byte(eboot_base + 7)
local e_ident_8 = safe_read_byte(eboot_base + 8)
print(string.format("  Class: %s, Data: %s, Version: %d, OS/ABI: %d, ABI Version: %d",
  e_ident_4 == 2 and "ELF64" or "ELF32", e_ident_5 == 1 and "Little Endian" or "Big Endian",
  e_ident_6 or 0, e_ident_7 or 0, e_ident_8 or 0))

local e_type = safe_read_word(eboot_base + 16)
local e_machine = safe_read_word(eboot_base + 18)
local e_version = safe_read_dword(eboot_base + 20)
local e_entry = safe_read_qword(eboot_base + 24)
local e_phoff = safe_read_qword(eboot_base + 32)
local e_shoff = safe_read_qword(eboot_base + 40)
local e_flags = safe_read_dword(eboot_base + 48)
local e_ehsize = safe_read_word(eboot_base + 52)
local e_phentsize = safe_read_word(eboot_base + 54)
local e_phnum = safe_read_word(eboot_base + 56)
local e_shentsize = safe_read_word(eboot_base + 58)
local e_shnum = safe_read_word(eboot_base + 60)
local e_shstrndx = safe_read_word(eboot_base + 62)

print(string.format("  Type: %d, Machine: %d (x86_64=%d), Entry: 0x%x", e_type, e_machine, 62, e_entry))
print(string.format("  Program headers: %d at 0x%x (size %d each)", e_phnum, e_phoff, e_phentsize))
print(string.format("  Section headers: %d at 0x%x (size %d each)", e_shnum, e_shoff, e_shentsize))

-- Read section string table
local function read_str(base, off, maxlen)
  maxlen = maxlen or 128
  local s = ""
  for i = 0, maxlen - 1 do
    local b = safe_read_byte(base + off + i)
    if not b or b == 0 then break end
    s = s .. string.char(b)
  end
  return s
end

local shstrtab_addr = 0
local shstrtab_size = 0
if e_shstrndx and e_shentsize and e_shoff then
  local shstr_hdr_base = e_shoff + e_shstrndx * e_shentsize
  shstrtab_addr = safe_read_qword(eboot_base + shstr_hdr_base + 24) or 0
  shstrtab_size = safe_read_qword(eboot_base + shstr_hdr_base + 32) or 0
  print(string.format("Section string table: at 0x%x (%d bytes)", shstrtab_addr, shstrtab_size))
end

-- Read section names
local section_names = {}
for i = 0, (e_shnum or 0) - 1 do
  local sh_off = (e_shoff or 0) + i * (e_shentsize or 0x40)
  local sh_name_idx = safe_read_dword(eboot_base + sh_off) or 0
  local sh_name = shstrtab_addr > 0 and read_str(eboot_base + shstrtab_addr, sh_name_idx, 64) or ""
  local sh_type = safe_read_dword(eboot_base + sh_off + 4) or 0
  local sh_flags = safe_read_qword(eboot_base + sh_off + 8) or 0
  local sh_addr = safe_read_qword(eboot_base + sh_off + 16) or 0
  local sh_offset = safe_read_qword(eboot_base + sh_off + 24) or 0
  local sh_size = safe_read_qword(eboot_base + sh_off + 32) or 0
  local sh_entsize = safe_read_qword(eboot_base + sh_off + 56) or 0
  
  section_names[i] = {
    name = sh_name, type = sh_type, flags = sh_flags,
    addr = sh_addr, offset = sh_offset, size = sh_size, entsize = sh_entsize
  }
end

-- Find interesting sections
local text_section = nil
local rodata_section = nil
local data_section = nil
local plt_section = nil

print("\n=== Interesting Sections ===")
for i = 0, (e_shnum or 0) - 1 do
  local s = section_names[i]
  if s and s.size > 0 then
    if s.name:find(".text") then text_section = s end
    if s.name:find(".rodata") then rodata_section = s end
    if s.name:find(".data") and not s.name:find("rel") then data_section = s end
    if s.name:find(".plt") then plt_section = s end
    
    if s.size > 0x1000 or s.name:find("text") or s.name:find("rodata") or s.name:find("data") or s.name:find("plt") or s.name:find("init") then
      print(string.format("  [%s] addr=0x%x size=0x%x flags=0x%x",
        s.name, s.addr, s.size, s.flags))
    end
  end
end

-- Read .rodata strings for interesting content
if rodata_section and rodata_section.size < 0x100000 and rodata_section.size > 0 then
  print(string.format("\n=== Scanning .rodata for interesting strings (0x%x bytes) ===", rodata_section.size))
  local rodata_base = eboot_base + rodata_section.addr
  local str = ""
  local found = {}
  for i = 0, rodata_section.size - 1 do
    local b = safe_read_byte(rodata_base + i)
    if not b then break end
    if b >= 32 and b < 127 then
      str = str .. string.char(b)
    else
      if #str >= 4 then
        local sl = str:lower()
        if sl:find("syscall") or sl:find("ioctl") or sl:find("debug") or sl:find("dev") or sl:find("kernel") or sl:find("exploit") or sl:find("dma") or sl:find("prx") or sl:find("rpc") or sl:find("http") or sl:find("socket") or sl:find("server") or sl:find("port") or sl:find("cmd") or sl:find("shell") or sl:find("backdoor") or sl:find("test") then
          table.insert(found, str)
        end
      end
      str = ""
    end
    if #found >= 50 then break end
  end
  if #found > 0 then
    print("  Interesting strings found:")
    for _, s in ipairs(found) do
      print("    " .. s)
    end
  else
    print("  No interesting strings found")
  end
end

-- Check for dynamic sections
print("\n=== Dynamic symbols summary ===")
for i = 0, (e_shnum or 0) - 1 do
  local s = section_names[i]
  if s and (s.name:find("dyn") or s.name:find("plt") or s.name:find("got")) and s.size > 0 then
    print(string.format("  [%s] addr=0x%x size=0x%x", s.name, s.addr, s.size))
  end
end

print("\n[+] Done")
