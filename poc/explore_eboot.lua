-- Explore eboot.bin in memory
local EBOOT_BASE = 0x13600000

-- Read and parse ELF header
local function read_elf_header(base)
  local ident = memory.read_buffer(base, 16)
  local e_type = memory.read_word(base + 16)
  local e_machine = memory.read_word(base + 18)
  local e_version = memory.read_dword(base + 20)
  local e_entry = memory.read_qword(base + 24)
  local e_phoff = memory.read_qword(base + 32)
  local e_shoff = memory.read_qword(base + 40)
  local e_flags = memory.read_dword(base + 48)
  local e_ehsize = memory.read_word(base + 52)
  local e_phentsize = memory.read_word(base + 54)
  local e_phnum = memory.read_word(base + 56)
  local e_shentsize = memory.read_word(base + 58)
  local e_shnum = memory.read_word(base + 60)
  local e_shstrndx = memory.read_word(base + 62)
  
  print(string.format("ELF Header at 0x%x:", base))
  print(string.format("  Entry: 0x%x", uint64(e_entry):tonumber()))
  print(string.format("  e_type: %d, e_machine: %d", uint64(e_type):tonumber(), uint64(e_machine):tonumber()))
  print(string.format("  e_phoff: 0x%x (%d entries, size %d)", uint64(e_phoff):tonumber(), uint64(e_phnum):tonumber(), uint64(e_phentsize):tonumber()))
  print(string.format("  e_shoff: 0x%x (%d entries, size %d)", uint64(e_shoff):tonumber(), uint64(e_shnum):tonumber(), uint64(e_shentsize):tonumber()))
  
  -- Read program headers
  local phoff = uint64(e_phoff):tonumber()
  local phnum = uint64(e_phnum):tonumber()
  local phentsize = uint64(e_phentsize):tonumber()
  
  print(string.format("\n=== Program Headers (%d entries) ===", phnum))
  for i = 0, phnum - 1 do
    local offset = base + phoff + i * phentsize
    local p_type = memory.read_dword(offset)
    local p_flags = memory.read_dword(offset + 4)
    local p_offset = memory.read_qword(offset + 8)
    local p_vaddr = memory.read_qword(offset + 16)
    local p_paddr = memory.read_qword(offset + 24)
    local p_filesz = memory.read_qword(offset + 32)
    local p_memsz = memory.read_qword(offset + 40)
    local p_align = memory.read_qword(offset + 48)
    
    if uint64(p_type):tonumber() ~= 0x6474e550 then  -- skip PT_GNU_EH_FRAME
      print(string.format("  [%d] type=0x%x flags=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x align=0x%x",
        i, uint64(p_type):tonumber(), uint64(p_flags):tonumber(),
        uint64(p_vaddr):tonumber(), uint64(p_filesz):tonumber(),
        uint64(p_memsz):tonumber(), uint64(p_align):tonumber()))
    end
  end
  
  return e_entry, e_phoff, e_phnum, e_phentsize
end

local function read_string(base, offset, maxlen)
  maxlen = maxlen or 256
  local s = ""
  for i = 0, maxlen - 1 do
    local b = memory.read_byte(base + offset + i)
    if b == 0 then break end
    s = s .. string.char(b)
  end
  return s
end

-- Read section headers for string table
local function read_section_strings(base, shoff, shnum, shentsize, shstrndx)
  if shstrndx == 0 or shnum == 0 then return {} end
  local shstrtab_off = shoff + shstrndx * shentsize
  local sh_offset = memory.read_qword(base + shstrtab_off + 24)
  local sh_size = memory.read_qword(base + shstrtab_off + 32)
  local sh_offset_num = uint64(sh_offset):tonumber()
  local sh_size_num = uint64(sh_size):tonumber()
  
  local strings = {}
  for i = 0, shnum - 1 do
    local sh_off = base + shoff + i * shentsize
    local sh_name_idx = memory.read_dword(sh_off)
    local idx = uint64(sh_name_idx):tonumber()
    if idx > 0 and idx < sh_size_num then
      strings[i] = read_string(base, sh_offset_num + idx, 64)
    end
  end
  return strings
end

local e_entry, e_phoff, e_phnum, e_phentsize = read_elf_header(EBOOT_BASE)

-- Get sections
local e_shoff_data = memory.read_qword(EBOOT_BASE + 40)
local e_shnum_data = memory.read_word(EBOOT_BASE + 60)
local e_shentsize_data = memory.read_word(EBOOT_BASE + 58)
local e_shstrndx_data = memory.read_word(EBOOT_BASE + 62)

local shoff = uint64(e_shoff_data):tonumber()
local shnum = uint64(e_shnum_data):tonumber()
local shentsize = uint64(e_shentsize_data):tonumber()
local shstrndx = uint64(e_shstrndx_data):tonumber()

print(string.format("\n=== Section Headers (%d entries) ===", shnum))
local section_names = read_section_strings(EBOOT_BASE, shoff, shnum, shentsize, shstrndx)

for i = 0, shnum - 1 do
  local sh_off = EBOOT_BASE + shoff + i * shentsize
  local sh_name = memory.read_dword(sh_off)
  local sh_type = memory.read_dword(sh_off + 4)
  local sh_flags = memory.read_qword(sh_off + 8)
  local sh_addr = memory.read_qword(sh_off + 16)
  local sh_offset_file = memory.read_qword(sh_off + 24)
  local sh_size = memory.read_qword(sh_off + 32)
  local sh_addralign = memory.read_qword(sh_off + 48)
  
  local name = section_names[i] or string.format("(idx %d)", uint64(sh_name):tonumber())
  local type_num = uint64(sh_type):tonumber()
  local addr_num = uint64(sh_addr):tonumber()
  local size_num = uint64(sh_size):tonumber()
  
  if size_num > 0 then
    print(string.format("  [%d] %20s type=0x%04x addr=0x%x size=0x%x", i, name, type_num, addr_num, size_num))
  end
end

print("[+] Done")
