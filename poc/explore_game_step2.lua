-- Step 2: Find game binary in memory
-- We know libkernel is at 0x813758000

local libkernel_base = 0x813758000

-- Check if ELF magic at an address
local function check_elf(base)
  local ok, magic = pcall(memory.read_qword, base)
  if ok and magic then
    -- Check for ELF magic: 0x7f 'E' 'L' 'F'
    local b0 = memory.read_byte(base)
    local b1 = memory.read_byte(base+1)
    local b2 = memory.read_byte(base+2)
    local b3 = memory.read_byte(base+3)
    if b0 == 0x7f and b1 == 0x45 and b2 == 0x4c and b3 == 0x46 then
      return true
    end
  end
  return false
end

-- Common PS4 game base addresses
local candidates = {
  0x400000,    -- Standard ELF base
  0x1000000,   -- Alternative base
  0x200000,    -- Small base
  0x800000,    -- Medium base
  0x10000000,  -- Large base
  0x600000,    -- Another common base
  0x813700000, -- Near libkernel
  0x813000000, -- Below libkernel
  0x800000000, -- Base region
  0x810000000, -- Module region
}

print("=== Searching for ELF headers ===")
for _, addr in ipairs(candidates) do
  local found = check_elf(addr)
  print(string.format("  0x%x: %s", addr, found and "ELF FOUND!" or "not found"))
end

-- Also try scanning around common regions
print("=== Scan around modules area (0x810000000 - 0x818000000) ===")
local step = 0x10000  -- 64KB steps
for base = 0x810000000, 0x818000000, step do
  if check_elf(base) then
    print(string.format("  ELF FOUND at 0x%x!", base))
    break
  end
end

-- Check known libkernel region
print("=== Check near libkernel ===")
for base = libkernel_base - 0x20000000, libkernel_base + 0x20000000, 0x100000 do
  if check_elf(base) then
    print(string.format("  ELF FOUND at 0x%x (offset from libkernel: %+d)", base, base - libkernel_base))
    break
  end
end

-- Try reading next to libkernel
print("=== Adjacent to libkernel ===")
for i = -0x20, 0x20 do
  local addr = libkernel_base + i * 0x1000
  local b0 = memory.read_byte(addr)
  local b1 = memory.read_byte(addr+1)
  local b2 = memory.read_byte(addr+2)
  local b3 = memory.read_byte(addr+3)
  if b0 == 0x7f and b1 == 0x45 and b2 == 0x4c and b3 == 0x46 then
    print(string.format("  ELF at 0x%x (offset %+d pages)!", addr, i))
  end
end

print("[+] Done scanning")
