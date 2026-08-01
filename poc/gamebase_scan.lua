--[[
    gamebase_scan.lua
    Find game base from syscall_wrapper address and scan for kernel pointers
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

print("[+] Game base scan\n")

-- Step 1: Get a known address in the game's code
local wrapper_addr = toaddr(S.syscall_wrapper[454])
print(string.format("  syscall_wrapper[454] = 0x%x", wrapper_addr))

-- Step 2: Scan backward to find ELF header (starts with 0x7F 0x45 0x4C 0x46 = \x7fELF)
-- Align to page boundary
local page_align = wrapper_addr - (wrapper_addr % 4096)
print(string.format("  Page-aligned addr: 0x%x\n", page_align))

-- Search backward for ELF magic
local elf_base = 0
local search_start = wrapper_addr - 0x400000  -- search up to 4MB back
if search_start < 0 then search_start = 0 end

print("[*] Searching for ELF header...\n")
for addr = wrapper_addr, search_start, -4096 do
    local magic = tonn(mem.read_dword(addr))
    if magic == 0x464C457F then  -- \x7FELF in LE
        elf_base = addr
        break
    end
end

if elf_base ~= 0 then
    print(string.format("  [!] ELF base = 0x%x\n", elf_base))
    
    -- Read ELF header fields
    local e_type = tonn(mem.read_word(elf_base + 16))
    local e_machine = tonn(mem.read_word(elf_base + 18))
    local e_phoff = tonn(mem.read_qword(elf_base + 32))
    local e_shoff = tonn(mem.read_qword(elf_base + 40))
    local e_flags = tonn(mem.read_dword(elf_base + 48))
    local e_ehsize = tonn(mem.read_word(elf_base + 52))
    local e_phentsize = tonn(mem.read_word(elf_base + 54))
    local e_phnum = tonn(mem.read_word(elf_base + 56))
    local e_shentsize = tonn(mem.read_word(elf_base + 58))
    local e_shnum = tonn(mem.read_word(elf_base + 60))
    
    print(string.format("  Type=%d Machine=%d Phoff=0x%x Shoff=0x%x", e_type, e_machine, e_phoff, e_shoff))
    print(string.format("  Phnum=%d Phentsize=%d Shnum=%d Shentsize=%d\n", e_phnum, e_phentsize, e_shnum, e_shentsize))
    
    -- Step 3: Scan program headers for PT_DYNAMIC (.dynamic section)
    print("[*] Scanning program headers...\n")
    for i = 0, e_phnum - 1 do
        local ph = elf_base + e_phoff + i * e_phentsize
        local p_type = tonn(mem.read_dword(ph))
        local p_flags = tonn(mem.read_dword(ph + 4))
        local p_offset = tonn(mem.read_qword(ph + 8))
        local p_vaddr = tonn(mem.read_qword(ph + 16))
        local p_paddr = tonn(mem.read_qword(ph + 24))
        local p_filesz = tonn(mem.read_qword(ph + 32))
        local p_memsz = tonn(mem.read_qword(ph + 40))
        local p_align = tonn(mem.read_qword(ph + 48))
        
        if p_type == 2 then  -- PT_DYNAMIC
            print(string.format("  PT_DYNAMIC: vaddr=0x%x memsz=0x%x flags=0x%x", p_vaddr, p_memsz, p_flags))
            
            -- Step 4: Scan dynamic section for DT_JMPREL (PLT relocations) and DT_SYMTAB
            local dynamic = p_vaddr
            for j = 0, p_memsz - 1, 16 do
                local d_tag = tonn(mem.read_qword(dynamic + j))
                local d_val = tonn(mem.read_qword(dynamic + j + 8))
                
                if d_tag == 3 then  -- DT_PLTGOT
                    print(string.format("    DT_PLTGOT = 0x%x", d_val))
                elseif d_tag == 23 then  -- DT_JMPREL
                    print(string.format("    DT_JMPREL = 0x%x", d_val))
                elseif d_tag == 2 then  -- DT_PLTRELSZ
                    print(string.format("    DT_PLTRELSZ = 0x%x", d_val))
                elseif d_tag == 6 then  -- DT_SYMTAB
                    print(string.format("    DT_SYMTAB = 0x%x", d_val))
                elseif d_tag == 5 then  -- DT_STRTAB
                    print(string.format("    DT_STRTAB = 0x%x", d_val))
                elseif d_tag == 10 then  -- DT_STRSZ
                    print(string.format("    DT_STRSZ = 0x%x", d_val))
                end
            end
            
            -- Step 5: Read GOT entries and check for kernel pointers
            -- Find DT_PLTGOT
            local pltgot = 0
            for j = 0, p_memsz - 1, 16 do
                local d_tag = tonn(mem.read_qword(dynamic + j))
                local d_val = tonn(mem.read_qword(dynamic + j + 8))
                if d_tag == 3 then
                    pltgot = d_val
                    break
                end
            end
            
            if pltgot ~= 0 then
                print(string.format("\n    GOT at 0x%x, scanning for kernel pointers...\n", pltgot))
                local kptrs = 0
                for j = 0, 1023, 8 do  -- scan first 1KB of GOT
                    local v = tonn(mem.read_qword(pltgot + j))
                    if is_kptr(v) then
                        kptrs = kptrs + 1
                        if kptrs <= 20 then
                            print(string.format("      GOT[%d] = 0x%x", j/8, v))
                        end
                    end
                end
                if kptrs == 0 then
                    print("      No kernel pointers found in GOT")
                else
                    print(string.format("      Total: %d kernel pointers in GOT", kptrs))
                end
            end
        end
    end
else
    print("  ELF header not found in range\n")
end

-- Step 6: Also try scanning around wrapper_addr for kernel ptrs
print("\n[*] Scanning around syscall wrapper for kernel pointers...\n")
local kptrs2 = 0
for off = -0x10000, 0x10000, 8 do
    local v = tonn(mem.read_qword(wrapper_addr + off))
    if is_kptr(v) then
        kptrs2 = kptrs2 + 1
        if kptrs2 <= 10 then
            print(string.format("  0x%x: 0x%x", wrapper_addr + off, v))
        end
    end
end
print(string.format("  Total kernel ptrs near wrapper: %d", kptrs2))

print("\n[+] Done")
