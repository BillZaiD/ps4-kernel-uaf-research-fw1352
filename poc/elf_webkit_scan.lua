--[[
    elf_webkit_scan.lua
    Find ELF base, scan GOT, detect WebKit
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
    return v >= 0xFFFF800000000000 and v <= 0xFFFFFFFFFFFFFFFF
end

local function safe_read(addr, sz)
    local ok, res = pcall(function()
        if sz == 8 then return tonn(mem.read_qword(addr))
        elseif sz == 4 then return tonn(mem.read_dword(addr))
        elseif sz == 2 then return tonn(mem.read_word(addr))
        elseif sz == 1 then return tonn(mem.read_byte(addr))
        end
    end)
    if ok then return res, true end
    return 0, false
end

local function read_str(addr, maxlen)
    local s = ""
    for i = 0, maxlen do
        local c, ok = safe_read(addr + i, 1)
        if not ok or c == 0 then break end
        s = s .. string.char(c)
    end
    return s
end

print("[+] ELF / WebKit / GOT Scanner\n")

S.resolve({close=6, getpid=20})

local wrapper_addr = toaddr(S.syscall_wrapper[454])
print(string.format("  syscall_wrapper[454] = 0x%x\n", wrapper_addr))

-- Find ELF base
print("[*] Searching for ELF header...\n")

local elf_base = 0
for off = 0, -0x100000, -4096 do
    local addr = wrapper_addr + off
    local magic, ok = safe_read(addr, 4)
    if not ok then break end
    if magic == 0x464C457F then
        elf_base = addr
        break
    end
end

if elf_base == 0 then
    print("  [X] ELF header not found\n")
    return
end

print(string.format("  [OK] ELF base = 0x%x\n", elf_base))

local e_phoff = tonn(mem.read_qword(elf_base + 32))
local e_phnum = tonn(mem.read_word(elf_base + 56))
local e_phentsize = tonn(mem.read_word(elf_base + 54))

-- Find PT_DYNAMIC
local dynamic_addr = 0
for i = 0, e_phnum - 1 do
    local ph = elf_base + e_phoff + i * e_phentsize
    local p_type = tonn(mem.read_dword(ph))
    local p_vaddr = tonn(mem.read_qword(ph + 16))
    if p_type == 2 then
        dynamic_addr = p_vaddr
        break
    end
end

if dynamic_addr == 0 then
    print("  [X] No PT_DYNAMIC\n")
    return
end

print(string.format("  PT_DYNAMIC at 0x%x\n", dynamic_addr))

-- Parse dynamic section
local pltgot, pltrelsz, jmprel, symtab, strtab, strsz = 0, 0, 0, 0, 0, 0
for j = 0, 4096, 16 do
    local d_tag = tonn(mem.read_qword(dynamic_addr + j))
    local d_val = tonn(mem.read_qword(dynamic_addr + j + 8))
    if d_tag == 0 then break end
    if d_tag == 3 then pltgot = d_val
    elseif d_tag == 23 then jmprel = d_val
    elseif d_tag == 2 then pltrelsz = d_val
    elseif d_tag == 6 then symtab = d_val
    elseif d_tag == 5 then strtab = d_val
    elseif d_tag == 10 then strsz = d_val
    end
end

print(string.format("  PLTGOT=0x%x JMPREL=0x%x PLTRELSZ=0x%x\n", pltgot, jmprel, pltrelsz))
print(string.format("  SYMTAB=0x%x STRTAB=0x%x STRSZ=%d\n", symtab, strtab, strsz))

-- Read SONAME from string table
if strtab ~= 0 then
    local soname = read_str(strtab, strsz)
    print(string.format("  SONAME: %s\n", soname))
end

-- Scan GOT for kernel pointers
if pltgot ~= 0 and pltrelsz > 0 then
    print("  [*] GOT kernel pointer scan:\n")
    local kcount = 0
    local limit = pltrelsz
    if limit > 4096 then limit = 4096 end
    for j = 0, limit - 1, 8 do
        local v, ok = safe_read(pltgot + j, 8)
        if not ok then break end
        if is_kptr(v) then
            kcount = kcount + 1
            print(string.format("    GOT[%d] = 0x%x", j/8, v))
        end
    end
    if kcount == 0 then
        print("    No kernel pointers (lazy binding)\n")
    else
        print(string.format("\n    Total: %d\n", kcount))
    end
end

-- Scan for WebKit-related strings in .rodata (scan first ~64KB)
print("\n[*] Scanning ELF for WebKit references...\n")

local webkit_strs = {"WebKit", "webkit", "WebCore", "JavaScriptCore", "Safari", "WTF"}
local found_wk = {}

-- Scan first 256KB of ELF for strings
for off = 0, 0x40000, 1 do
    local c, ok = safe_read(elf_base + off, 1)
    if not ok then break end
    if c >= 65 and c <= 90 then  -- uppercase letter
        local s = read_str(elf_base + off, 32)
        if #s >= 4 then
            for _, pat in ipairs(webkit_strs) do
                if string.find(s, pat) and not found_wk[pat] then
                    found_wk[pat] = true
                    print(string.format("  Found '%s' at 0x%x: '%s'", pat, elf_base + off, s))
                end
            end
        end
    end
end

if next(found_wk) == nil then
    print("  No WebKit references in libkernel\n")
end

-- List loaded library names from strtab
print("\n[*] Library dependencies from .dynamic:\n")

-- Read DT_NEEDED entries
for j = 0, 4096, 16 do
    local d_tag = tonn(mem.read_qword(dynamic_addr + j))
    local d_val = tonn(mem.read_qword(dynamic_addr + j + 8))
    if d_tag == 0 then break end
    if d_tag == 1 and strtab ~= 0 then  -- DT_NEEDED
        local libname = read_str(strtab + d_val, 64)
        print(string.format("  NEEDED: %s", libname))
    end
end

print("\n[+] Complete")
