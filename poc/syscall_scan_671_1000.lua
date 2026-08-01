local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")

S.resolve({close=6, getpid=20})

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

local function find_tramp(w)
    for i = 0, 35 do
        if tonn(mem.read_byte(w+i))==0x49 and tonn(mem.read_byte(w+i+1))==0x89 and tonn(mem.read_byte(w+i+2))==0xCA then
            return i
        end
    end
    return 7
end

print(string.format("[+] Scanning syscall_wrapper[671..1000]\n"))

local found_any = false
for N = 671, 1000 do
    local w = toaddr(S.syscall_wrapper[N])
    if w ~= 0 then
        found_any = true
        local tramp = w + find_tramp(w)
        print(string.format("[+] sc%d wrapper at 0x%x, tramp at 0x%x", N, w, tramp))
        local ok, r = pcall(function()
            return tonn(nat.fcall_with_rax(tramp, N, 0, 0, 0, 0, 0, 0))
        end)
        if ok then
            if r ~= -1 then
                print(string.format("  [!] sc%d returned %d [NON -1]", N, r))
            end
        else
            print(string.format("  [E] sc%d pcall error: %s", N, tostring(r)))
        end
    end
end

if not found_any then
    print("[-] No wrappers found in range 671-1000")
end

print("\n[+] Scan complete")
