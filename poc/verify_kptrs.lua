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

local wrapper = toaddr(S.syscall_wrapper[454])

-- Read the kernel-looking pointers from the known offsets
local offsets = {0x1b8, 0x238, 0x248, 0x280, 0x348, 0x3a8}
for _, off in ipairs(offsets) do
    local kaddr = tonn(mem.read_qword(wrapper + off))
    print(string.format("wrapper+%x = 0x%x", off, kaddr))
    
    -- Try to READ from that address
    local ok, val = pcall(function()
        return tonn(mem.read_qword(kaddr))
    end)
    if ok then
        print(string.format("  -> [0x%x] = 0x%x", kaddr, val))
    else
        print("  -> read FAILED (unmapped)")
    end
end
print("done")
