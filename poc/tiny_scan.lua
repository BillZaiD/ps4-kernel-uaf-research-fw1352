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

local wrapper = toaddr(S.syscall_wrapper[454])
print(string.format("w=0x%x", wrapper))

local c = 0
for off = 0, 0x2000, 8 do
    local v = tonn(mem.read_qword(wrapper + off))
    if is_kptr(v) then
        c = c + 1
        if c <= 15 then
            print(string.format("+%x %x", off, v))
        end
    end
end
print(string.format("c=%d", c))
print("ok")
