-- test just a few key sysctls
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local buf = memory.alloc(0x100)
local size = memory.alloc(0x8)

local tests = {"machdep.rcmgr_debug_menu","machdep.idps","machdep.tsc_freq","kern.ostype"}
for _, name in ipairs(tests) do
    memory.write_qword(size, 0x100)
    local ok = sysctlbyname(name, buf, size, 0, 0)
    if ok then
        local len = tonn(memory.read_qword(size))
        local val = memory.read_buffer(buf, len)
        print(name .. "=" .. val)
    else
        print(name .. "=ERR")
    end
end
