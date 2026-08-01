-- read debug-related sysctls only
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local buf = memory.alloc(0x100)
local size = memory.alloc(0x8)

local tests = {
    "machdep.rcmgr_debug_menu",
    "machdep.rcmgr_sl_debugger", 
    "machdep.rcmgr_intdev",
    "machdep.tsc_freq",
    "kern.ostype",
}

for _, name in ipairs(tests) do
    memory.write_qword(size, 0x100)
    local ok = sysctlbyname(name, buf, size, 0, 0)
    if ok then
        local len = tonn(memory.read_qword(size))
        local val = memory.read_buffer(buf, len)
        local ascii = ""
        for i = 1, #val do
            local c = string.byte(val, i)
            if c >= 32 and c <= 126 then ascii = ascii .. string.char(c)
            else ascii = ascii .. string.format("\\x%02x", c) end
        end
        print(name .. "=" .. ascii)
    else
        print(name .. "=ERR")
    end
end
