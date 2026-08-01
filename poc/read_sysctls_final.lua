-- read debug sysctls safely
local mem = rawget(_G, "memory")
local buf = mem.alloc(0x100)
local sz = mem.alloc(8)

local function read_val(name)
    mem.write_qword(sz, 0x100)
    local ok = sysctlbyname(name, buf, sz, 0, 0)
    if not ok then return "ERR" end
    local rsz = mem.read_qword(sz)
    local len = 0
    if type(rsz) == "table" then len = rsz.l else len = tonumber(tostring(rsz)) or 0 end
    if len == 0 or len > 0x100 then return "BAD_LEN" end
    local v = mem.read_buffer(buf, len)
    local s = ""
    for i = 1, #v do
        local c = string.byte(v, i)
        if c >= 32 and c <= 126 then s = s .. string.char(c)
        else s = s .. string.format("\\x%02x", c) end
    end
    return s
end

print("kern.ostype=" .. read_val("kern.ostype"))
print("kern.osrelease=" .. read_val("kern.osrelease"))
print("machdep.tsc_freq=" .. read_val("machdep.tsc_freq"))
print("machdep.rcmgr_debug_menu=" .. read_val("machdep.rcmgr_debug_menu"))
print("machdep.rcmgr_sl_debugger=" .. read_val("machdep.rcmgr_sl_debugger"))
print("machdep.rcmgr_intdev=" .. read_val("machdep.rcmgr_intdev"))
