-- read one rcmgr sysctl
local mem = rawget(_G, "memory")
local buf = mem.alloc(0x100)
local sz = mem.alloc(8)
mem.write_qword(sz, 0x100)
local ok = sysctlbyname("machdep.rcmgr_debug_menu", buf, sz, 0, 0)
if ok then
    local rsz = mem.read_qword(sz)
    local len = 0
    if type(rsz) == "table" then len = rsz.l else len = tonumber(tostring(rsz)) or 0 end
    local v = mem.read_buffer(buf, len)
    local s = ""
    for i = 1, #v do
        local c = string.byte(v, i)
        if c >= 32 and c <= 126 then s = s .. string.char(c)
        else s = s .. string.format("\\x%02x", c) end
    end
    print("VAL:" .. s)
else
    print("ERR")
end
