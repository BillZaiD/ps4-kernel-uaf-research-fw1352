-- Read critical debug sysctls one at a time
print("=== Debug sysctl check ===\n")

local function read_sysctl(name)
    local buf = memory.alloc(256)
    local buf_size = memory.alloc(8)
    memory.write_qword(buf_size, 256)
    
    local ok = sysctlbyname(name, buf, buf_size, nil, 0)
    if ok then
        local size = memory.read_qword(buf_size):tonumber()
        local val = memory.read_buffer(buf, math.min(size, 256))
        return val
    end
    return nil
end

local function read_as_num(name)
    local val = read_sysctl(name)
    if val and #val >= 1 then
        local num = 0
        for i = 1, math.min(#val, 8) do
            num = num + string.byte(val, i) * 256^(i-1)
        end
        return num
    end
    return nil
end

local function read_as_str(name)
    local val = read_sysctl(name)
    if val then
        local null_pos = val:find("\0")
        if null_pos then val = val:sub(1, null_pos - 1) end
        return val
    end
    return nil
end

-- Read each sysctl
local checks = {
    {"kern.sdk_version", "num"},
    {"kern.cpumode", "num"},
    {"kern.cpumode_game", "num"},
    {"machdep.idps", "str"},
    {"machdep.curr_manumode", "num"},
    {"machdep.openpsid", "str"},
    {"machdep.rcmgr_sl_debugger", "num"},
    {"machdep.rcmgr_debug_menu", "num"},
    {"machdep.rcmgr_debug_menu_for_psm", "num"},
    {"machdep.rcmgr_debug_menu_mini", "num"},
    {"machdep.rcmgr_flaged_updater", "num"},
    {"machdep.rcmgr_force_update", "num"},
    {"machdep.rcmgr_intdev", "num"},
    {"machdep.rcmgr_psm_intdev", "num"},
}

for _, c in ipairs(checks) do
    local name, typ = c[1], c[2]
    local val
    if typ == "num" then
        val = read_as_num(name)
    else
        val = read_as_str(name)
    end
    
    if val ~= nil then
        if typ == "num" then
            print(string.format("  %s = %d (0x%x)", name, val, val))
        else
            print(string.format("  %s = '%s'", name, val:gsub("[^%w%p%s]", ".")))
        end
    else
        print(string.format("  %s = (unreadable)", name))
    end
end

print("\nDone!")
return "ok"
