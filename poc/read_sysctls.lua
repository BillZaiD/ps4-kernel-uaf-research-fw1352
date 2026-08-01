-- read machdep.rcmgr sysctls
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local sysctls = {
    "machdep.rcmgr_intdev", "machdep.rcmgr_psm_intdev",
    "machdep.rcmgr_sl_debugger", "machdep.rcmgr_debug_menu",
    "machdep.rcmgr_debug_menu_for_psm", "machdep.rcmgr_debug_menu_mini",
    "machdep.rcmgr_flaged_updater", "machdep.rcmgr_force_update",
    "machdep.rcmgr_special_i", "machdep.rcmgr_fake_finalize",
    "machdep.rcmgr_psn_access_trace_log", "machdep.rcmgr_beta_update_test",
    "machdep.rcmgr_utoken_store_mode", "machdep.rcmgr_utoken_data_execution",
    "machdep.rcmgr_utoken_weakened_port_restriction",
    "machdep.rcmgr_utoken_flaged_updater", "machdep.rcmgr_utoken_np_env_switching",
    "machdep.rcmgr_utoken_save_data_repair", "machdep.rcmgr_utoken_fake_sharefactory",
    "machdep.rcmgr_utoken_use_softwagner",
    "machdep.rcmgr_qaf_generation", "machdep.rcmgr_qaf_name",
    "machdep.upd_version", "machdep.system_ex_version",
    "machdep.cpumode_platform", "machdep.bootparams.base_ps4_mode",
    "machdep.tsc_freq",
}

local buf = memory.alloc(0x100)
local size = memory.alloc(0x8)

for _, name in ipairs(sysctls) do
    memory.write_qword(size, 0x100)
    local ok = sysctlbyname(name, buf, size, 0, 0)
    if ok then
        local len = tonn(memory.read_qword(size))
        local val = memory.read_buffer(buf, len)
        local ascii = ""
        for i = 1, #val do
            local c = string.byte(val, i)
            if c >= 32 and c <= 126 then
                ascii = ascii .. string.char(c)
            else
                ascii = ascii .. string.format("\\x%02x", c)
            end
        end
        print(name .. "=" .. ascii)
    else
        print(name .. "=ERR")
    end
end
