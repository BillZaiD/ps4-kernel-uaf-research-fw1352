-- Read interesting sysctls
print("=== Interesting sysctl read ===\n")

local sysctls = {
    "kern.sdk_version",
    "kern.cpumode",
    "kern.cpumode_game",
    "machdep.tsc_freq",
    "machdep.idps",
    "machdep.openpsid",
    "machdep.curr_manumode",
    "machdep.hwfeature_for_decid",
    "machdep.rcmgr_sl_debugger",
    "machdep.rcmgr_debug_menu",
    "machdep.rcmgr_debug_menu_for_psm",
    "machdep.rcmgr_debug_menu_mini",
    "machdep.rcmgr_flaged_updater",
    "machdep.rcmgr_force_update",
    "machdep.rcmgr_special_i",
    "machdep.rcmgr_fake_finalize",
    "machdep.rcmgr_psn_access_trace_log",
    "machdep.rcmgr_beta_update_test",
    "machdep.rcmgr_utoken_store_mode",
    "machdep.rcmgr_utoken_data_execution",
    "machdep.rcmgr_utoken_weakened_port_restriction",
    "machdep.rcmgr_utoken_flaged_updater",
    "machdep.rcmgr_utoken_np_env_switching",
    "machdep.rcmgr_utoken_save_data_repair",
    "machdep.rcmgr_utoken_fake_sharefactory",
    "machdep.rcmgr_utoken_use_softwagner",
    "machdep.rcmgr_utoken_notbefore",
    "machdep.rcmgr_utoken_notafter",
    "machdep.rcmgr_qaf_notbefore",
    "machdep.rcmgr_qaf_notafter",
    "machdep.rcmgr_qaf_generation",
    "machdep.rcmgr_qaf_name",
    "machdep.rcmgr_intdev",
    "machdep.rcmgr_psm_intdev",
    "hw.sce_subsys_subid",
    "kern.proc.ptc",
    "vm.budgets.mlock_avail",
    "vm.budgets.mlock_total",
    "kern.dmem.game_budget_limit",
    "vm.kern_heap_size",
}

-- Read sysctls using the raw syscall method
-- sysctl(name, namelen, oldp, oldlenp, newp, newlen)

for _, name in ipairs(sysctls) do
    local ok, result = pcall(function()
        return sysctlbyname(name)
    end)
    
    if ok then
        if result then
            print(string.format("  %s: %s", name, tostring(result)))
        else
            print(string.format("  %s: (nil/false)", name))
        end
    else
        print(string.format("  %s: ERROR - %s", name, tostring(result)))
    end
end

print("\nDone!")
return "ok"
