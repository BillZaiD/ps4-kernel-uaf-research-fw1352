--[[
    sony_full_fuzzer.lua
    Comprehensive fuzzer for ALL Sony custom syscalls 585-677
    Tests multiple argument patterns per syscall to find:
    - Non-standard return values (info leaks)
    - Buffer writes (data written to output buffers)
    - Kernel pointer leaks
    - Privilege escalation paths
    
    Platform: PS4 FW 13.52
    Safety: Uses fcall_with_rax which catches crashes via longjmp
]]

local utils = require("lib.ps4_utils")
local M = rawget(_G, "memory")
local N = rawget(_G, "native")
local S = rawget(_G, "syscall")

utils.resolve()

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v)) or 0
end

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

-- Allocate working buffers
local buf1 = M.alloc(4096)
local buf2 = M.alloc(4096)
local size_buf = M.alloc(16)

-- Sony custom syscall numbers (from libkernel.bin analysis)
local SONY_SYSCALLS = {
    585, 586, 587, 588, 591, 592, 593, 594, 595, 596,
    598, 599, 600, 601, 602, 603, 604, 605, 606, 607,
    608, 610, 611, 612, 613, 615, 616, 617, 618, 619,
    620, 622, 623, 624, 625, 626, 627, 628, 629, 630,
    632, 633, 634, 635, 636, 637, 638, 639, 640, 641,
    642, 643, 646, 647, 648, 649, 652, 653, 654, 655,
    656, 657, 658, 659, 660, 661, 662, 663, 664, 665,
    666, 667, 668, 669, 670, 671, 672, 673, 674, 675,
    676, 677,
}

-- Known syscall names (from reverse engineering)
local KNOWN_NAMES = {
    [585] = "is_in_sandbox",
    [586] = "dynlib_do_copy_relocations",
    [587] = "dynlib_load_prx_for_libkernel",
    [588] = "dynlib_relocate_eboot_image",
    [591] = "dynlib_find_by_name",
    [592] = "dynlib_do_copy_relocations_v2",
    [593] = "dynlib_relocate_eboot_image_v2",
    [594] = "dynlib_load_prx",
    [595] = "dynlib_unload_prx",
    [596] = "dynlib_get_info_for_libkernel",
    [598] = "dynlib_get_list_for_libkernel",
    [599] = "dynlib_get_info2",
    [600] = "dynlib_get_list2",
    [601] = "sceKernelGetModuleInfoByHandle",
    [602] = "dynlib_process_needed_and_relocate",
    [603] = "sceKernelGetModuleInfoForLibkernel",
    [605] = "sceKernelGetModuleInfo",
    [607] = "sceKernelGetModuleList",
    [608] = "dynlib_load_prx_with_lib",
    [610] = "sceKernelGetCompiledSdkVersion",
    [611] = "sceKernelGetProcessTime",
    [613] = "sceKernelGetEventTimerTime",
    [615] = "sceKernelGetProcessTimeImpl",
    [616] = "sceKernelGetModuleInfo2",
    [618] = "budget",
    [619] = "budget_get_ptype",
    [620] = "budget_get_kernel_budgets",
    [622] = "sceKernelReserveVirtualRange",
    [623] = "sceKernelMapFlexibleMemory",
    [624] = "sceKernelRemapBlock",
    [625] = "sceKernelGetDirectMemoryType",
    [626] = "sceKernelMmap",
    [627] = "sceKernelReserveVirtualRange2",
    [628] = "sceKernelMunmap",
    [629] = "sceKernelMapBlock",
    [630] = "sceKernelMapBlockFromContainer",
    [632] = "sceKernelGetBlockTypeInfo",
    [633] = "sceKernelSetBlockHeaderType",
    [634] = "sceKernelSetOptimalCpuAffinityMask",
    [635] = "sceKernelSetProcessMemory",
    [636] = "sceKernelGetProcessMemoryMap",
    [637] = "sceKernelGetDirectMemoryAll",
    [638] = "sceKernelReleaseDirectMemory",
    [639] = "sceKernelGetPthreadMemoryInfo",
    [640] = "sceKernelSwitchToProcessMemory",
    [641] = "sceKernelCreateUserMemoryBlock",
    [642] = "sceKernelMapUserMemoryBlock",
    [643] = "sceKernelReleaseUserMemoryBlock",
    [646] = "sceKernelCreateEvent",
    [647] = "sceKernelDeleteEvent",
    [648] = "sceKernelTriggerEvent",
    [649] = "sceKernelClearEvent",
    [652] = "sceKernelGetEventInfo",
    [653] = "sceKernelCancelEvent",
    [654] = "sceKernelGetEventUserData",
    [655] = "sceKernelSetEvent",
    [656] = "sceKernelCreateSema",
    [657] = "sceKernelDeleteSema",
    [658] = "sceKernelWaitSema",
    [659] = "sceKernelSignalSema",
    [660] = "sceKernelPollSema",
    [661] = "sceKernelCancelSema",
    [662] = "sceKernelGetSemaInfo",
    [663] = "sceKernelCreateEqueue",
    [664] = "sceKernelDeleteEqueue",
    [665] = "sceKernelAddUserEvent",
    [666] = "sceKernelTriggerUserEvent",
    [667] = "sceKernelDeleteUserEvent",
    [668] = "sceKernelGetUserEventInfo",
    [669] = "sceKernelCancelUserEvent",
    [670] = "sceKernelGetUserDataForUserEvent",
    [671] = "sceKernelPeekEvent",
    [672] = "sceKernelWaitEqueue",
    [673] = "sceKernelGetEqueueInfo",
    [674] = "sceKernelGetProcessAioInfo",
    [675] = "sysctl",
    [676] = "sceKernelGetCurrentCpu",
    [677] = "sceKernelIsStackOverrun",
}

-- Argument patterns to test
local ARG_PATTERNS = {
    {
        name = "zero_args",
        fn = function(scno)
            return utils.fcall(scno, 0, 0, 0, 0, 0, 0)
        end,
    },
    {
        name = "buf_arg1",
        fn = function(scno)
            for j = 0, 255 do M.write_byte(buf1 + j, 0) end
            return utils.fcall(scno, buf1, 256, 0, 0, 0, 0)
        end,
    },
    {
        name = "neg1_args",
        fn = function(scno)
            return utils.fcall(scno, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0)
        end,
    },
    {
        name = "buf_large_size",
        fn = function(scno)
            for j = 0, 255 do M.write_byte(buf1 + j, 0) end
            return utils.fcall(scno, buf1, 0x100000, 0, 0, 0, 0)
        end,
    },
    {
        name = "size_ptr_arg",
        fn = function(scno)
            M.write_qword(size_buf, 0x100)
            return utils.fcall(scno, buf1, size_buf, 0, 0, 0, 0)
        end,
    },
    {
        name = "kernel_addr_arg",
        fn = function(scno)
            return utils.fcall(scno, 0xFFFF800000100000, 0x100, 0, 0, 0, 0)
        end,
    },
    {
        name = "small_handle",
        fn = function(scno)
            return utils.fcall(scno, 1, 0, 0, 0, 0, 0)
        end,
    },
    {
        name = "two_bufs",
        fn = function(scno)
            for j = 0, 63 do
                M.write_byte(buf1 + j, 0)
                M.write_byte(buf2 + j, 0)
            end
            return utils.fcall(scno, buf1, 64, buf2, 64, 0, 0)
        end,
    },
    {
        name = "flags_1",
        fn = function(scno)
            return utils.fcall(scno, buf1, 64, 1, 0, 0, 0)
        end,
    },
    {
        name = "flags_ff",
        fn = function(scno)
            return utils.fcall(scno, buf1, 64, 0xFF, 0, 0, 0)
        end,
    },
}

-- Collect results
local results = {}
local anomalies = {}

print("=" .. string.rep("=", 69))
print("  SONY CUSTOM SYSCALL FUZZER - FW 13.52")
print("  Testing " .. #SONY_SYSCALLS .. " syscalls x " .. #ARG_PATTERNS .. " patterns")
print("=" .. string.rep("=", 69))
print()

-- Phase 1: Quick scan - zero args for all syscalls
print("[Phase 1] Quick scan: zero args for all " .. #SONY_SYSCALLS .. " syscalls\n")
local non_neg1 = {}

for _, scno in ipairs(SONY_SYSCALLS) do
    local name = KNOWN_NAMES[scno] or "unknown"
    local ret = utils.fcall(scno, 0, 0, 0, 0, 0, 0)
    local r = tonn(ret)

    if r ~= -1 and r ~= 0xFFFFFFFFFFFFFFFF then
        local tag = ""
        if is_kptr(r) then tag = " *** KERNEL PTR ***"
        elseif r == 0 then tag = " (zero)"
        elseif r > 0 and r < 0x100 then tag = " (small)"
        else tag = string.format(" (0x%x)", r)
        end
        print(string.format("  sc%03d %-40s = 0x%x%s", scno, name, r, tag))
        table.insert(non_neg1, {scno = scno, name = name, ret = r})
    end
end

if #non_neg1 == 0 then
    print("  All syscalls returned -1 with zero args")
end

-- Phase 2: Deep fuzz non-negative-return syscalls
print(string.format("\n[Phase 2] Deep fuzz: %d syscalls with %d patterns each\n",
    #non_neg1 + #SONY_SYSCALLS, #ARG_PATTERNS))

-- Deep fuzz ALL syscalls, not just non-negative ones
for _, scno in ipairs(SONY_SYSCALLS) do
    local name = KNOWN_NAMES[scno] or "unknown"
    local syscall_results = {}

    for _, pattern in ipairs(ARG_PATTERNS) do
        local ok, ret = pcall(pattern.fn, scno)
        if ok then
            local r = tonn(ret)
            if r ~= -1 and r ~= 0xFFFFFFFFFFFFFFFF then
                table.insert(syscall_results, {
                    pattern = pattern.name,
                    ret = r,
                })
            end
        else
            table.insert(anomalies, {
                scno = scno,
                name = name,
                pattern = pattern.name,
                error = "crash/exception",
            })
        end
    end

    -- Check buffer contents for leaks
    if #syscall_results > 0 then
        for _, sr in ipairs(syscall_results) do
            local tag = ""
            if is_kptr(sr.ret) then
                tag = " *** KERNEL PTR ***"
                table.insert(anomalies, {
                    scno = scno,
                    name = name,
                    pattern = sr.pattern,
                    error = string.format("kernel ptr: 0x%x", sr.ret),
                })
            end

            -- Scan buffers for kernel pointers
            local kptrs_buf1 = 0
            local kptrs_buf2 = 0
            for j = 0, 248, 8 do
                local v1 = tonn(M.read_qword(buf1 + j))
                local v2 = tonn(M.read_qword(buf2 + j))
                if is_kptr(v1) then kptrs_buf1 = kptrs_buf1 + 1 end
                if is_kptr(v2) then kptrs_buf2 = kptrs_buf2 + 1 end
            end

            if kptrs_buf1 > 0 or kptrs_buf2 > 0 then
                tag = tag .. string.format(" [KPTRs in buf: %d/%d]", kptrs_buf1, kptrs_buf2)
                table.insert(anomalies, {
                    scno = scno,
                    name = name,
                    pattern = sr.pattern,
                    error = string.format("buffer kptr leak: %d/%d", kptrs_buf1, kptrs_buf2),
                })
            end

            print(string.format("  sc%03d %-40s %-16s = 0x%x%s",
                scno, name, sr.pattern, sr.ret, tag))
        end
    end
end

-- Phase 3: Special interest syscalls - exhaustive testing
print("\n[Phase 3] Exhaustive testing of high-value syscalls\n")

-- Memory-related syscalls (highest exploit potential)
local HIGH_VALUE = {
    622, -- sceKernelReserveVirtualRange
    623, -- sceKernelMapFlexibleMemory
    624, -- sceKernelRemapBlock
    625, -- sceKernelGetDirectMemoryType
    626, -- sceKernelMmap
    627, -- sceKernelReserveVirtualRange2
    628, -- sceKernelMunmap
    629, -- sceKernelMapBlock
    630, -- sceKernelMapBlockFromContainer
    632, -- sceKernelGetBlockTypeInfo
    636, -- sceKernelGetProcessMemoryMap
    637, -- sceKernelGetDirectMemoryAll
    638, -- sceKernelReleaseDirectMemory
    641, -- sceKernelCreateUserMemoryBlock
    642, -- sceKernelMapUserMemoryBlock
    643, -- sceKernelReleaseUserMemoryBlock
    675, -- sysctl (custom)
    677, -- sceKernelIsStackOverrun
}

for _, scno in ipairs(HIGH_VALUE) do
    local name = KNOWN_NAMES[scno] or "unknown"
    print(string.format("--- sc%03d %s ---", scno, name))

    -- Exhaustive arg combinations
    local tests = {
        {0, 0, 0, 0, 0, 0},
        {buf1, 0x1000, 0, 0, 0, 0},
        {buf1, 0x1000, 7, 0, 0, 0},       -- RWX flags
        {buf1, 0x1000, 3, 0, 0, 0},        -- RW flags
        {0, 0x1000, 7, 0, 0, 0},           -- NULL addr + size + RWX
        {0x7FFFFFFF000, 0x1000, 7, 0, 0, 0}, -- User addr
        {buf1, 0x1000, 7, 1, 0, 0},        -- With flags
        {buf1, 0x1000, 7, 2, 0, 0},
        {buf1, 0, 0, 0, 0, 0},             -- buf, zero size
        {buf1, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0}, -- Huge size
        {buf1, 0x1000, 7, 0, 0xFFFFFFFFFFFFFFFF, 0}, -- Negative extra arg
    }

    for _, args in ipairs(tests) do
        local ok, ret = pcall(function()
            return utils.fcall(scno, args[1], args[2], args[3], args[4], args[5], args[6])
        end)
        if ok then
            local r = tonn(ret)
            if r ~= -1 and r ~= 0xFFFFFFFFFFFFFFFF then
                local argstr = string.format("(%x,%x,%x,%x,%x,%x)",
                    tonn(args[1]), tonn(args[2]), tonn(args[3]),
                    tonn(args[4]), tonn(args[5]), tonn(args[6]))
                local tag = ""
                if is_kptr(r) then tag = " *** KERNEL PTR ***" end
                print(string.format("  %s -> 0x%x%s", argstr, r, tag))

                -- Check buffers
                for j = 0, 248, 8 do
                    local v = tonn(M.read_qword(buf1 + j))
                    if is_kptr(v) then
                        print(string.format("    [!] KPTR in buf1+0x%x: 0x%x", j, v))
                    end
                end
            end
        end
    end
    print()
end

-- Summary
print("=" .. string.rep("=", 69))
print("  SUMMARY")
print("=" .. string.rep("=", 69))
print(string.format("  Syscalls tested: %d", #SONY_SYSCALLS))
print(string.format("  Patterns per syscall: %d", #ARG_PATTERNS))
print(string.format("  Anomalies found: %d", #anomalies))

if #anomalies > 0 then
    print("\n  ANOMALIES:")
    for _, a in ipairs(anomalies) do
        print(string.format("    sc%03d %-40s %-16s: %s",
            a.scno, a.name, a.pattern, a.error))
    end
else
    print("\n  No anomalies detected. All syscalls behave as expected.")
end

print("\n[+] Fuzzer complete")
