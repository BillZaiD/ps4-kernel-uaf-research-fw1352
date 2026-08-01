--[[
    device_sysctl_probe.lua
    Probe device nodes and sysctl interfaces for info leaks and memory corruption
    Discovered via libkernel.bin string analysis:
    - /dev/dmem0, /dev/dmem%d (direct memory)
    - vm.budgets.mlock_avail/total
    - kern.dmem.game_budget_limit
    - machdep.icc.sys_event_log
    - hw.sflash.get_write_prio/set_write_prio
    - machdep.rcmgr_debug_menu (debug flag)
    
    Platform: PS4 FW 13.52
]]

local utils = require("lib.ps4_utils")
local M = rawget(_G, "memory")
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

local buf = M.alloc(8192)
local buf2 = M.alloc(8192)

print("=" .. string.rep("=", 69))
print("  DEVICE & SYSCTL PROBE - FW 13.52")
print("=" .. string.rep("=", 69))

-- =============================================
-- Phase 1: Device node enumeration
-- =============================================
print("\n[Phase 1] Device Node Scan\n")

local devices = {
    "/dev/dmem0",
    "/dev/dmem1",
    "/dev/dmem2",
    "/dev/dmem3",
    "/dev/dmem4",
    "/dev/dmem5",
    "/dev/dmem6",
    "/dev/dmem7",
    "/dev/dmem8",
    "/dev/dmem9",
    "/dev/gc",
    "/dev/rng",
    "/dev/sce0",
    "/dev/sce1",
    "/dev/sce2",
    "/dev/sceRng",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
    "/dev/dtrace",
    "/dev/bpf",
    "/dev/crypto",
    "/dev/tls",
    "/dev/sflash0",
    "/dev/sflash1",
    "/dev/icc",
    "/dev/icc2",
    "/dev/gnm",
    "/dev/gnm2",
    "/dev/pfs",
    "/dev/npdrm",
    "/dev/mira",
    "/dev/ss/",
    "/dev/system",
    "/dev/system2",
}

local open_fds = {}
for _, dev in ipairs(devices) do
    for j = 0, 255 do M.write_byte(buf + j, 0) end
    -- Write device path
    for i = 1, #dev do
        M.write_byte(buf + i - 1, string.byte(dev, i))
    end
    M.write_byte(buf + #dev, 0)

    local fd = tonn(utils.fcall(5, buf, 0, 0, 0, 0, 0))  -- open(path, flags=O_RDONLY)
    if fd >= 0 and fd < 1024 then
        print(string.format("  [+] OPEN: %s -> fd=%d", dev, fd))
        table.insert(open_fds, {path = dev, fd = fd})
    else
        print(string.format("  [-] %s -> errno=%d", dev, fd))
    end
end

-- =============================================
-- Phase 2: ioctl on open devices
-- =============================================
print("\n[Phase 2] ioctl Probing on Open Devices\n")

-- Known ioctl numbers from PS4 RE
local ioctl_cmds = {
    {name = "DIOCGMEDIASIZE",  cmd = 0x40086418},  -- Get media size
    {name = "DIOCGSECTORSIZE",  cmd = 0x40026417},  -- Get sector size
    {name = "FIONBIO",          cmd = 0x8004667e},  -- Non-blocking I/O
    {name = "FIOASYNC",         cmd = 0x8004667d},  -- Async I/O
    {name = "FIOSETOWN",        cmd = 0x8004667c},  -- Set owner
    {name = "FIOGETOWN",        cmd = 0x4004667b},  -- Get owner
    {name = "DIOCGMEDIASIZE64", cmd = 0x40086489},  -- 64-bit media size
    {name = "FIOCLEX",          cmd = 0x20006601},  -- Close exec
    {name = "FIONCLEX",         cmd = 0x20006602},  -- Close exec (clear)
    {name = "TIOCGWINSZ",       cmd = 0x40087468},  -- Terminal size
    {name = "TIOCSWINSZ",       cmd = 0x80087467},  -- Set terminal size
    {name = "PT AttACH",        cmd = 0x80087469},  -- ptrace attach (wrong, but test)
    {name = "GPU_GET_BUS",      cmd = 0xC0108F00},  -- GPU bus access
    {name = "GPU_GET_VM",       cmd = 0xC0188F01},  -- GPU virtual memory
    {name = "GPU_MAP",          cmd = 0xC0208F02},  -- GPU memory map
}

for _, entry in ipairs(open_fds) do
    print(string.format("  --- %s (fd=%d) ---", entry.path, entry.fd))
    for _, ioctl_info in ipairs(ioctl_cmds) do
        for j = 0, 255 do M.write_byte(buf2 + j, 0) end
        local r = tonn(utils.fcall(54, entry.fd, ioctl_info.cmd, buf2))
        if r ~= -1 then
            print(string.format("    [+] %s (0x%x) -> %d", ioctl_info.name, ioctl_info.cmd, r))
            -- Check for kernel ptrs in output
            for j = 0, 248, 8 do
                local v = tonn(M.read_qword(buf2 + j))
                if is_kptr(v) then
                    print(string.format("        [!] KPTR at +0x%x: 0x%x", j, v))
                end
            end
        end
    end
end

-- Close all fds
for _, entry in ipairs(open_fds) do
    utils.fcall(6, entry.fd, 0, 0, 0, 0, 0)
end

-- =============================================
-- Phase 3: sysctl MIB deep scan
-- =============================================
print("\n[Phase 3] sysctl MIB Deep Scan\n")

-- Extended MIB paths discovered from libkernel strings
local mib_paths = {
    -- VM budget system
    {name = "vm.budgets.mlock_avail",       mib = {12, 100}},
    {name = "vm.budgets.mlock_total",       mib = {12, 101}},
    {name = "vm.budgets",                   mib = {12}},
    {name = "vm",                           mib = {12}},
    -- Direct memory
    {name = "kern.dmem.game_budget_limit",  mib = {1, 57}},
    {name = "kern.dmem",                    mib = {1, 55}},
    {name = "kern.dmem.size",               mib = {1, 56}},
    -- Machdep (security/debug)
    {name = "machdep.rcmgr_debug_menu",     mib = {6, 7}},
    {name = "machdep.rcmgr_sl_debugger",    mib = {6, 8}},
    {name = "machdep.rcmgr_intdev",         mib = {6, 1}},
    {name = "machdep.rcmgr_psm_intdev",     mib = {6, 2}},
    {name = "machdep.icc.sys_event_log",    mib = {6, 15}},
    {name = "machdep.tsc_freq",             mib = {6, 4}},
    {name = "machdep.idps",                 mib = {6, 5}},
    -- Sflash
    {name = "hw.sflash.get_write_prio",     mib = {6, 50}},
    {name = "hw.sflash.set_write_prio",     mib = {6, 51}},
    {name = "hw.sflash",                    mib = {6, 49}},
    -- Proc (info leak potential)
    {name = "kern.proc.all",                mib = {1, 14, 0}},
    {name = "kern.proc.pid",                mib = {1, 14, 1}},
    {name = "kern.proc.path",               mib = {1, 14, 12}},
    {name = "kern.proc.ptc",                mib = {1, 14, 13}},
    {name = "kern.proc.ptype",              mib = {1, 14, 8}},
    -- Kptr settings
    {name = "kern.ps_showallprocs",         mib = {1, 9}},
    {name = "security.bsd.unprivileged_proc_debug", mib = {10, 11}},
    -- Memory info
    {name = "vm.loadavg",                   mib = {12, 2}},
    {name = "vm.vmtotal",                   mib = {12, 1}},
    {name = "vm.stats.vm.v_free_count",     mib = {12, 3, 1}},
    {name = "hw.physmem",                   mib = {6, 12}},
    {name = "hw.usermem",                   mib = {6, 13}},
    {name = "hw.realmem",                   mib = {6, 14}},
    -- Security
    {name = "security",                     mib = {10}},
    {name = "security.see_other_uids",      mib = {10, 1}},
    {name = "security.see_other_gids",      mib = {10, 2}},
    {name = "security.unprivileged_read_msgbuf", mib = {10, 8}},
    {name = "security.unprivileged_proc_debug", mib = {10, 11}},
    {name = "security.unprivileged_kmem_map", mib = {10, 14}},
    -- Misc
    {name = "kern.random.fort_seed",        mib = {1, 37}},
    {name = "kern.entropy",                 mib = {1, 37, 0}},
    {name = "kern.dumper",                  mib = {1, 38}},
    {name = "kern.ipc.maxsockbuf",          mib = {1, 51, 17}},
    {name = "kern.ipc.sendspace",           mib = {1, 51, 1}},
    {name = "kern.ipc.recvspace",           mib = {1, 51, 2}},
    {name = "net.inet6.ip6.rthdr_max",      mib = {40, 53, 0}},
}

-- Create MIB structure in memory
local mib_buf = M.alloc(256)
local oldp = M.alloc(4096)
local oldlenp = M.alloc(16)

for _, mp in ipairs(mib_paths) do
    -- Build MIB: {len, mib[0], mib[1], ...}
    local mib_len = #mp.mib
    M.write_dword(mib_buf, mib_len)
    for i = 1, mib_len do
        M.write_dword(mib_buf + 4 + (i - 1) * 4, mp.mib[i])
    end

    -- Clear output buffer
    for j = 0, 4095 do M.write_byte(oldp + j, 0) end
    M.write_qword(oldlenp, 4096)

    -- sysctl(mib, ..., oldp, oldlenp, newp, newlen)
    -- Use MIB format: first arg is the MIB buffer, second is MIB length * 4
    local r = tonn(utils.fcall(202, mib_buf, mib_len * 4, 0, oldp, oldlenp, 0, 0))
    local actual_len = tonn(M.read_qword(oldlenp))

    if r == 0 then
        -- Read first 8 bytes of result
        local v1 = tonn(M.read_qword(oldp))
        local v2 = tonn(M.read_qword(oldp + 8))
        local v3 = tonn(M.read_qword(oldp + 16))
        local has_kptr = is_kptr(v1) or is_kptr(v2) or is_kptr(v3)

        local tag = ""
        if has_kptr then tag = " *** KPTR ***" end

        print(string.format("  [+] %s (len=%d):", mp.name, actual_len))
        print(string.format("      qword[0]=0x%x  qword[1]=0x%x  qword[2]=0x%x%s",
            v1, v2, v3, tag))

        if has_kptr then
            for j = 0, math.min(actual_len - 8, 4088), 8 do
                local v = tonn(M.read_qword(oldp + j))
                if is_kptr(v) then
                    print(string.format("      [!] KPTR at +0x%x: 0x%x", j, v))
                end
            end
        end

        -- If it's a string, print it
        if actual_len > 0 and actual_len < 256 then
            local str = ""
            for j = 0, actual_len - 1 do
                local ch = tonn(M.read_byte(oldp + j))
                if ch >= 32 and ch < 127 then
                    str = str .. string.char(ch)
                elseif ch == 0 then
                    break
                end
            end
            if #str > 0 then
                print(string.format("      string: \"%s\"", str))
            end
        end
    else
        print(string.format("  [-] %s -> errno=%d", mp.name, r))
    end
end

-- =============================================
-- Phase 4: proc sysctl (kinfo_proc leak)
-- =============================================
print("\n[Phase 4] kinfo_proc Deep Analysis\n")

-- Try kern.proc with different opcodes
local proc_ops = {
    {name = "KERN_PROC_ALL",     op = 0},
    {name = "KERN_PROC_PID",     op = 1},
    {name = "KERN_PROC_PGRP",    op = 2},
    {name = "KERN_PROC_SESSION",  op = 3},
    {name = "KERN_PROC_TTY",     op = 4},
    {name = "KERN_PROC_UID",     op = 5},
    {name = "KERN_PROC_RUID",    op = 6},
    {name = "KERN_PROC_ALL+ARGS", op = 7},
    {name = "KERN_PROC_TYPE",    op = 8},
}

-- Get our PID
local pid = tonn(utils.fcall(20, 0, 0, 0, 0, 0, 0))
print(string.format("  Our PID: %d\n", pid))

for _, pop in ipairs(proc_ops) do
    -- Build MIB: {CTL_KERN, KERN_PROC, op}
    M.write_dword(mib_buf, 3)
    M.write_dword(mib_buf + 4, 1)    -- CTL_KERN
    M.write_dword(mib_buf + 8, 14)   -- KERN_PROC
    M.write_dword(mib_buf + 12, pop.op)

    for j = 0, 4095 do M.write_byte(oldp + j, 0) end
    M.write_qword(oldlenp, 4096)

    -- For PID-based queries, set the arg (PID) in MIB[3]
    if pop.op == 1 then
        M.write_dword(mib_buf + 16, pid)
        M.write_dword(mib_buf, 4)  -- 4-element MIB
    end

    local r = tonn(utils.fcall(202, mib_buf, (pop.op == 1 and 16 or 12), 0, oldp, oldlenp, 0, 0))
    local actual_len = tonn(M.read_qword(oldlenp))

    if r == 0 and actual_len > 0 then
        print(string.format("  %s (op=%d, len=%d):", pop.name, pop.op, actual_len))

        -- Scan for kernel pointers
        local kptrs = 0
        local strings_found = {}
        for j = 0, math.min(actual_len - 8, 4088), 8 do
            local v = tonn(M.read_qword(oldp + j))
            if is_kptr(v) then
                kptrs = kptrs + 1
                print(string.format("    [!] KPTR at +0x%x: 0x%x", j, v))
            end
        end

        -- Try to extract strings (process names, paths, etc.)
        local str = ""
        for j = 0, math.min(actual_len - 1, 4095) do
            local ch = tonn(M.read_byte(oldp + j))
            if ch >= 32 and ch < 127 then
                str = str .. string.char(ch)
            else
                if #str >= 4 then
                    table.insert(strings_found, {offset = j - #str, str = str})
                end
                str = ""
            end
        end

        for _, sf in ipairs(strings_found) do
            print(string.format("    string @ +0x%x: \"%s\"", sf.offset, sf.str))
        end

        if kptrs == 0 and #strings_found == 0 then
            print("    (no kernel pointers or strings found)")
        end
    else
        print(string.format("  %s (op=%d) -> errno=%d (len=%d)", pop.name, pop.op, r, actual_len))
    end
end

-- =============================================
-- Phase 5: Socket ioctl (SIOCGIFCONF etc)
-- =============================================
print("\n[Phase 5] Socket ioctl Probe\n")

-- Create a socket
local sd = tonn(utils.fcall(97, 2, 2, 17, 0, 0, 0))  -- AF_INET, SOCK_DGRAM, IPPROTO_UDP
print(string.format("  socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) = %d", sd))

if sd >= 0 then
    -- Try network ioctls
    local net_ioctls = {
        {name = "SIOCGIFCONF",    cmd = 0xC0986924},
        {name = "SIOCGIFADDR",    cmd = 0xC0206921},
        {name = "SIOCGIFNETMASK", cmd = 0xC0206925},
        {name = "SIOCGIFBRDADDR", cmd = 0xC0206923},
        {name = "SIOCGIFMTU",     cmd = 0xC0206933},
        {name = "SIOCGIFHWADDR",  cmd = 0xC0206932},
        {name = "SIOCGIFINDEX",   cmd = 0xC0206933},
        {name = "SIOCGIFFLAGS",   cmd = 0xC0206911},
        {name = "FIONREAD",       cmd = 0x4004667f},
    }

    for _, nio in ipairs(net_ioctls) do
        for j = 0, 255 do M.write_byte(buf2 + j, 0) end
        -- Try to write a known interface name "lo\0"
        M.write_byte(buf2, string.byte("l"))
        M.write_byte(buf2 + 1, string.byte("o"))
        M.write_byte(buf2 + 2, 0)

        local r = tonn(utils.fcall(54, sd, nio.cmd, buf2))
        if r ~= -1 then
            print(string.format("  [+] %s (0x%x) -> %d", nio.name, nio.cmd, r))
            -- Check for data
            local has_data = false
            for j = 0, 63 do
                if tonn(M.read_byte(buf2 + j)) ~= 0 then
                    has_data = true
                    break
                end
            end
            if has_data then
                local hex = ""
                for j = 0, 31 do hex = hex .. string.format("%02x ", tonn(M.read_byte(buf2 + j))) end
                print(string.format("      data: %s", hex))
            end
        end
    end

    -- Close socket
    utils.fcall(6, sd, 0, 0, 0, 0, 0)
end

-- =============================================
-- Phase 6: AIO (Asynchronous I/O) probe
-- =============================================
print("\n[Phase 6] AIO Probe\n")

-- aio_read/write use syscalls 318/319 in FreeBSD
-- Check if they exist as wrappers
for scno = 318, 322 do
    local w = utils.toaddr(S.syscall_wrapper[scno])
    if w ~= 0 then
        print(string.format("  [+] sc%d has wrapper", scno))
        -- Try with zero args (should return EINVAL)
        local r = tonn(utils.fcall(scno, 0, 0, 0, 0, 0, 0))
        print(string.format("      zero args -> %d", r))
    end
end

-- =============================================
-- Phase 7: Memory mapping syscalls
-- =============================================
print("\n[Phase 7] Memory Mapping Probes\n")

-- mmap via syscall 477
local test_pages = 0x1000
local mmap_buf = tonn(utils.fcall(477, 0, test_pages, 3, 0x1002, -1, 0))
print(string.format("  mmap(NULL, 0x1000, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0) = 0x%x", mmap_buf))

if mmap_buf ~= 0 and mmap_buf ~= 0xFFFFFFFFFFFFFFFF then
    -- Write test pattern
    for j = 0, test_pages - 1 do
        M.write_byte(mmap_buf + j, j % 256)
    end

    -- Try mprotect with EXEC (should fail with W^X)
    local mp = tonn(utils.fcall(74, mmap_buf, test_pages, 7))
    print(string.format("  mprotect(mmap, 0x1000, PROT_RWX) = %d", mp))

    -- Check if it actually has exec (try to read back)
    local readback = 0
    for j = 0, 7 do
        readback = bit.bor(bit.lshift(readback, 8), tonn(M.read_byte(mmap_buf + j)))
    end
    print(string.format("  readback[0..7] = 0x%x (should be 0x0001020304050607)", readback))

    -- munmap
    local mun = tonn(utils.fcall(73, mmap_buf, test_pages))
    print(string.format("  munmap(0x%x, 0x1000) = %d", mmap_buf, mun))
end

-- =============================================
-- Phase 8: thr_new (thread creation)
-- =============================================
print("\n[Phase 8] Thread System Probe\n")

-- thr_new with various args
local thr_buf = M.alloc(0x100)
for j = 0, 0xFF do M.write_byte(thr_buf + j, 0) end

local r = tonn(utils.fcall(455, thr_buf, 0x88, 0, 0, 0))
print(string.format("  thr_new(buf, 0x88, 0, 0, 0) = %d", r))

-- =============================================
-- Summary
-- =============================================
print("\n" .. "=" .. string.rep("=", 69))
print("  PROBE COMPLETE")
print("=" .. string.rep("=", 69))
print(string.format("  Devices opened: %d", #open_fds))
print("  Check output above for kernel pointers, data leaks, or anomalies.")
print("=" .. string.rep("=", 69))
