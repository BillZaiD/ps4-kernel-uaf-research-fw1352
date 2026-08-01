--[[
    dev_scan.lua
    Enumerate /dev/ entries and test open/ioctl/read/write/mmap operations
]]

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

S.resolve({open=5, close=6, read=3, write=4, getpid=20, ioctl=54, mmap=477})

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local O_RDONLY = 0
local O_WRONLY = 1
local O_RDWR  = 2
local mode_names = {[0]="RDONLY", [1]="WRONLY", [2]="RDWR"}

local dev_paths = {
    "/dev/dri/card0",
    "/dev/dri/controlD64",
    "/dev/fd/0",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/bpf",
    "/dev/bpf0",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/gc",
    "/dev/gpu",
    "/dev/gpu0",
    "/dev/gpu1",
    "/dev/gpu2",
    "/dev/gpu3",
    "/dev/gpu4",
    "/dev/gpu5",
    "/dev/gpu6",
    "/dev/gpu7",
    "/dev/gpiomem",
    "/dev/scemtx",
    "/dev/scemd",
    "/dev/scese",
    "/dev/scesys",
    "/dev/scecbl",
    "/dev/scecbl0",
    "/dev/scecbl1",
    "/dev/scecbl2",
    "/dev/scecbl3",
    "/dev/scecbl4",
    "/dev/scecbl5",
    "/dev/scecbl6",
    "/dev/scecbl7",
    "/dev/scecbl8",
    "/dev/scecbl9",
    "/dev/scecbl10",
    "/dev/scecbl11",
    "/dev/scecbl12",
    "/dev/scecbl13",
    "/dev/scecbl14",
    "/dev/scecbl15",
    "/dev/scecbl16",
    "/dev/scecbl17",
    "/dev/scecbl18",
    "/dev/scecbl19",
    "/dev/scecbl20",
    "/dev/scesas",
    "/dev/scese",
    "/dev/sce_sbl_fw_mgr",
    "/dev/sce_sbl_svc",
    "/dev/sce_sbl_mgr",
    "/dev/sce_sbl_keymgr",
    "/dev/sce_sbl_codegen",
    "/dev/sce_sbl_rnd",
    "/dev/sce_sbl_apploader",
    "/dev/sce_sbl_antidbgex",
    "/dev/sce_sbl_user",
    "/dev/scesys",
    "/dev/scestorage",
    "/dev/sce_sbl_sdk",
    "/dev/sce_sbl_config",
    "/dev/sce_sbl_verifier",
    "/dev/sce_sbl_factory",
    "/dev/sce_sbl_update",
    "/dev/sce_sbl_recovery",
    "/dev/sce_sbl_sm",
    "/dev/sce_sbl_appmgr",
    "/dev/sce_sbl_rng",
    "/dev/sce_sbl_crypto",
    "/dev/sce_sbl_is",
    "/dev/sce_sbl_pfs",
    "/dev/sce_sbl_bgft",
    "/dev/sce_sbl_fs",
    "/dev/sce_sbl_db",
    "/dev/sce_sbl_encdec",
    "/dev/sce_sbl_pm",
    "/dev/sce_sbl_core",
    "/dev/sce_sbl_reserved",
    "/dev/sce_vs",
    "/dev/sce_vr",
    "/dev/sce_uv",
    "/dev/sce_av",
    "/dev/sce_av_enc",
    "/dev/sce_av_dec",
    "/dev/sce_hevc",
    "/dev/sce_jpeg",
    "/dev/sce_gpu",
    "/dev/sce_gpu_srv",
    "/dev/sce_gpu_core",
    "/dev/sce_gpu_compute",
    "/dev/sce_gpu_user",
    "/dev/sce_gpu_kgsl",
    "/dev/sce_ai",
    "/dev/sce_disp",
    "/dev/sce_hdmi",
    "/dev/sce_sd",
    "/dev/sce_sd_enc",
    "/dev/sce_sd_bc",
    "/dev/sce_sd_cd",
    "/dev/sce_sd_pd",
    "/dev/sce_sd_sys",
    "/dev/sce_bt",
    "/dev/sce_wlan",
    "/dev/sce_np",
    "/dev/sce_np_mgr",
    "/dev/sce_np_enc",
    "/dev/sce_np_auth",
    "/dev/sce_sys",
    "/dev/sce_sys_core",
    "/dev/sce_sys_dbg",
    "/dev/sce_sys_ftr",
    "/dev/sce_sys_prv",
    "/dev/sce_sys_rat",
    "/dev/sce_sys_sm",
    "/dev/sce_sys_trace",
    "/dev/sce_sys_pii",
    "/dev/sce_dip",
    "/dev/sce_dip0",
    "/dev/sce_dip1",
    "/dev/sce_dip2",
    "/dev/sce_dip3",
    "/dev/sce_dip_ctl",
    "/dev/sce_led",
    "/dev/sce_buzzer",
    "/dev/sce_fan",
    "/dev/sce_thermal",
    "/dev/sce_battery",
    "/dev/sce_power",
    "/dev/sce_usb",
    "/dev/sce_usb_mass",
    "/dev/sce_sata",
    "/dev/sce_nand",
    "/dev/sce_emmc",
    "/dev/sce_sdio",
    "/dev/sce_i2c",
    "/dev/sce_spi",
    "/dev/sce_uart",
    "/dev/sce_gpio",
    "/dev/sce_adc",
    "/dev/sce_rtc",
    "/dev/sce_wdt",
    "/dev/sce_timer",
    "/dev/sce_dmac",
    "/dev/sce_pcie",
    "/dev/sce_sm",
    "/dev/sce_mc",
    "/dev/sce_mc_dma",
    "/dev/sce_mc_cmd",
    "/dev/sce_mc_queue",
    "/dev/sce_vdec",
    "/dev/sce_venc",
    "/dev/sce_vdec0",
    "/dev/sce_venc0",
    "/dev/sce_vdec_ucode",
    "/dev/sce_venc_ucode",
    "/dev/sce_audio",
    "/dev/sce_audio_dsp",
    "/dev/sce_audio_mgr",
    "/dev/sce_audio_sys",
    "/dev/sce_audio_core",
    "/dev/sce_audio_bus",
    "/dev/sce_codec",
    "/dev/sce_codec_enc",
    "/dev/sce_codec_dec",
    "/dev/sce_codec_mic",
    "/dev/sce_codec_spk",
    "/dev/sce_video",
    "/dev/sce_video_enc",
    "/dev/sce_video_dec",
    "/dev/sce_video_m2m",
    "/dev/sce_camera",
    "/dev/sce_camera0",
    "/dev/sce_camera1",
    "/dev/sce_camera_isp",
    "/dev/sce_camera_sens",
    "/dev/sce_touch",
    "/dev/sce_touch0",
    "/dev/sce_touch1",
    "/dev/sce_touchpad",
    "/dev/sce_motion",
    "/dev/sce_als",
    "/dev/sce_compass",
    "/dev/sce_gyro",
    "/dev/sce_accel",
    "/dev/sce_lightbar",
    "/dev/sce_als_prx",
}

local results = {}

local function try_open(path, flags)
    local fd = S.open(path, flags, 0)
    return tonn(fd)
end

local function try_ioctl(fd, req, buf)
    return tonn(S.ioctl(fd, req, buf or 0))
end

local function try_read(fd, buf, count)
    return tonn(S.read(fd, buf, count))
end

local function try_write(fd, buf, count)
    return tonn(S.write(fd, buf, count))
end

local function try_mmap(addr, len, prot, flags, fd, offset)
    return tonn(S.mmap(addr, len, prot, flags, fd, offset))
end

print("[+] Device Enumeration Scan\n")
print(string.format("  PID: %d\n\n", tonn(S.getpid())))

for _, path in ipairs(dev_paths) do
    for _, flags in ipairs({O_RDONLY, O_WRONLY, O_RDWR}) do
        local fd = try_open(path, flags)
        if fd >= 0 then
            local key = path .. " [" .. mode_names[flags] .. "]"
            if not results[path] then results[path] = {} end
            table.insert(results[path], {mode=flags, fd=fd})
            print(string.format("[OPEN OK] %s (fd=%d)", key, fd))

            -- Try ioctl with some common requests
            local ioctl_reqs = {0, 0x4001, 0x40046601, 0xC0046602, 0xC0086603}
            for _, req in ipairs(ioctl_reqs) do
                local r = try_ioctl(fd, req)
                if r >= 0 then
                    print(string.format("  [IOCTL] %s req=0x%x -> %d", key, req, r))
                elseif r == -1 then
                    -- silent, expected for most
                else
                    print(string.format("  [IOCTL] %s req=0x%x -> %d (unexpected)", key, req, r))
                end
            end

            -- Try read with small buffer
            local rbuf = mem.alloc(64)
            if rbuf and tonn(rbuf) ~= 0 then
                local nr = try_read(fd, rbuf, 64)
                if nr > 0 then
                    print(string.format("  [READ]  %s -> %d bytes", key, nr))
                elseif nr == 0 then
                    -- EOF, not interesting
                end
            end

            -- Try write with small buffer
            local wbuf = mem.alloc(64)
            if wbuf and tonn(wbuf) ~= 0 then
                local nw = try_write(fd, wbuf, 64)
                if nw >= 0 then
                    print(string.format("  [WRITE] %s -> %d bytes", key, nw))
                end
            end
        end
    end
end

-- Special mmap tests on /dev/gc
print("\n[*] mmap tests on /dev/gc...\n")
local gc_fd_rdonly = try_open("/dev/gc", O_RDONLY)
local gc_fd_rdwr = try_open("/dev/gc", O_RDWR)

local prot_combs = {
    {prot=3, name="PROT_READ|PROT_WRITE"},
    {prot=7, name="PROT_READ|PROT_WRITE|PROT_EXEC"},
    {prot=1, name="PROT_READ"},
    {prot=2, name="PROT_WRITE"},
}

local sizes = {0x1000, 0x10000, 0x100000, 0x400000, 0x800000}
local flags_map = {1, 2, 3, 0x20, 0x21, 0x22, 0x23}

for _, fd_info in ipairs({{fd=gc_fd_rdonly, tag="RDONLY"}, {fd=gc_fd_rdwr, tag="RDWR"}}) do
    local fd = fd_info.fd
    if tonn(fd) >= 0 then
        print(string.format("  Testing mmap on /dev/gc [%s] (fd=%d)\n", fd_info.tag, tonn(fd)))
        for _, pc in ipairs(prot_combs) do
            for _, sz in ipairs(sizes) do
                for _, fl in ipairs(flags_map) do
                    local addr = try_mmap(0, sz, pc.prot, fl, tonn(fd), 0)
                    if addr > 0 and addr < 0xFFFFFFFFFFFF0000 then
                        print(string.format("  [MMAP OK] prot=%s(%d) size=0x%x flags=0x%x -> 0x%x",
                            pc.name, pc.prot, sz, fl, addr))
                        -- Try reading from mapped memory
                        local val = tonn(mem.read_dword(addr))
                        print(string.format("    [MMAP READ] first dword at 0x%x = 0x%x", addr, val))
                        -- Unmap (close would be done by fd close)
                        S.mmap(addr, sz, 0, 0x2, -1, 0) -- MAP_FIXED unmap attempt
                        break
                    end
                end
            end
        end
    end
end

-- Close all opened fds
print("\n[*] Closing opened file descriptors...\n")
for path, entries in pairs(results) do
    for _, entry in ipairs(entries) do
        local r = tonn(S.close(entry.fd))
        if r ~= 0 then
            print(string.format("  close(%d) %s [%s] -> %d", entry.fd, path, mode_names[entry.mode], r))
        end
    end
end

print("\n[+] Device scan complete\n")
print("[*] Summary of successfully opened devices:\n")
for path, entries in pairs(results) do
    local modes = {}
    for _, e in ipairs(entries) do
        table.insert(modes, mode_names[e.mode])
    end
    print(string.format("  %s (%s)", path, table.concat(modes, ", ")))
end
