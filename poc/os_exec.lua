-- Explore via os.execute
print("=== OS Execute Exploration ===\n")

-- Helper to run and capture
local function run(cmd)
    print("> " .. cmd)
    local ok, r = pcall(os.execute, cmd)
    print(string.format("  ret=%s", tostring(r)))
    print("")
end

-- Basic system info
run("uname -a")
run("cat /proc/version 2>/dev/null || echo no_proc")
run("cat /etc/fstab 2>/dev/null || echo no_fstab")
run("id")
run("ls -la /")
run("ls -la /dev/")
run("ls -la /proc/ 2>/dev/null || echo no_proc")
run("mount")
run("df -h")
run("cat /proc/cpuinfo 2>/dev/null || echo no_cpuinfo")
run("cat /proc/meminfo 2>/dev/null || echo no_meminfo")
run("env")
run("ps 2>/dev/null || ps aux 2>/dev/null || echo no_ps")

-- Look for kernel symbols
run("cat /proc/kallsyms 2>/dev/null | head -5 || echo no_kallsyms")
run("cat /proc/modules 2>/dev/null | head -5 || echo no_modules")
run("lsmod 2>/dev/null || echo no_lsmod")

-- Check if we can find kernel memory
run("cat /dev/kmem 2>&1 | head -c 100 || echo no_kmem")
run("ls -la /dev/mem 2>/dev/null || echo no_mem")

-- Look for interesting paths
run("ls -la /system/ 2>/dev/null || ls -la /System/ 2>/dev/null || echo no_system")
run("ls -la /app0/ 2>/dev/null || echo no_app0")
run("ls -la /data/ 2>/dev/null || echo no_data")
run("ls -la /mnt/ 2>/dev/null || echo no_mnt")

print("Done!")
