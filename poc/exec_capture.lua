-- Capture os.execute output via temp file
print("=== OS Execute with output capture ===\n")

local function run_capture(cmd)
    -- Write command output to temp file
    local tmp = "/data/tmp_out.txt"
    os.execute(cmd .. " > " .. tmp .. " 2>&1")
    
    -- Read file
    local f = io.open(tmp, "r")
    if f then
        local content = f:read("*all")
        f:close()
        os.execute("rm " .. tmp)
        return content
    end
    return nil
end

local function test(name, cmd)
    print("--- " .. name .. " ---")
    local out = run_capture(cmd)
    if out then
        print(out)
    else
        print("(no output or error)")
    end
    print("")
end

test("uname", "uname -a")
test("id", "id")
test("root", "ls -la /")
test("dev", "ls -la /dev/")
test("mount", "mount")
test("env", "env")
test("processes", "ps 2>/dev/null || ps aux 2>/dev/null || echo ps_failed")
test("shell", "echo $0 && which sh")
test("kernel_info", "sysctl kern.ostype kern.osrelease 2>/dev/null || sysctl -a 2>/dev/null | head -20 || echo sysctl_failed")
test("proc_self", "ls -la /proc/self/ 2>/dev/null || echo no_procfs")
test("data", "ls -la /data/")
test("system", "ls -la /system/ 2>/dev/null || echo no_system")
test("app0", "ls -la /app0/ 2>/dev/null || echo no_app0")
test("preinst", "ls -la /preinst/ 2>/dev/null || echo no_preinst")
test("update", "ls -la /update/ 2>/dev/null || echo no_update")
test("recovery", "ls -la /recovery/ 2>/dev/null || echo no_recovery")
test("firmware", "ls -la /firmware/ 2>/dev/null || echo no_firmware")
test("lib", "ls -la /lib/ 2>/dev/null || echo no_lib")
test("bin", "ls -la /bin/ 2>/dev/null || echo no_bin")
test("sbin", "ls -la /sbin/ 2>/dev/null || echo no_sbin")
test("usr", "ls -la /usr/ 2>/dev/null || echo no_usr")
test("modules", "lsmod 2>/dev/null || cat /proc/modules 2>/dev/null || echo no_modules")

print("Done!")
