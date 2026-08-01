-- Use io.popen to execute and capture
print("=== io.popen exploration ===\n")

local function run(cmd)
    print("> " .. cmd)
    local ok, f = pcall(io.popen, cmd, "r")
    if ok and f then
        local out = f:read("*all")
        f:close()
        print(out)
    else
        print(string.format("  ERROR: %s", tostring(f)))
    end
    print("")
end

run("uname -a 2>&1")
run("id 2>&1")
run("cat /proc/version 2>&1")
run("cat /etc/fstab 2>&1 || true")
run("mount 2>&1")
run("ls -la / 2>&1")
run("ls -la /av_contents/ 2>&1")
run("ls -la /av_contents/content_tmp/ 2>&1")
run("ls -la /savedata0/ 2>&1")
run("df -h 2>&1")
run("env 2>&1")
run("ps 2>&1 || ps aux 2>&1 || true")
run("cat /proc/self/maps 2>&1 || true")
run("cat /proc/self/status 2>&1 || true")
run("sysctl -a 2>&1 | head -50 || true")

print("Done!")
