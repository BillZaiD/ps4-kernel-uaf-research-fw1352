-- Use os.execute + file write to capture output
print("=== os.execute + file I/O ===\n")

local WRITE_DIR = "/av_contents/content_tmp/"
local timestamp = tostring(os.time())
local outfile = WRITE_DIR .. "exec_out_" .. timestamp .. ".txt"

local function run(cmd)
    print("> " .. cmd)
    local full_cmd = cmd .. " > " .. outfile .. " 2>&1"
    local ok, ret = pcall(os.execute, full_cmd)
    print(string.format("  os.execute ret=%s", tostring(ret)))
    
    -- Read output
    local fok, f = pcall(io.open, outfile, "r")
    if fok and f then
        local content = f:read("*all")
        f:close()
        if content and #content > 0 then
            print(content)
        else
            print("  (empty output)")
        end
    else
        print(string.format("  io.open error: %s", tostring(f)))
    end
    print("")
end

run("uname -a")
run("id")
run("cat /etc/fstab")
run("mount")
run("ls -la /")
run("ls -la /av_contents/")
run("ls -la /av_contents/content_tmp/")
run("ls -la /savedata0/")
run("env")
run("ps")
run("sysctl -a 2>/dev/null | head -30")
run("cat /proc/cpuinfo")
run("cat /proc/version")
run("cat /proc/self/maps")
run("cat /proc/self/status")

-- Clean up
pcall(os.execute, "rm -f " .. outfile)

print("Done!")
