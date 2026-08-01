-- Read files from PS4 filesystem
print("=== PS4 Filesystem Read ===\n")

local function read_file(path)
    local ok, f = pcall(io.open, path, "r")
    if ok and f then
        local content = f:read("*all")
        f:close()
        if content and #content > 0 then
            return content
        end
        return "(empty)"
    end
    return nil
end

local function try_read(name, path)
    local c = read_file(path)
    if c then
        print(string.format("--- %s (%s) ---", name, path))
        if #c > 500 then
            print(string.sub(c, 1, 500) .. "\n...(truncated, total " .. #c .. " bytes)")
        else
            print(c)
        end
        print("")
    else
        print(string.format("[%s] NOT FOUND: %s", name, path))
    end
end

-- Framework files
try_read("main.lua", "/savedata0/main.lua")
try_read("syscall.lua", "/savedata0/syscall.lua")
try_read("native.lua", "/savedata0/native.lua")
try_read("lua.lua", "/savedata0/lua.lua")
try_read("kernel.lua", "/savedata0/kernel.lua")
try_read("gpu.lua", "/savedata0/gpu.lua")
try_read("misc.lua", "/savedata0/misc.lua")
try_read("offsets.lua", "/savedata0/offsets.lua")

-- System files
try_read("hosts", "/etc/hosts")
try_read("fstab", "/etc/fstab")
try_read("passwd", "/etc/passwd")

-- Game files
try_read("eboot.bin", "/app0/eboot.bin")

-- Kernel modules
try_read("libkernel", "/system/common/lib/libkernel.sprx")

print("Done!")
