-- Explore /dev/ and try to access kernel memory
print("=== /dev/ exploration ===\n")

-- Use syscall 5 (open) to check /dev/ entries
local wt = syscall.syscall_wrapper

local function open_file(path)
    local buf = memory.alloc(512)
    memory.write_buffer(buf, 0, path)
    
    -- open(path, O_RDONLY, 0) = syscall 5
    local ok, ret = pcall(native.fcall, wt[5], buf, 0, 0, 0, 0, 0)
    if ok then
        local fd = 0
        if type(ret) == "table" then fd = ret.h * 4294967296 + ret.l end
        if fd >= 0 then
            return fd
        end
    end
    return nil, ret
end

local function close_fd(fd)
    pcall(native.fcall, wt[6], fd, 0, 0, 0, 0, 0)
end

-- Check various kernel memory devices
local devs = {
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/io",
    "/dev/fb0",
    "/dev/fb",
    "/dev/gpu",
    "/dev/dri",
    "/dev/dri/card0",
    "/dev/dma",
    "/dev/sce",
    "/dev/scesys",
}

print("--- Opening devices ---")
for _, dev in ipairs(devs) do
    local to_write = dev .. "\0"
    local buf = memory.alloc(#to_write + 1)
    memory.write_buffer(buf, 0, to_write)
    
    local ok, ret = pcall(native.fcall, wt[5], buf, 0, 0, 0, 0, 0)
    if ok then
        local fd = 0
        if type(ret) == "table" then fd = ret.h * 4294967296 + ret.l end
        if fd >= 0 then
            print(string.format("  %s: fd=%d (SUCCESS!)", dev, fd))
            if fd > 2 then close_fd(fd) end
        elseif fd == -1 then
            print(string.format("  %s: fd=-1 (access denied)", dev))
        else
            print(string.format("  %s: fd=0x%x", dev, fd))
        end
    else
        print(string.format("  %s: error %s", dev, tostring(ret)))
    end
end

-- Try open("/", O_RDONLY)
print("\n--- Opening / (directory) ---")
local path = "/\0"
local buf = memory.alloc(#path)
memory.write_buffer(buf, 0, path)
local ok, ret = pcall(native.fcall, wt[5], buf, 0, 0, 0, 0, 0)
if ok then
    local fd = 0
    if type(ret) == "table" then fd = ret.h * 4294967296 + ret.l end
    print(string.format("  open('/') ret = 0x%x", fd))
    if fd > 2 then close_fd(fd) end
end

-- Try stat syscall to check if /dev/kmem exists
-- stat syscall = 188 on FreeBSD
print("\n--- stat /dev/kmem ---")
local sb = memory.alloc(144) -- stat struct
memory.write_buffer(buf, 0, "/dev/kmem\0")
local ok, ret = pcall(native.fcall, wt[188], buf, sb, 0, 0, 0, 0)
if ok then
    local r = 0
    if type(ret) == "table" then r = ret.h * 4294967296 + ret.l end
    print(string.format("  stat ret = 0x%x", r))
    if r == 0 then
        print("  /dev/kmem EXISTS!")
        -- Read device type/mode
        local mode = memory.read_qword(sb + 4)
        local dev = memory.read_qword(sb + 12)
        print(string.format("  mode=0x%x dev=0x%x", mode.l or 0, dev.l or 0))
    end
end

-- Try to read /proc/self/map_files or /proc/self/mem
print("\n--- Try /proc/self/mem ---")
memory.write_buffer(buf, 0, "/proc/self/mem\0")
local ok, ret = pcall(native.fcall, wt[5], buf, 2, 0, 0, 0, 0)  -- O_RDWR = 2
if ok then
    local fd = 0
    if type(ret) == "table" then fd = ret.h * 4294967296 + ret.l end
    print(string.format("  open /proc/self/mem: ret=0x%x", fd))
    if fd > 2 then
        -- Try to read from it
        local rdbuf = memory.alloc(16)
        local ok, r = pcall(native.fcall, wt[3], fd, rdbuf, 16, 0, 0, 0)
        if ok then
            local hex = ""
            for i = 0, 15 do
                local b = memory.read_byte(rdbuf + i)
                hex = hex .. string.format("%02x", b.l)
            end
            print(string.format("  read result: %s", hex))
        end
        close_fd(fd)
    end
end

-- Check if ptrace is available (syscall 26)
print("\n--- ptrace test ---")
local ok, ret = pcall(native.fcall, wt[26], 0, 0, 0, 0, 0, 0)  -- PT_TRACE_ME
if ok then
    local r = 0
    if type(ret) == "table" then r = ret.h * 4294967296 + ret.l end
    print(string.format("  ptrace ret = 0x%x", r))
end

print("\nDone!")
