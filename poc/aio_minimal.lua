--[[
    aio_minimal.lua
    Minimal AIO test: resolve syscalls via S.resolve and call them
]]
local S = rawget(_G, "syscall")
local mem = rawget(_G, "memory")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

print("[+] AIO Minimal Test\n")

-- Resolve AIO syscalls like lapse.lua does
S.resolve({
    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_poll = 0x298,
    aio_multi_cancel = 0x29a,
    aio_submit_cmd = 0x29d,
    getpid = 20,
})

-- Test each with null args (should return -1 safely)
local pid = tonn(S.getpid())
print(string.format("PID = %d\n", pid))

local r
r = tonn(S.aio_multi_delete(0, 0, 0))
print(string.format("aio_multi_delete(0,0,0) = %d", r))

r = tonn(S.aio_multi_wait(0, 0, 0, 0, 0))
print(string.format("aio_multi_wait(0,0,0,0,0) = %d", r))

r = tonn(S.aio_multi_poll(0, 0, 0))
print(string.format("aio_multi_poll(0,0,0) = %d", r))

r = tonn(S.aio_multi_cancel(0, 0, 0))
print(string.format("aio_multi_cancel(0,0,0) = %d", r))

r = tonn(S.aio_submit_cmd(0, 0, 0, 0, 0))
print(string.format("aio_submit_cmd(0,0,0,0,0) = %d", r))

print("\n[+] All AIO syscalls return safely!")
