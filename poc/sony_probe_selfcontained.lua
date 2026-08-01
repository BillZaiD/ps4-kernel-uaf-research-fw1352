--[[
    sony_probe_selfcontained.lua
    Sony syscall probe 452-599 - no external dependencies
]]

-- Inline utilities
local mem = rawget(_G, "memory")
local nat = rawget(_G, "native")
local sys = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

local function find_trampoline(w, limit)
    limit = limit or 35
    for i = 0, limit do
        local b1 = mem.read_byte(w + i)
        local b2 = mem.read_byte(w + i + 1)
        local b3 = mem.read_byte(w + i + 2)
        if b1 == 0x49 and b2 == 0x89 and b3 == 0xCA then
            return i
        end
    end
    return 7
end

local function fcall(scno, rdi, rsi, rdx, rcx, r8, r9)
    local w = toaddr(sys.syscall_wrapper[scno])
    if w == 0 then return nil end
    local tramp = w + find_trampoline(w)
    return tonn(nat.fcall_with_rax(tramp, scno, rdi or 0, rsi or 0, rdx or 0, rcx or 0, r8 or 0, r9 or 0))
end

local function has_wrapper(sc)
    return sys.syscall_wrapper[sc] ~= nil
end

local function is_kptr(v)
    return v >= 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF
end

 -- Allocate read buffer
 local outbuf = mem.alloc(4096)

-- Clear buffer
for j = 0, 4095 do
    mem.write_byte(outbuf + j, 0)
end

print("[+] Sony syscall 452-599 self-contained probe\n")

-- Phase 1: Check availability
local avail = {}
local miss = {}
for sc = 452, 599 do
    if has_wrapper(sc) then
        avail[#avail + 1] = sc
    else
        miss[#miss + 1] = sc
    end
end
print(string.format("[+] Available: %d, Missing: %d", #avail, #miss))

-- Phase 2: Test each available Sony syscall with zero args
print("\n[*] Testing Sony syscalls (452-599) with zero args:\n")
local interesting = {}

for _, sc in ipairs(avail) do
    local w = toaddr(sys.syscall_wrapper[sc])
    local b0 = mem.read_byte(w)
    if b0 == 72 then  -- valid wrapper (mov rax)
        local ret = fcall(sc, 0, 0, 0, 0, 0, 0)
        
        local analysis = ""
        if ret == -1 or ret == 0xFFFFFFFFFFFFFFFF then
            analysis = "(-1)"
        elseif ret == 0 then
            analysis = "(0)"
        elseif is_kptr(ret) then
            analysis = "(KERNEL PTR!)"
        elseif ret > 0 and ret < 1000 then
            analysis = "(small: " .. ret .. ")"
        elseif ret > 1000 then
            analysis = "(large: " .. ret .. ")"
        else
            analysis = "(0x" .. string.format("%x", ret) .. ")"
        end
        
        if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= 0 then
            print(string.format("  sc%d (zero) -> %s <---", sc, analysis))
            interesting[#interesting + 1] = {sc = sc, ret = ret}
        end

        -- Test with outbuf as arg1
        if ret == -1 or ret == 0xFFFFFFFFFFFFFFFF then
            for j = 0, 255 do
                mem.write_byte(outbuf + j, 0)
            end
            local ret2 = fcall(sc, outbuf, 256, 0, 0, 0, 0)
            if ret2 ~= -1 and ret2 ~= 0xFFFFFFFFFFFFFFFF and ret2 ~= 0 then
                print(string.format("  sc%d (buf) -> %d (0x%x) <---", sc, ret2, ret2))
                -- Check buffer contents
                for j = 0, 255, 8 do
                    local val = tonn(mem.read_qword(outbuf + j))
                    if val ~= 0 then
                        if is_kptr(val) then
                            print(string.format("    [!] KPTR at +0x%x: 0x%x", j, val))
                        else
                            print(string.format("    [*] data at +0x%x: 0x%x", j, val))
                        end
                    end
                end
                interesting[#interesting + 1] = {sc = sc, ret = ret2, mode = "outbuf"}
            end
        end
    end
end

-- Phase 3: Test fork, ptrace, chroot
print("\n[*] Testing fork (sc2)...")
if has_wrapper(2) then
    local ret = fcall(2, 0, 0, 0, 0, 0, 0)
    print(string.format("  fork() = %d (0=child, >0=parent, <0=error)", ret))
end

print("\n[*] Testing ptrace (sc59)...")
if has_wrapper(59) then
    -- PT_TRACE_ME = 0
    local r0 = fcall(59, 0, 0, 0, 0, 0, 0)
    print(string.format("  ptrace(PTRACE_TRACEME) -> %d", r0))
    -- PT_ATTACH = 1, pid=-1
    local r1 = fcall(59, 1, -1, 0, 0, 0, 0)
    print(string.format("  ptrace(PT_ATTACH, -1) -> %d", r1))
    -- PT_IO = 5, with kernel addr
    for j = 0, 63 do mem.write_byte(outbuf + j, 0) end
    local r2 = fcall(59, 5, 999999, 0xFFFFFFFF80000000, outbuf, 8, 0)
    print(string.format("  ptrace(PT_IO, 999999, kernel) -> %d", r2))
end

print("\n[*] Testing chroot (sc12)...")
if has_wrapper(12) then
    local r0 = fcall(12, 0, 0, 0, 0, 0, 0)
    print(string.format("  chroot(NULL) -> %d", r0))
end

-- Phase 4: Summary
print("\n[+] === RESULTS ===")
if #interesting == 0 then
    print("[+] All Sony syscalls return -1 with zero args and outbuf")
    print("[+] No obvious info leak from 452-599 range")
else
    print(string.format("[+] %d interesting syscalls found:", #interesting))
    for _, e in ipairs(interesting) do
        print(string.format("  sc%d: %s ret=0x%x", e.sc, e.mode or "zero", e.ret))
    end
end

print("\n[+] Done")
