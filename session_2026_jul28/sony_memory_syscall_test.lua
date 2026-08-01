--[[
    sony_memory_syscall_test.lua
    Targeted probe for Sony memory syscalls (597, 599, 600, 623-627)
    Tests for missing validation on user-controlled sizes,
    info leaks via oversized buffers, and integer overflow in size calcs.

    Platform: PS4 FW 13.52 (HeerBSD, 16KB pages)
    Safety: fcall_with_rax catches crashes via longjmp; no writes to kernel
    Deploy: via remote Lua loader on PS4
]]

-- ============================================================
-- SECTION 0: Self-contained primitives
-- ============================================================

local M = rawget(_G, "memory")
local N = rawget(_G, "native")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then
        return v.h * 4294967296 + v.l
    end
    local n = tonumber(tostring(v))
    return n or 0
end

local function is_kptr(v)
    return v >= 0xFFFFFFFF80000000 and v <= 0xFFFFFFFFFFFFFFFF
end

local function is_userspace(v)
    return v >= 0x10000 and v <= 0x7FFFFFFFFFFF
end

local function hex8(v)
    return string.format("0x%016x", v)
end

local function scan_kptrs(buf, len)
    local ptrs = {}
    local align = 8
    if len < 8 then align = 1 end
    for j = 0, len - 8, align do
        local v = tonn(M.read_qword(buf + j))
        if is_kptr(v) then
            table.insert(ptrs, {offset = j, value = v})
        end
    end
    return ptrs
end

local function hexdump(buf, len)
    local s = {}
    for i = 0, len - 1 do
        s[#s + 1] = string.format("%02x", tonn(M.read_byte(buf + i)))
    end
    return table.concat(s, " ")
end

local function zero_buf(buf, len)
    for i = 0, len - 1 do M.write_byte(buf + i, 0) end
end

local function fill_buf(buf, len, val)
    for i = 0, len - 1 do M.write_byte(buf + i, val) end
end

local function sc_call(scno, a1, a2, a3, a4, a5, a6)
    local stubs = S.syscall_wrapper
    local w = tonn(stubs[scno])
    local tramp
    if w ~= 0 then
        tramp = w + 10
    else
        local gw = tonn(stubs[20])
        tramp = gw + 10
    end
    return tonn(N.fcall_with_rax(tramp, scno,
        a1 or 0, a2 or 0, a3 or 0,
        a4 or 0, a5 or 0, a6 or 0))
end

-- ============================================================
-- SECTION 1: Allocate all buffers up front
-- ============================================================

local BUF_SIZE   = 0x40000   -- 256KB main working buffer
local BIG_SIZE   = 0x100000  -- 1MB overflow detection buffer
local SCAN_SIZE  = 0x10000   -- 64KB scan window
local PAGE       = 0x4000    -- 16KB (PS4 page size)
local HALF_PAGE = 0x8000

local work_buf   = M.alloc(BUF_SIZE)
local big_buf    = M.alloc(BIG_SIZE)
local out_buf    = M.alloc(PAGE)
local scan_buf   = M.alloc(SCAN_SIZE)
local size_slot  = M.alloc(16)
local addr_slot  = M.alloc(16)

zero_buf(work_buf, BUF_SIZE)
zero_buf(big_buf, BIG_SIZE)
zero_buf(out_buf, PAGE)
zero_buf(scan_buf, SCAN_SIZE)
zero_buf(size_slot, 16)
zero_buf(addr_slot, 16)

print(string.rep("=", 70))
print("  SONY MEMORY SYSCALL PROBE - FW 13.52")
print("  Target: syscalls 597, 599, 600, 623-627")
print("  Goal: info leaks, missing validation, int overflow")
print("  Safety: longjmp recovery; no kernel writes")
print(string.rep("=", 70))

-- Quick sanity check
local pid = sc_call(20)
print(string.format("\nSanity: getpid() = %d (should be > 0)", pid))
if pid == 0 or pid == 0xFFFFFFFF then
    print("FATAL: syscall path broken, aborting")
    return
end

-- ============================================================
-- SECTION 2: Syscall mapping with zero/one/edge args
-- ============================================================

local TARGET_SYSCALLS = {
    {scno = 597, name = "dynlib_get_info(unknown)",
     desc = "Between dynlib_get_info_for_libkernel(596) and dynlib_get_list_for_libkernel(598)"},
    {scno = 599, name = "dynlib_get_info2",
     desc = "Module info retrieval (v2)"},
    {scno = 600, name = "dynlib_get_list2",
     desc = "Module list retrieval (v2)"},
    {scno = 623, name = "sceKernelMapFlexibleMemory",
     desc = "Map flexible memory region"},
    {scno = 624, name = "sceKernelRemapBlock",
     desc = "Remap a memory block"},
    {scno = 625, name = "sceKernelGetDirectMemoryType",
     desc = "Query direct memory type"},
    {scno = 626, name = "sceKernelMmap",
     desc = "Custom mmap (PS4-specific)"},
    {scno = 627, name = "sceKernelReserveVirtualRange2",
     desc = "Reserve virtual address range (v2)"},
}

print("\n" .. string.rep("-", 70))
print("PHASE 1: Return value mapping (zero/one/edge args)")
print(string.rep("-", 70))

local results = {}
for _, sc in ipairs(TARGET_SYSCALLS) do
    results[sc.scno] = {name = sc.name, interesting = false, leak_found = false}
end

-- Test patterns:
-- 1: all zeros  2: one in each arg  3: -1 in each arg
-- 4: 0x1000 in each  5: addr_slot pointer
local patterns = {
    {label = "all zeros",
     a = {0, 0, 0, 0, 0, 0}},
    {label = "a1=1",
     a = {1, 0, 0, 0, 0, 0}},
    {label = "a2=1",
     a = {0, 1, 0, 0, 0, 0}},
    {label = "a3=1",
     a = {0, 0, 1, 0, 0, 0}},
    {label = "a4=1",
     a = {0, 0, 0, 1, 0, 0}},
    {label = "a5=1",
     a = {0, 0, 0, 0, 1, 0}},
    {label = "a6=1",
     a = {0, 0, 0, 0, 0, 1}},
    {label = "all -1",
     a = {-1, -1, -1, -1, -1, -1}},
    {label = "a1=outbuf, a2=PAGE",
     a = {out_buf, PAGE, 0, 0, 0, 0}},
    {label = "a1=addr_slot, a2=0x100",
     a = {addr_slot, 0x100, 0, 0, 0, 0}},
}

for _, sc in ipairs(TARGET_SYSCALLS) do
    print(string.format("\n[%d] %s (%s)", sc.scno, sc.name, sc.desc))
    for _, pat in ipairs(patterns) do
        zero_buf(out_buf, PAGE)
        local ret = sc_call(sc.scno,
            pat.a[1], pat.a[2], pat.a[3],
            pat.a[4], pat.a[5], pat.a[6])
        local tag = ""
        if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= 0 then
            tag = " <<<< INTERESTING"
            results[sc.scno].interesting = true
        elseif ret == 0 then
            tag = " (ret=0, check buf)"
            -- Still scan output buffer for leaks even on success=0
        end

        -- Scan output buffers for kernel pointers
        local kptrs = scan_kptrs(out_buf, 256)
        if #kptrs > 0 then
            tag = tag .. "  *** KPTR LEAK ***"
            results[sc.scno].leak_found = true
            for _, kp in ipairs(kptrs) do
                tag = tag .. string.format("\n      KPTR at +0x%x: %s", kp.offset, hex8(kp.value))
            end
        end

        -- Also scan addr_slot in case the syscall wrote a pointer there
        local slot_kptrs = scan_kptrs(addr_slot, 16)
        if #slot_kptrs > 0 then
            tag = tag .. "  *** SLOT KPTR ***"
            results[sc.scno].leak_found = true
            for _, kp in ipairs(slot_kptrs) do
                tag = tag .. string.format("\n      SLOT KPTR: %s", hex8(kp.value))
            end
        end

        print(string.format("  %-30s -> %s%s", pat.label, hex8(ret), tag))
    end
end

-- ============================================================
-- SECTION 3: Size validation testing
-- Tests whether the syscalls properly validate size arguments
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 2: Size validation fuzzing")
print(string.rep("-", 70))

local sizes_to_test = {
    0,
    1,
    0x100,
    0x1000,
    PAGE,
    0x10000,
    0x100000,         -- 1MB
    0x1000000,        -- 16MB
    0x10000000,       -- 256MB
    0x100000000,      -- 4GB (32-bit overflow boundary)
    0x7FFFFFFF,       -- INT32_MAX
    0x80000000,       -- INT32_MAX + 1
    0xFFFFFFFF,       -- UINT32_MAX
    0x100000000,      -- 4GB exact
    0x200000000,      -- 8GB
    0x7FFFFFFFFFFF,   -- Max userspace on some archs
    0x1000000000,     -- High bits set
}

local clean_sizes = {}
for _, s in ipairs(sizes_to_test) do
    if s ~= nil then
        table.insert(clean_sizes, s)
    end
end

for _, sc in ipairs(TARGET_SYSCALLS) do
    print(string.format("\n[%d] %s - size validation", sc.scno, sc.name))
    for _, sz in ipairs(clean_sizes) do
        zero_buf(out_buf, PAGE)
        -- Use a3 or a2 as size (common for memory syscalls)
        local ret = sc_call(sc.scno,
            out_buf, sz, 3,
            0, 0, 0)

        if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
            print(string.format("  size=0x%x -> ret=%s (NOT -1!)", sz, hex8(ret)))
            -- Check for kernel pointers
            local kptrs = scan_kptrs(out_buf, 512)
            if #kptrs > 0 then
                print(string.format("    *** KPTR LEAK with size=0x%x ***", sz))
                for _, kp in ipairs(kptrs) do
                    print(string.format("      +0x%x: %s", kp.offset, hex8(kp.value)))
                end
            end
        end
    end
end

-- ============================================================
-- SECTION 4: Integer overflow in size calculations
-- Pass sizes that when multiplied/shifted might wrap
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 3: Integer overflow candidates")
print("Passing sizes that might overflow in kernel size calculations")
print(string.rep("-", 70))

local overflow_sizes = {
    {desc = "0x10000 * 0x10000 (if kernel mul)",  val = 0x100000000},
    {desc = "0x1000 * 0x1000 (if kernel mul)",   val = 0x1000000},
    {desc = "PAGE * 0x10000",                     val = PAGE * 0x10000},
    {desc = "0xFFFFFFFF * 2 + 2 (wrap to 0)",    val = 0},
    {desc = "0x7FFFFFFF + 1 (sign flip)",         val = 0x80000000},
    {desc = "0xFFFFFFFF + 1 (32-bit wrap)",       val = 0x100000000},
    {desc = "Max 53-bit double size",              val = 0x1FFFFFFFFFFFFF},
    {desc = "Half page (8192)",                    val = 0x2000},
    {desc = "Page - 1 (16383)",                    val = PAGE - 1},
    {desc = "Page + 1 (16385)",                    val = PAGE + 1},
    {desc = "2 pages (32768)",                     val = PAGE * 2},
    {desc = "16KB * 1024 (16MB)",                  val = PAGE * 1024},
}

for _, sc in ipairs(TARGET_SYSCALLS) do
    print(string.format("\n[%d] %s - overflow tests", sc.scno, sc.name))
    for _, ov in ipairs(overflow_sizes) do
        if ov.val ~= 0 then  -- skip zero-value entries
            zero_buf(out_buf, PAGE)
            fill_buf(scan_buf, SCAN_SIZE, 0xAA)
            local ret = sc_call(sc.scno,
                out_buf, ov.val, 3,
                scan_buf, 0, 0)
            if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
                print(string.format("  %s = ret=%s", ov.desc, hex8(ret)))
                -- Deep scan all buffers for kernel pointers
                local kptrs = scan_kptrs(out_buf, PAGE)
                local kptrs2 = scan_kptrs(scan_buf, SCAN_SIZE)
                for _, kp in ipairs(kptrs) do
                    print(string.format("    OUTBUF KPTR +0x%x: %s", kp.offset, hex8(kp.value)))
                end
                for _, kp in ipairs(kptrs2) do
                    print(string.format("    SCANBUF KPTR +0x%x: %s", kp.offset, hex8(kp.value)))
                end
            end
        end
    end
end

-- ============================================================
-- SECTION 5: Oversized buffer info leak scan
-- Pass large output buffers and scan for kernel pointers
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 4: Oversized buffer leak scan")
print("Passing large output buffers, scanning for kernel pointers")
print(string.rep("-", 70))

local oversized_tests = {
    {scno = 597, a1 = out_buf, a2 = 0x10000, a3 = 0,
     label = "597 with 64KB outbuf"},
    {scno = 599, a1 = out_buf, a2 = 0x10000, a3 = 0,
     label = "599 dynlib_get_info2 with 64KB outbuf"},
    {scno = 600, a1 = out_buf, a2 = 0x10000, a3 = 0,
     label = "600 dynlib_get_list2 with 64KB outbuf"},
    {scno = 623, a1 = out_buf, a2 = 0x10000, a3 = 3,
     label = "623 MapFlexible with 64KB buf"},
    {scno = 624, a1 = out_buf, a2 = 0x10000, a3 = 0,
     label = "624 RemapBlock with 64KB buf"},
    {scno = 625, a1 = out_buf, a2 = big_buf, a3 = 0x10000,
     label = "625 GetDirectMemType with 64KB outbuf"},
    {scno = 626, a1 = out_buf, a2 = 0x10000, a3 = 7,
     label = "626 Mmap with 64KB"},
    {scno = 627, a1 = out_buf, a2 = 0x10000, a3 = 3,
     label = "627 ReserveVirtualRange2 with 64KB"},
}

for _, test in ipairs(oversized_tests) do
    zero_buf(out_buf, PAGE)
    zero_buf(big_buf, BIG_SIZE)

    local ret = sc_call(test.scno,
        test.a1, test.a2, test.a3,
        test.a4 or 0, test.a5 or 0, test.a6 or 0)

    print(string.format("\n  %s -> ret=%s", test.label, hex8(ret)))

    -- Scan the first 64KB of the big buffer
    local kptrs = scan_kptrs(big_buf, SCAN_SIZE)
    if #kptrs > 0 then
        print(string.format("  *** %d KERNEL POINTERS in big_buf! ***", #kptrs))
        for _, kp in ipairs(kptrs) do
            print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
        end
    end

    -- Also scan out_buf
    local kptrs2 = scan_kptrs(out_buf, PAGE)
    if #kptrs2 > 0 then
        print(string.format("  *** %d KERNEL POINTERS in out_buf! ***", #kptrs2))
        for _, kp in ipairs(kptrs2) do
            print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
        end
    end

    -- If it returned positive, dump first 128 bytes
    if ret > 0 and ret < 0x100000 then
        print(string.format("  Hex dump of out_buf (min %d bytes):", math.min(ret, 128)))
        print(string.format("    %s", hexdump(out_buf, math.min(ret, 128))))
    end
end

-- ============================================================
-- SECTION 6: Pointer-as-size and size-as-pointer confusion
-- Tests if the syscall confuses pointer and size arguments
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 5: Pointer/size confusion tests")
print("Passing kernel-like pointers as sizes and vice versa")
print(string.rep("-", 70))

local confuse_addrs = {
    0xFFFFFFFF80000000,
    0xFFFFFFFF80001000,
    0xFFFFFFFF80010000,
    0xFFFFFFFF82000000,
    0xFFFFFFFF83000000,
    0xFFFFFFFFC0000000,
    0xFFFFFFFFFE000000,
    0x00000000DEADBEEF,
    0x00000000CAFEBABE,
    0x0000000041414141,
}

for _, sc in ipairs(TARGET_SYSCALLS) do
    print(string.format("\n[%d] %s - ptr/size confusion", sc.scno, sc.name))
    for _, bad_ptr in ipairs(confuse_addrs) do
        zero_buf(out_buf, PAGE)

        -- Pass kernel address as a1 (output buffer?)
        local ret = sc_call(sc.scno,
            bad_ptr, PAGE, 3,
            0, 0, 0)
        if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= 0 then
            print(string.format("  a1=kptr(0x%x) -> ret=%s", bad_ptr, hex8(ret)))
            local kptrs = scan_kptrs(out_buf, PAGE)
            for _, kp in ipairs(kptrs) do
                print(string.format("    LEAK: +0x%x = %s", kp.offset, hex8(kp.value)))
            end
        end

        zero_buf(out_buf, PAGE)

        -- Pass kernel address as size (a2)
        ret = sc_call(sc.scno,
            out_buf, bad_ptr, 3,
            0, 0, 0)
        if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF and ret ~= 0 then
            print(string.format("  a2=kptr(0x%x) -> ret=%s", bad_ptr, hex8(ret)))
            local kptrs = scan_kptrs(out_buf, PAGE)
            for _, kp in ipairs(kptrs) do
                print(string.format("    LEAK: +0x%x = %s", kp.offset, hex8(kp.value)))
            end
        end
    end
end

-- ============================================================
-- SECTION 7: Cross-syscall interaction
-- Use fds from kqueue/pipe/socket with memory syscalls
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 6: Cross-syscall interaction")
print("Passing kqueue/pipe/socket fds to memory syscalls")
print(string.rep("-", 70))

-- Create test fds
local pipe_buf = M.alloc(8)
zero_buf(pipe_buf, 8)
local pipe_ret = sc_call(42, pipe_buf, 0)
local rd_fd = -1
local wr_fd = -1
if pipe_ret == 0 then
    rd_fd = tonn(M.read_dword(pipe_buf))
    wr_fd = tonn(M.read_dword(pipe_buf + 4))
    print(string.format("  Pipe created: rd=%d wr=%d", rd_fd, wr_fd))
end

local kq_fd = sc_call(362)
if kq_fd >= 0 and kq_fd < 1024 then
    print(string.format("  Kqueue created: fd=%d", kq_fd))
end

local cross_fds = {}
if rd_fd >= 0 then table.insert(cross_fds, {fd = rd_fd, name = "pipe_rd"}) end
if wr_fd >= 0 then table.insert(cross_fds, {fd = wr_fd, name = "pipe_wr"}) end
if kq_fd >= 0 then table.insert(cross_fds, {fd = kq_fd, name = "kqueue"}) end

if #cross_fds > 0 then
    for _, sc in ipairs(TARGET_SYSCALLS) do
        print(string.format("\n[%d] %s - cross-fd tests", sc.scno, sc.name))
        for _, cf in ipairs(cross_fds) do
            zero_buf(out_buf, PAGE)
            -- Pass fd as various arguments
            local ret = sc_call(sc.scno,
                cf.fd, PAGE, 3,
                0, 0, 0)
            if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
                print(string.format("  fd=%s(%d) as a1 -> ret=%s",
                    cf.name, cf.fd, hex8(ret)))
            end

            zero_buf(out_buf, PAGE)
            ret = sc_call(sc.scno,
                out_buf, cf.fd, 3,
                0, 0, 0)
            if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
                print(string.format("  fd=%s(%d) as a2 -> ret=%s",
                    cf.name, cf.fd, hex8(ret)))
            end
        end
    end
else
    print("  No test fds available, skipping")
end

-- Cleanup fds
if rd_fd >= 0 then sc_call(6, rd_fd) end
if wr_fd >= 0 then sc_call(6, wr_fd) end
if kq_fd >= 0 then sc_call(6, kq_fd) end
M.write_dword(pipe_buf, 0)
M.write_dword(pipe_buf + 4, 0)

-- ============================================================
-- SECTION 8: GetProcessMemoryMap (636) deep scan
-- This is the most likely info leak vector among memory syscalls
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 7: sceKernelGetProcessMemoryMap (636) deep scan")
print("This lists all memory mappings - may contain kernel pointers")
print(string.rep("-", 70))

-- Allocate a large buffer for memory map data
local mmap_buf = M.alloc(0x10000)  -- 64KB
zero_buf(mmap_buf, 0x10000)

local ret636 = sc_call(636, mmap_buf, 0x10000, 0, 0, 0, 0)
print(string.format("  sc636(mmap_buf, 64KB) = %s", hex8(ret636)))

if ret636 > 0 and ret636 < 0x100000 then
    -- Scan entire returned data
    local kptrs = scan_kptrs(mmap_buf, math.min(ret636, 0x10000))
    print(string.format("  Kernel pointers found: %d", #kptrs))
    for _, kp in ipairs(kptrs) do
        print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
    end

    -- Print first 256 bytes as hex
    print(string.format("  First 256 bytes:"))
    print(string.format("    %s", hexdump(mmap_buf, 256)))

    -- Try different sizes
    for _, sz in ipairs({0x1000, 0x2000, 0x4000, 0x8000, 0x10000}) do
        zero_buf(mmap_buf, 0x10000)
        local r = sc_call(636, mmap_buf, sz, 0, 0, 0, 0)
        if r ~= -1 and r ~= 0xFFFFFFFFFFFFFFFF and r > 0 then
            local kptrs = scan_kptrs(mmap_buf, math.min(r, sz))
            if #kptrs > 0 then
                print(string.format("  sc636(size=%d): %d kernel ptrs!", sz, #kptrs))
                for _, kp in ipairs(kptrs) do
                    print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
                end
            end
        end
    end
end

-- ============================================================
-- SECTION 9: sceKernelGetDirectMemoryAll (637) deep scan
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 8: sceKernelGetDirectMemoryAll (637) deep scan")
print(string.rep("-", 70))

zero_buf(mmap_buf, 0x10000)
local ret637 = sc_call(637, mmap_buf, 0x10000, 0, 0, 0, 0)
print(string.format("  sc637(mmap_buf, 64KB) = %s", hex8(ret637)))

if ret637 > 0 and ret637 < 0x100000 then
    local kptrs = scan_kptrs(mmap_buf, math.min(ret637, 0x10000))
    print(string.format("  Kernel pointers found: %d", #kptrs))
    for _, kp in ipairs(kptrs) do
        print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
    end
    print(string.format("  First 256 bytes:"))
    print(string.format("    %s", hexdump(mmap_buf, 256)))
end

-- ============================================================
-- SECTION 10: sceKernelGetPthreadMemoryInfo (639)
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 9: sceKernelGetPthreadMemoryInfo (639)")
print(string.rep("-", 70))

zero_buf(mmap_buf, 0x10000)
local ret639 = sc_call(639, mmap_buf, 0x10000, 0, 0, 0, 0)
print(string.format("  sc639(mmap_buf, 64KB) = %s", hex8(ret639)))

if ret639 > 0 and ret639 < 0x100000 then
    local kptrs = scan_kptrs(mmap_buf, math.min(ret639, 0x10000))
    print(string.format("  Kernel pointers found: %d", #kptrs))
    for _, kp in ipairs(kptrs) do
        print(string.format("    +0x%x: %s", kp.offset, hex8(kp.value)))
    end
    print(string.format("  First 256 bytes:"))
    print(string.format("    %s", hexdump(mmap_buf, 256)))
end

-- ============================================================
-- SECTION 11: sceKernelGetBlockTypeInfo (632)
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 10: sceKernelGetBlockTypeInfo (632)")
print(string.rep("-", 70))

-- Try with various block IDs
for block_id = 0, 31 do
    zero_buf(out_buf, PAGE)
    local ret = sc_call(632, block_id, out_buf, PAGE, 0, 0, 0)
    if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
        print(string.format("  block=%d -> ret=%s", block_id, hex8(ret)))
        local kptrs = scan_kptrs(out_buf, 256)
        for _, kp in ipairs(kptrs) do
            print(string.format("    KPTR +0x%x: %s", kp.offset, hex8(kp.value)))
        end
    end
end

-- ============================================================
-- SECTION 12: sceKernelGetEventUserData (654) and event syscalls
-- These may leak kernel event structure pointers
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 11: Sony event syscalls (646-654)")
print("May leak kernel event handles/pointers")
print(string.rep("-", 70))

local event_syscalls = {
    {scno = 646, name = "sceKernelCreateEvent",
     args = {out_buf, 0, 0, 0, 0, 0}},
    {scno = 652, name = "sceKernelGetEventInfo",
     args = {0, out_buf, PAGE, 0, 0, 0}},
    {scno = 654, name = "sceKernelGetEventUserData",
     args = {0, out_buf, 0, 0, 0, 0}},
    {scno = 673, name = "sceKernelGetEqueueInfo",
     args = {0, out_buf, PAGE, 0, 0, 0}},
    {scno = 674, name = "sceKernelGetProcessAioInfo",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 676, name = "sceKernelGetCurrentCpu",
     args = {0, 0, 0, 0, 0, 0}},
    {scno = 677, name = "sceKernelIsStackOverrun",
     args = {0, 0, 0, 0, 0, 0}},
}

for _, es in ipairs(event_syscalls) do
    zero_buf(out_buf, PAGE)
    local ret = sc_call(es.scno,
        es.args[1], es.args[2], es.args[3],
        es.args[4], es.args[5], es.args[6])
    local tag = ""
    if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
        tag = " <<<< INTERESTING"
    end
    local kptrs = scan_kptrs(out_buf, 256)
    if #kptrs > 0 then
        tag = tag .. " *** KPTR LEAK ***"
        for _, kp in ipairs(kptrs) do
            tag = tag .. string.format("\n    +0x%x: %s", kp.offset, hex8(kp.value))
        end
    end
    print(string.format("  sc%03d %-40s -> %s%s",
        es.scno, es.name, hex8(ret), tag))
end

-- ============================================================
-- SECTION 13: sceKernelGetProcessTime variants
-- These time functions may leak kernel timing structures
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 12: Time/syscall info (610-615, 675)")
print(string.rep("-", 70))

local time_syscalls = {
    {scno = 610, name = "sceKernelGetCompiledSdkVersion",
     args = {out_buf, 0, 0, 0, 0, 0}},
    {scno = 611, name = "sceKernelGetProcessTime",
     args = {out_buf, 0, 0, 0, 0, 0}},
    {scno = 613, name = "sceKernelGetEventTimerTime",
     args = {0, out_buf, 0, 0, 0, 0}},
    {scno = 615, name = "sceKernelGetProcessTimeImpl",
     args = {out_buf, 0, 0, 0, 0, 0}},
    {scno = 675, name = "sysctl (custom)",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
}

for _, ts in ipairs(time_syscalls) do
    zero_buf(out_buf, PAGE)
    local ret = sc_call(ts.scno,
        ts.args[1], ts.args[2], ts.args[3],
        ts.args[4], ts.args[5], ts.args[6])
    local tag = ""
    if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
        tag = " <<<< INTERESTING"
    end
    local kptrs = scan_kptrs(out_buf, 256)
    if #kptrs > 0 then
        tag = tag .. " *** KPTR LEAK ***"
        for _, kp in ipairs(kptrs) do
            tag = tag .. string.format("\n    +0x%x: %s", kp.offset, hex8(kp.value))
        end
    end
    print(string.format("  sc%03d %-40s -> %s%s",
        ts.scno, ts.name, hex8(ret), tag))
end

-- ============================================================
-- SECTION 14: sceKernelSetProcessMemory (635) and config calls
-- These may have less validation since they "set" not "get"
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 13: Memory config syscalls (633-635, 638, 640)")
print(string.rep("-", 70))

local config_syscalls = {
    {scno = 633, name = "sceKernelSetBlockHeaderType",
     args = {0, out_buf, PAGE, 0, 0, 0}},
    {scno = 635, name = "sceKernelSetProcessMemory",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 638, name = "sceKernelReleaseDirectMemory",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 640, name = "sceKernelSwitchToProcessMemory",
     args = {0, out_buf, 0, 0, 0, 0}},
    {scno = 643, name = "sceKernelReleaseUserMemoryBlock",
     args = {0, out_buf, 0, 0, 0, 0}},
}

for _, cs in ipairs(config_syscalls) do
    zero_buf(out_buf, PAGE)
    local ret = sc_call(cs.scno,
        cs.args[1], cs.args[2], cs.args[3],
        cs.args[4], cs.args[5], cs.args[6])
    local tag = ""
    if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
        tag = " <<<< INTERESTING"
    end
    local kptrs = scan_kptrs(out_buf, 256)
    if #kptrs > 0 then
        tag = tag .. " *** KPTR LEAK ***"
        for _, kp in ipairs(kptrs) do
            tag = tag .. string.format("\n    +0x%x: %s", kp.offset, hex8(kp.value))
        end
    end
    print(string.format("  sc%03d %-40s -> %s%s",
        cs.scno, cs.name, hex8(ret), tag))
end

-- ============================================================
-- SECTION 15: mmap-backed buffer + syscall write-through test
-- If a syscall writes to a userspace buffer, we can detect it
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 14: mmap write-through detection")
print("If syscalls write to our mmap'd region, we detect it")
print(string.rep("-", 70))

local mmap_region = tonn(sc_call(477, 0, PAGE, 3, 0x1002, -1, 0))
if mmap_region > 0 and mmap_region < 0x7FFFFFFFFFFF then
    print(string.format("  mmap'd region at %s", hex8(mmap_region)))

    -- Fill with known pattern
    fill_buf(mmap_region, PAGE, 0xCC)

    -- Try each memory syscall with mmap_region as output
    for _, sc in ipairs(TARGET_SYSCALLS) do
        fill_buf(mmap_region, PAGE, 0xCC)
        local ret = sc_call(sc.scno,
            mmap_region, PAGE, 3,
            0, 0, 0)

        -- Check if anything changed
        local changed = false
        local first_change = -1
        for i = 0, math.min(PAGE - 1, 4095) do
            if tonn(M.read_byte(mmap_region + i)) ~= 0xCC then
                changed = true
                if first_change < 0 then first_change = i end
                break
            end
        end

        if changed then
            print(string.format("  [%d] %s WROTE to mmap region at offset 0x%x!",
                sc.scno, sc.name, first_change))
            -- Scan entire page for kernel pointers
            local kptrs = scan_kptrs(mmap_region, PAGE)
            if #kptrs > 0 then
                print(string.format("    *** %d KERNEL POINTERS written! ***", #kptrs))
                for _, kp in ipairs(kptrs) do
                    print(string.format("      +0x%x: %s", kp.offset, hex8(kp.value)))
                end
            end
            -- Print first changed bytes
            print(string.format("    Changed data: %s",
                hexdump(mmap_region, math.min(PAGE, 256))))
        end
    end

    -- Cleanup mmap
    sc_call(73, mmap_region, PAGE)
else
    print("  mmap failed, skipping write-through test")
end

-- ============================================================
-- SECTION 16: Budget syscalls (618-620)
-- These handle resource budgets - may leak kernel data
-- ============================================================

print("\n" .. string.rep("-", 70))
print("PHASE 15: Budget syscalls (618-620)")
print(string.rep("-", 70))

local budget_tests = {
    {scno = 618, name = "budget",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 618, name = "budget (zero args)",
     args = {0, 0, 0, 0, 0, 0}},
    {scno = 619, name = "budget_get_ptype",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 619, name = "budget_get_ptype (zero)",
     args = {0, 0, 0, 0, 0, 0}},
    {scno = 620, name = "budget_get_kernel_budgets",
     args = {out_buf, PAGE, 0, 0, 0, 0}},
    {scno = 620, name = "budget_get_kernel_budgets (zero)",
     args = {0, 0, 0, 0, 0, 0}},
}

for _, bt in ipairs(budget_tests) do
    zero_buf(out_buf, PAGE)
    local ret = sc_call(bt.scno,
        bt.args[1], bt.args[2], bt.args[3],
        bt.args[4], bt.args[5], bt.args[6])
    local tag = ""
    if ret ~= -1 and ret ~= 0xFFFFFFFFFFFFFFFF then
        tag = " <<<< INTERESTING"
    end
    local kptrs = scan_kptrs(out_buf, 256)
    if #kptrs > 0 then
        tag = tag .. " *** KPTR LEAK ***"
        for _, kp in ipairs(kptrs) do
            tag = tag .. string.format("\n    +0x%x: %s", kp.offset, hex8(kp.value))
        end
    end
    print(string.format("  sc%03d %-40s -> %s%s",
        bt.scno, bt.name, hex8(ret), tag))
end

-- ============================================================
-- SUMMARY
-- ============================================================

print("\n" .. string.rep("=", 70))
print("  PROBE COMPLETE - SUMMARY")
print(string.rep("=", 70))

print("\nInteresting results:")
local any_interesting = false
for scno, info in pairs(results) do
    if info.interesting or info.leak_found then
        any_interesting = true
        print(string.format("  sc%03d %s:", scno, info.name))
        if info.interesting then print("    - Returned non-standard value") end
        if info.leak_found then print("    - *** KERNEL POINTER LEAK FOUND ***") end
    end
end

if not any_interesting then
    print("  No non-standard returns or kernel pointer leaks detected")
end

print("\nWhat to look for in the output above:")
print("  1. Any 'KPTR' lines = kernel pointer info leak (CRITICAL)")
print("  2. 'INTERESTING' = non -1/0 return value (syscall not fully sandboxed)")
print("  3. 'WROTE to mmap region' = syscall writes to userspace (potential overflow)")
print("  4. Any hex dump showing non-zero data after a syscall")
print("  5. Block IDs that return useful data (memory blocks)")
print("  6. Event syscalls that return non-standard values")

print("\nIf kernel pointers found:")
print("  1. Record the exact syscall number + argument pattern")
print("  2. Record the leaked kernel address")
print("  3. Use address to defeat KASLR and find kernel base")
print("  4. Combine with kqueue UAF or CVE-2026-3038 for R/W")

print("\nIf non -1 returns found:")
print("  1. This means the syscall is not fully sandboxed")
print("  2. Try with different argument combinations")
print("  3. Look for output buffers that contain useful data")
print("  4. May be a path to kernel memory mapping")

print(string.rep("=", 70))
