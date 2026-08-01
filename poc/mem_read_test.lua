-- Find memory read/write patterns by dumping loaded functions
print("--- Look for memory access patterns ---")
-- Check if there's a memory.read_qword that works
local buf = memory.alloc(0x40)

-- Test read_qword with simple table
local q = memory.read_qword(buf, 0)
print(string.format("read_qword(buf): type=%s", type(q)))
if type(q) == "table" then
    print(string.format("  h=%d l=%d", q.h or -1, q.l or -1))
end

-- Test read_dword
local dw = memory.read_dword(buf, 0)
print(string.format("read_dword(buf): type=%s", type(dw)))
if type(dw) == "table" then
    print(string.format("  h=%d l=%d", dw.h or -1, dw.l or -1))
end

-- Test read_word
local wd = memory.read_word(buf, 0)
print(string.format("read_word(buf): type=%s", type(wd)))
if type(wd) == "table" then
    print(string.format("  h=%d l=%d", wd.h or -1, wd.l or -1))
end

-- check the lua table for memory.read_multiple_qwords
print("\n--- read_multiple_qwords ---")
local mqw = memory.read_multiple_qwords(buf, 4)
print(string.format("type=%s", type(mqw)))
if type(mqw) == "table" then
    for i, v in ipairs(mqw) do
        if type(v) == "table" then
            print(string.format("  [%d] h=%d l=%d", i, v.h or -1, v.l or -1))
        else
            print(string.format("  [%d] = %s", i, tostring(v)))
        end
    end
end

-- Try reading at different offsets from alloc
print("\n--- reading at buf+16 ---")
local buf2_h = buf.h
local buf2_l = buf.l + 16
if buf2_l >= 0x100000000 then
    buf2_l = buf2_l - 0x100000000
    buf2_h = buf2_h + 1
end
local buf2 = {h = buf2_h, l = buf2_l}
local q2 = memory.read_qword(buf2, 0)
if type(q2) == "table" then
    print(string.format("buf+16 qword: h=%d l=%d (0x%x%08x)", q2.h or 0, q2.l or 0, q2.h or 0, q2.l or 0))
end

print("\nDone!")
