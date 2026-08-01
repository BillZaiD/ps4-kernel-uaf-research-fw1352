-- Use read_byte (returns {h,l}) and check .l for value
local wt = syscall.syscall_wrapper
local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "CRASH" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh = ret.h or 0; rl = ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    if rh == 0xffffffff and rl == 0xffffffff then return "-1"
    elseif rh == 0 and rl == 0 then return "0"
    else return string.format("0x%x%08x", rh, rl) end
end

-- read_byte returns {h=0, l=byte_value}
local function rb(addr, off)
    local v = memory.read_byte(addr, off or 0)
    if type(v) == "table" then return v.l or 0 else return 0 end
end

-- write byte
local function wb(addr, off, val)
    memory.write_byte(addr, off, val)
end

local targets = {596, 599, 602, 606, 617, 620}

for _, n in ipairs(targets) do
    local buf = memory.alloc(0x80)
    
    -- Fill with 0xBB
    for i = 0, 0x7f do wb(buf, i, 0xBB) end
    
    -- Call syscall with buf address as lo+hi packed?
    -- native.fcall takes args as individual numbers
    -- buf.l = lo32, buf.h = hi32
    -- The function expects a 64-bit pointer, so we need to pass it as a 64-bit value
    -- In x64 calling convention, a 64-bit value needs to go in a single register
    -- native.fcall probably takes (func_addr, a1, a2, ...)
    -- where each arg is uint64 {h,l} or a number
    
    -- Let's try passing buf directly (it's a table, might be serialized as uint64)
    local r = sc(n, buf)
    
    -- Read first 32 bytes
    local data = {}
    for i = 0, 31 do data[i+1] = rb(buf, i) end
    
    local hex = ""
    for i = 1, 32 do hex = hex .. string.format("%02x", data[i]) end
    
    local changed = false
    for i = 1, 32 do if data[i] ~= 0xBB then changed = true; break end end
    
    print(string.format("SC%03d ret=%s changed=%s", n, r, tostring(changed)))
    print(string.format("  buf[0..31]: %s", hex))
    
    if changed then
        -- Print as qwords too
        local qwords = {}
        for i = 0, 3 do
            local q = memory.read_qword(buf, i * 8)
            local qv = 0
            if type(q) == "table" then qv = q.h * 0x100000000 + q.l end
            qwords[i+1] = qv
            print(string.format("  qword[%d]: 0x%x", i, qv))
        end
    end
    
    print("")
end

print("Done!")
