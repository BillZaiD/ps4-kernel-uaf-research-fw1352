-- transfer file via raw socket writes
local f = io.open(WRITABLE_PATH .. "lk.bin", "rb")
local data = f:read("*all")
f:close()

local chunk = 0x4000
local pos = 1
while pos <= #data do
    local endpos = pos + chunk - 1
    if endpos > #data then endpos = #data end
    local seg = data:sub(pos, endpos)
    syscall.write(client_fd, seg, #seg)
    pos = pos + chunk
end
-- signal done
syscall.write(client_fd, "DONE_TRANSFER", 13)
