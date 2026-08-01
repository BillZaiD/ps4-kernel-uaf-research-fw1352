-- read dumped file and send hex-encoded
local f = io.open(WRITABLE_PATH .. "lk.bin", "rb")
local data = f:read("*all")
f:close()

print("SIZE:" .. #data)

-- Send in 4KB hex chunks
local chunk = 0x1000
local pos = 1
while pos <= #data do
    local endpos = pos + chunk - 1
    if endpos > #data then endpos = #data end
    local seg = data:sub(pos, endpos)
    local hex = ""
    for i = 1, #seg do
        hex = hex .. string.format("%02x", string.byte(seg, i))
    end
    print("CHUNK:" .. hex)
    pos = pos + chunk
end
print("TRANSFER_END")
