local out = ""
local function num(v)
  if v == nil then return "nil" end
  if type(v) == "table" then
    local tn = v:tonumber()
    if tn then return string.format("%d", tn) end
    return string.format("u64(0x%x,0x%x)", v.h or 0, v.l or 0)
  end
  return tostring(v)
end
local function emit(s) out = out .. s .. "\n" end

local socket_fn = syscall.socket.fn_addr
local libk_base = (socket_fn.h or 0) * 4294967296 + (socket_fn.l or 0) - 0x0b70
local function sc(dump_off, a, b, c, d, e, f)
  a = a or 0; b = b or 0; c = c or 0; d = d or 0; e = e or 0; f = f or 0
  local ok, ret = pcall(native.fcall, libk_base + dump_off, a, b, c, d, e, f)
  if ok then return ret else return nil end
end
local function n(v)
  if v == nil then return -1 end
  local tn = v:tonumber()
  if tn then return tn end
  return -1
end
local function t(v)
  if v == nil then return 0 end
  if type(v) == "number" then return v end
  if type(v) == "table" then
    local tn = v:tonumber()
    if tn then return tn end
    return (v.h or 0) * 4294967296 + (v.l or 0)
  end
  return tonumber(tostring(v)) or 0
end
local function rb(a) return t(memory.read_byte(a)) end
local function rd(a) return t(memory.read_dword(a)) end

emit("=== R9AO fstat#551 STD on internal fds + getrandom ===")

-- fstat on internal device fds (libkernel-cached 5/6/7)
local sb = memory.alloc(256)
local function dump_fstat(fd, label)
  for i = 0, 255 do memory.write_byte(sb + i, 0xAA) end
  local r = sc(0x1a30, fd, sb, 0, 0, 0, 0)
  local hx = ""
  for i = 0, 63 do hx = hx .. string.format("%02x ", rb(sb + i)) end
  emit(label .. " fstat(" .. fd .. ")=" .. num(r) .. " data=" .. hx)
end
dump_fstat(5, "dev")
dump_fstat(6, "dev")
dump_fstat(7, "dev")

-- socketpair for a normal fd comparison
local sv = memory.alloc(8)
memory.write_buffer(sv, "\0\0\0\0\0\0\0\0")
local r = sc(0x0e10, 1, 1, 0, sv)
if r and n(r) == 0 then
  local fd0 = rd(sv)
  local fd1 = rd(sv + 4)
  dump_fstat(fd0, "sock")
  dump_fstat(fd1, "sock")
  sc(0x26b0, fd0, 0, 0, 0, 0, 0)
  sc(0x26b0, fd1, 0, 0, 0, 0, 0)
end

-- getrandom sc#563
local gr = memory.alloc(32)
for i = 0, 31 do memory.write_byte(gr + i, 0) end
local rgr = sc(0x1b70, gr, 32, 0, 0, 0, 0)
emit("getrandom(32)=" .. num(rgr))
local hx2 = ""
for i = 0, 15 do hx2 = hx2 .. string.format("%02x ", rb(gr + i)) end
emit("  data=" .. hx2)
syscall.write(client_fd, out, #out)
