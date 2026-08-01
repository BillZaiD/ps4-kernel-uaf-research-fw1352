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

emit("=== R9AN kevent STD #560 vs COMPAT11 #363 ===")

local sv = memory.alloc(8)
memory.write_buffer(sv, "\0\0\0\0\0\0\0\0")
local r = sc(0x0e10, 1, 1, 0, sv)
if not r or n(r) ~= 0 then emit("socketpair failed: " .. num(r)) syscall.write(client_fd, out, #out) return end
local fd0 = memory.read_dword(sv):tonumber()
local fd1 = memory.read_dword(sv + 4):tonumber()
emit("fd0=" .. fd0 .. " fd1=" .. fd1)

local kq = n(sc(0x1390))
emit("kqueue=" .. kq)

local ev = memory.alloc(64)
local evo = memory.alloc(64)
local function zero(a, sz)
  local b = ""
  for i = 1, sz do b = b .. "\0" end
  memory.write_buffer(a, b, sz)
end
local function fill_kevent(a, ident, filter, flags, fflags, data, udata)
  memory.write_qword(a + 0, ident)
  memory.write_word(a + 8, filter)
  memory.write_word(a + 10, flags)
  memory.write_dword(a + 12, fflags)
  memory.write_qword(a + 16, data)
  memory.write_qword(a + 24, udata)
  memory.write_qword(a + 32, 0)
  memory.write_qword(a + 40, 0)
  memory.write_qword(a + 48, 0)
  memory.write_qword(a + 56, 0)
end

-- register EVFILT_READ (-1 as unsigned short = 0xffff) on fd1, via STD #560
zero(ev, 64)
fill_kevent(ev, fd1, 0xffff, 0x25, 0, 0, 0x77777777)
local ret560 = sc(0x1b50, kq, ev, 1, 0, 0, 0)
emit("kevent560 register: " .. num(ret560))

-- same via COMPAT11 #363
zero(ev, 64)
fill_kevent(ev, fd1, 0xffff, 0x25, 0, 0, 0x77777777)
local ret363 = sc(0x13b0, kq, ev, 1, 0, 0, 0)
emit("kevent363 register: " .. num(ret363))

-- write data to fd0 to trigger read event
local wb = memory.alloc(16)
memory.write_buffer(wb, "ABCDEFGH")
local wr = sc(0x2910, fd0, wb, 8, 0, 0, 0)
emit("write=" .. num(wr))

-- collect via STD #560
zero(evo, 64)
local r560 = sc(0x1b50, kq, 0, 0, evo, 1, 0)
emit("kevent560 collect: " .. num(r560))
if n(r560) > 0 then
  local id = memory.read_qword(evo + 0):tonumber()
  local fl = memory.read_word(evo + 8):tonumber()
  local fg = memory.read_word(evo + 10):tonumber()
  local ff = memory.read_dword(evo + 12):tonumber()
  local dt = memory.read_qword(evo + 16):tonumber()
  local ud = memory.read_qword(evo + 24):tonumber()
  local e0 = memory.read_qword(evo + 32):tonumber()
  local e1 = memory.read_qword(evo + 40):tonumber()
  local e2 = memory.read_qword(evo + 48):tonumber()
  local e3 = memory.read_qword(evo + 56):tonumber()
  emit(string.format("  std: id=0x%x filter=0x%x flags=0x%x fflags=0x%x data=%d udata=0x%x ext=%d,%d,%d,%d",
    id, fl, fg, ff, dt, ud, e0, e1, e2, e3))
end

-- collect via COMPAT11 #363
zero(evo, 64)
local r363 = sc(0x13b0, kq, 0, 0, evo, 1, 0)
emit("kevent363 collect: " .. num(r363))
if n(r363) > 0 then
  local id = memory.read_qword(evo + 0):tonumber()
  local fl = memory.read_word(evo + 8):tonumber()
  local fg = memory.read_word(evo + 10):tonumber()
  local ff = memory.read_dword(evo + 12):tonumber()
  local dt = memory.read_qword(evo + 16):tonumber()
  local ud = memory.read_qword(evo + 24):tonumber()
  local e0 = memory.read_qword(evo + 32):tonumber()
  local e1 = memory.read_qword(evo + 40):tonumber()
  local e2 = memory.read_qword(evo + 48):tonumber()
  local e3 = memory.read_qword(evo + 56):tonumber()
  emit(string.format("  c11: id=0x%x filter=0x%x flags=0x%x fflags=0x%x data=%d udata=0x%x ext=%d,%d,%d,%d",
    id, fl, fg, ff, dt, ud, e0, e1, e2, e3))
end

-- try EVFILT_USER (-7 = 0xfff9) with NOTE_TRIGGER via STD #560
zero(ev, 64)
fill_kevent(ev, 1, 0xfff9, 0x25, 0x80000000, 0, 0xdeadbeef)
local ru = sc(0x1b50, kq, ev, 1, 0, 0, 0)
emit("kevent560 user-trigger: " .. num(ru))
zero(evo, 64)
local rcu = sc(0x1b50, kq, 0, 0, evo, 1, 0)
emit("kevent560 user-collect: " .. num(rcu))
if n(rcu) > 0 then
  local id = memory.read_qword(evo + 0):tonumber()
  local fl = memory.read_word(evo + 8):tonumber()
  local ff = memory.read_dword(evo + 12):tonumber()
  local dt = memory.read_qword(evo + 16):tonumber()
  local ud = memory.read_qword(evo + 24):tonumber()
  emit(string.format("  user: id=0x%x filter=0x%x fflags=0x%x data=%d udata=0x%x", id, fl, ff, dt, ud))
end

sc(0x26b0, kq, 0, 0, 0, 0, 0)
sc(0x26b0, fd0, 0, 0, 0, 0, 0)
sc(0x26b0, fd1, 0, 0, 0, 0, 0)
emit("done")
syscall.write(client_fd, out, #out)
