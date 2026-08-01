-- PS4 FW 13.52 - DEVICE PROBE R8 (ioctl sweep)
-- Use S.open + S.ioctl (named wrappers, PROVEN safe in R6).
-- Sweep broad ioctl code families on dce + dmem0, scanning buffer even on -1.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { close = 6, open = 5, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R8 START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

local families = {
  {name="6600", list={0xC0106600,0xC0106601,0xC0106602,0xC0106603,0xC0106604,0xC0106605,
                      0xC0106610,0xC0106611,0xC0106612,0xC0106613,0xC0106614,0xC0106615,
                      0xC0106620,0xC0106630,0xC0106640,0xC0106650,0xC0106660}},
  {name="8000", list={0xC0088000,0xC0088001,0xC0088002,0xC0088003,0xC0108000,0xC0108001,
                      0xC0108002,0xC0188000,0xC0188001,0xC0208000,0xC0208001,0xC0408000,
                      0xC0408001,0xC0408002}},
  {name="8F00", list={0xC0108F00,0xC0188F01,0xC0208F02,0xC0408F03,0xC0108F10,0xC0108F11,
                      0xC0108F20,0xC0208F21,0xC0108F30,0xC0188F31,0xC0108F40}},
  {name="A801", list={0xC008A801,0xC010A801,0xC020A801,0xC040A801,0xC008A802,0xC010A802,
                      0xC020A802,0xC040A802,0x4008A801,0x4010A801,0x4020A801,0x4040A801,
                      0x8008A801,0x8010A801,0x8020A801,0x8040A801}},
  {name="5300", list={0xC0085300,0xC0105300,0xC0085301,0xC0105301,0xC0085302,0xC0105302,
                      0xC0105303,0x40105303,0x80105303,0xC0085303,0xC0085304,0xC0105304,
                      0xC0105305,0x40105305}},
  {name="0400", list={0xC0080400,0xC0100400,0xC0080401,0xC0100401,0xC0080402,0xC0100402,
                      0xC0080403,0xC0100403,0xC0080404,0xC0100404,0xC0080405,0xC0100405,
                      0xC0080410,0xC0100410,0xC0080420,0xC0100420}},
  {name="6601_mem", list={0xC0086601,0xC0186601,0xC0206601,0xC0406601,0xC0806601,
                          0xC0086602,0xC0186602,0xC0086610,0xC0086611,0xC0086612,
                          0xC0106616,0xC0106617,0xC0106618,0xC0106619,0xC010661A}},
  {name="dmem_864", list={0x40086418,0x40026417,0x40086489,0x40046419,0x4008641A,
                          0x80086418,0xC0086418,0x40086400,0x40086401,0x40086402,
                          0xC0106400,0xC0086400,0xC0106401,0xC0086401}},
  {name="7000", list={0xC0087000,0xC0107000,0xC0087001,0xC0107001,0xC0087002,0xC0107002,
                      0xC0087003,0xC0107003,0xC0087010,0xC0107010}},
  {name="9500", list={0xC0089500,0xC0109500,0xC0089501,0xC0109501,0xC0089502,0xC0109502,
                      0xC0089503,0xC0109503}},
  {name="random_big", list={0xC0100001,0xC0100002,0xC0100003,0xC0200001,0xC0200002,
                            0xC0400001,0xC0400002,0xC0100100,0xC0100101,0xC0100102,
                            0xC0100200,0xC0100201,0xC0100300,0xC0100301,0xC0100302,
                            0xC0100A00,0xC0100A01,0xC0100A02,0xC0100B00,0xC0100B01,
                            0xC0100C00,0xC0100C01,0xC0100D00,0xC0100D01,0xC0100E00,
                            0xC0100F00,0xC0101000,0xC0101001,0xC0101002,0xC0102000,
                            0xC0102001,0xC0103000,0xC0103001,0xC0104000,0xC0104001,
                            0xC0105000,0xC0105001,0xC0106000,0xC0106001,0xC0107000}},
  {name="gpu_known", list={0xC0208201,0xC0108201,0xC0208202,0xC0108202,0xC0208203,
                           0xC0108203,0xC0208204,0xC0108204,0xC0108300,0xC0108301,
                           0xC0208300,0xC0208301,0xC0108400,0xC0108401}},
  {name="misc_wr", list={0xC0100000,0xC0100004,0xC0100005,0xC0100006,0xC0080001,
                         0xC0080002,0xC0080003,0xC0080004,0xC0080005,0xC010000A,
                         0xC010000B,0xC010000C,0xC0080010,0xC0080011,0xC0080012,
                         0xC0100010,0xC0100011,0xC0100012,0xC0100013,0xC0100014}},
}

local devs = { {path="/dev/dce",name="dce"}, {path="/dev/dmem0",name="dmem0"} }

for _, d in ipairs(devs) do
  print("### " .. d.name)
  local fd = open_dev(d.path, 2)
  print(string.format("fd=%d", fd))
  if fd >= 0 and fd < 1024 then
    for _, fam in ipairs(families) do
      for _, req in ipairs(fam.list) do
        pcall(function()
          local buf = mem.alloc(512)
          for i = 0, 511 do mem.write_byte(buf+i, 0x41 + (i % 26)) end
          local r = t(S.ioctl(fd, req, buf))
          if r ~= -1 then
            print(string.format("ioctl(0x%08x)=%d", req, r))
            local hx = ""
            for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
            print("  " .. hx)
          elseif r == -1 then
            local mod = false
            for i = 0, 31 do
              if rb(buf+i) ~= 0x41 + (i % 26) then mod = true; break end
            end
            if mod then
              print(string.format("ioctl(0x%08x)=-1 BUT BUF MODIFIED", req))
              local hx = ""
              for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
              print("  " .. hx)
            end
          end
        end)
      end
    end
    S.close(fd)
  end
end

print("=== DEV-R8 DONE ===")
