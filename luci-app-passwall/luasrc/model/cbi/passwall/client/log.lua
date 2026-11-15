local m = Map("passwall", translate("日志"))
m.apply_on_parse = false
local s = m:section(TypedSection, "global")
s.anonymous = true
local o = s:option(Flag, "log_tcp", translate("启用 TCP 节点日志"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "log_udp", translate("启用 UDP 节点日志"))
o.default = "0"
o.rmempty = false

o = s:option(ListValue, "loglevel", "Xray " .. translate("日志等级"))
o.default = "warning"
o:value("warning")
o:value("error")
o:value("info")
o:value("debug")

o = s:option(Flag, "log_debug", translate("详细运行日志"))
o.default = "0"
o.rmempty = false
m:append(Template("passwall/log/log"))
return m
