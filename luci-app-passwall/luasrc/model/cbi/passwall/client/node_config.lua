local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local types_dir = "/usr/lib/lua/luci/model/cbi/passwall/client/type/"

if not arg[1] or not uci:get(appname, arg[1]) then
	luci.http.redirect(api.url("node_list"))
end

m = Map(appname, translate("Node Config"))
m.redirect = api.url()

s = m:section(NamedSection, arg[1], "nodes", "")
s.addremove = false
s.dynamic = false

o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

o = s:option(Value, "type", translate("Core"))
o.default = "Xray"
o.readonly = true
o.rmempty = false
o.write = function(self, section)
	self.map:set(section, self.option, "Xray")
end

local xray_form = loadfile(types_dir .. "ray.lua")
setfenv(xray_form, getfenv(1))(m, s)

return m
