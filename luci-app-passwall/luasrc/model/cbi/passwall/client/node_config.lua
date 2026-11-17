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

o = s:option(DummyValue, "type", translate("Core"))
o.template = "passwall/value_text"
o.cfgvalue = function()
	return "Xray"
end

-- Native CBI skips parsing read-only values. Persist the fixed core on both
-- Save and Save & Apply, including nodes created before this invariant existed.
function m.on_before_save(self)
	self:set(arg[1], "type", "Xray")
end

local xray_form = loadfile(types_dir .. "ray.lua")
setfenv(xray_form, getfenv(1))(m, s)

m:append(Template("passwall/style"))

return m
