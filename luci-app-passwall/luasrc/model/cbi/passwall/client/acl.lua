local api = require "luci.passwall.api"
local appname = "passwall"
local sys = api.sys

m = Map(appname)

-- [[ ACLs Settings ]]--
s = m:section(TypedSection, "acl_rule")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true
s.extedit = api.url("acl_config", "%s")
function s.create(e, t)
	t = TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(t))
end
function s.remove(e, t)
	TypedSection.remove(e, t)
end

---- Enable
o = s:option(Flag, "enabled", translate("启用"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("备注"))
o.rmempty = true

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[e:upper()] = {
		ip = t,
		mac = e
	}
end)

o = s:option(DummyValue, "sources", translate("设备 MAC 地址"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local e = ''
	local v = Value.cfgvalue(t, n) or ''
	string.gsub(v, '[^' .. " " .. ']+', function(w)
		local a = w
		local hint = mac_t[w:upper()]
		if hint then
			a = a .. '（' .. hint.ip .. '）'
		end
		if #e > 0 then
			e = e .. "<br />"
		end
		e = e .. require("luci.xml").pcdata(a)
	end)
	return e
end

m:append(Template("passwall/style"))

return m
