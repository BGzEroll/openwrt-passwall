local api = require "luci.passwall.api"
local appname = "passwall"
local sys = api.sys

m = Map(appname)

s = m:section(TypedSection, "global", translate("ACLs"), "<font color='red'>" .. translate("ACLs identify directly connected devices by MAC address and override ports only. Nodes, DNS and destination policy are global.") .. "</font>")
s.anonymous = true

o = s:option(Flag, "acl_enable", translate("Main switch"))
o.rmempty = false
o.default = false

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
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.rmempty = true

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[e] = {
		ip = t,
		mac = e
	}
end)

o = s:option(DummyValue, "sources", translate("Device MAC Addresses"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local e = ''
	local v = Value.cfgvalue(t, n) or ''
	string.gsub(v, '[^' .. " " .. ']+', function(w)
		local a = w
		if mac_t[w] then
			a = a .. ' (' .. mac_t[w].ip .. ')'
		end
		if #e > 0 then
			e = e .. "<br />"
		end
		e = e .. a
	end)
	return e
end

o = s:option(Flag, "direct", translate("Direct"))
o.default = "0"
o.rmempty = false

return m
