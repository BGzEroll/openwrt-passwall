local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local sys = api.sys
local datatypes = api.datatypes

local function port_validate(self, value)
	return value:gsub("-", ":")
end

local function dynamic_list_write(self, section, value)
	local values = {}
	local seen = {}
	if type(value) ~= "table" then
		value = { value }
	end
	for _, item in ipairs(value) do
		if item and #item > 0 then
			item = item:upper()
			if not seen[item] then
				seen[item] = true
				values[#values + 1] = item
			end
		end
	end
	return DynamicList.write(self, section, table.concat(values, " "))
end

m = Map(appname)

s = m:section(NamedSection, arg[1], translate("ACLs"),
	translate("An ACL identifies directly connected devices by MAC address and only overrides their TCP/UDP port policy. Destination lists, nodes and DNS always use Global Config."))
s.addremove = false
s.dynamic = false

o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = true

local mac_hints = {}
sys.net.mac_hints(function(mac, ip)
	mac_hints[#mac_hints + 1] = { mac = mac, ip = ip }
end)
table.sort(mac_hints, function(a, b)
	return a.mac < b.mac
end)

sources = s:option(DynamicList, "sources", translate("Device MAC Addresses"),
	translate("Only MAC addresses are supported. One ACL can contain multiple directly connected LAN, Wi-Fi, bridge or VLAN devices."))
sources.cast = "string"
for _, hint in ipairs(mac_hints) do
	sources:value(hint.mac, string.format("%s (%s)", hint.mac, hint.ip))
end
sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local list = {}
			for item in value:gmatch("%S+") do
				list[#list + 1] = item
			end
			value = list
		end
	end
	return value
end
sources.validate = function(self, value, section)
	for _, item in ipairs(value) do
		if not datatypes.macaddr(item) then
			self:add_error(section, "invalid", translate("Only valid MAC addresses are accepted: ") .. item)
			return nil
		end
	end
	return value
end
sources.write = dynamic_list_write

direct = s:option(Flag, "direct", translate("Direct"),
	translate("Completely bypass Passwall for these devices, including TCP, UDP, DNS hijack and ping hijack. Direct takes priority over every normal ACL."))
direct.default = "0"
direct.rmempty = false

local function add_port_option(key, title, global_key, description, values)
	local global_value = uci:get(appname, "@global_forwarding[0]", global_key) or "disable"
	local option = s:option(Value, key, title, description)
	option.default = "default"
	option:value("disable", translate("No patterns are used"))
	option:value("default", translate("Use global config") .. " (" .. global_value .. ")")
	for _, value in ipairs(values or {}) do
		option:value(value, value == "1:65535" and translate("All") or value)
	end
	option.validate = port_validate
	option:depends("direct", "0")
	return option
end

add_port_option("tcp_no_redir_ports", translate("TCP Bypass Ports"), "tcp_no_redir_ports",
	translate("These ports bypass Passwall before destination policy is evaluated."), { "1:65535" })
add_port_option("udp_no_redir_ports", translate("UDP Bypass Ports"), "udp_no_redir_ports",
	translate("These ports bypass Passwall before destination policy is evaluated."), { "1:65535" })
add_port_option("tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"), "tcp_proxy_drop_ports",
	translate("Drop only when the shared Global Policy classifies the destination as PROXY."))
add_port_option("udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"), "udp_proxy_drop_ports",
	translate("Drop only when the shared Global Policy classifies the destination as PROXY."), { "443" })
add_port_option("tcp_redir_ports", translate("TCP Proxy Ports"), "tcp_redir_ports",
	translate("The historical UCI key is retained, but TCP transparent proxying is TPROXY-only."),
	{ "1:65535", "80,443", "80:65535", "1:443" })
add_port_option("udp_redir_ports", translate("UDP Proxy Ports"), "udp_redir_ports", nil,
	{ "1:65535", "53" })

return m
