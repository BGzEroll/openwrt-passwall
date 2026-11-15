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

s = m:section(NamedSection, arg[1], translate("访问控制"))
s.addremove = false
s.dynamic = false

o = s:option(Flag, "enabled", translate("启用"))
o.default = 1
o.rmempty = false

o = s:option(Value, "remarks", translate("备注"))
o.default = arg[1]
o.rmempty = true

local mac_hints = {}
sys.net.mac_hints(function(mac, ip)
	mac_hints[#mac_hints + 1] = { mac = mac, ip = ip }
end)
table.sort(mac_hints, function(a, b)
	return a.mac < b.mac
end)

sources = s:option(DynamicList, "sources", translate("设备 MAC 地址"),
	translate("仅支持 MAC 地址。"))
sources.cast = "string"
for _, hint in ipairs(mac_hints) do
	sources:value(hint.mac, string.format("%s（%s）", hint.mac, hint.ip))
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
			self:add_error(section, "invalid", translate("无效 MAC 地址：") .. item)
			return nil
		end
	end
	return value
end
sources.write = dynamic_list_write

direct = s:option(Flag, "direct", translate("直连"),
	translate("绕过 TCP/UDP 代理及 DNS、Ping 劫持；优先级高于普通访问控制规则。"))
direct.default = "0"
direct.rmempty = false

local function add_port_option(key, title, global_key, description, values)
	local global_value = uci:get(appname, "@global_forwarding[0]", global_key) or "disable"
	local option = s:option(Value, key, title, description)
	option.default = "default"
	option:value("disable", translate("不使用"))
	option:value("default", translate("使用全局配置") .. "（" .. global_value .. "）")
	for _, value in ipairs(values or {}) do
		option:value(value, value == "1:65535" and translate("全部") or value)
	end
	option.validate = port_validate
	option:depends("direct", "0")
	option:depends("direct", "")
	return option
end

add_port_option("tcp_no_redir_ports", translate("TCP 不代理端口"), "tcp_no_redir_ports",
	translate("这些端口优先绕过 Passwall。"), { "1:65535" })
add_port_option("udp_no_redir_ports", translate("UDP 不代理端口"), "udp_no_redir_ports",
	translate("这些端口优先绕过 Passwall。"), { "1:65535" })
add_port_option("tcp_proxy_drop_ports", translate("TCP 代理丢弃端口"), "tcp_proxy_drop_ports",
	nil)
add_port_option("udp_proxy_drop_ports", translate("UDP 代理丢弃端口"), "udp_proxy_drop_ports",
	nil, { "443" })
add_port_option("tcp_redir_ports", translate("TCP 代理端口"), "tcp_redir_ports",
	nil,
	{ "1:65535", "80,443", "80:65535", "1:443" })
add_port_option("udp_redir_ports", translate("UDP 代理端口"), "udp_redir_ports", nil,
	{ "1:65535", "53" })

m:append(Template("passwall/style"))

return m
