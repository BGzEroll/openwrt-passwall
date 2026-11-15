local api = require "luci.passwall.api"
local appname = "passwall"
local fs = api.fs
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

m = Map(appname)

-- [[ Delay Settings ]]--
s = m:section(TypedSection, "global_delay", translate("Delay Settings"))
s.anonymous = true
s.addremove = false

---- Delay Start
o = s:option(Value, "start_delay", translate("Delay Start"),
				 translate("Units:seconds"))
o.default = "60"
o.rmempty = true

-- [[ Forwarding Settings ]]--
s = m:section(TypedSection, "global_forwarding",
			  translate("Forwarding Settings"))
s.anonymous = true
s.addremove = false

---- TCP Bypass Ports
o = s:option(Value, "tcp_no_redir_ports", translate("TCP Bypass Ports"))
o.default = "disable"
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP Bypass Ports
o = s:option(Value, "udp_no_redir_ports", translate("UDP Bypass Ports"),
			 "<font color='red'>" .. translate(
				 "Fill in the ports you don't want to be forwarded by the agent, with the highest priority.") ..
				 "</font>")
o.default = "disable"
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

---- TCP Proxy Drop Ports
o = s:option(Value, "tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"))
o.default = "disable"
o:value("disable", translate("No patterns are used"))
o.validate = port_validate

---- UDP Proxy Drop Ports
o = s:option(Value, "udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"))
o.default = "disable"
o:value("disable", translate("No patterns are used"))
o:value("443", translate("QUIC"))
o.validate = port_validate

---- TCP Proxy Ports
o = s:option(Value, "tcp_redir_ports", translate("TCP Proxy Ports"))
o.default = "1:65535"
o:value("1:65535", translate("All"))
o:value("22,25,53,143,465,587,853,993,995,80,443", translate("Common Use"))
o:value("80,443", translate("Only Web"))
o.validate = port_validate

---- UDP Proxy Ports
o = s:option(Value, "udp_redir_ports", translate("UDP Proxy Ports"))
o.default = "1:65535"
o:value("1:65535", translate("All"))
o:value("53", "DNS")
o.validate = port_validate

o = s:option(Flag, "iproute_shunt", translate("通过策略路由转发代理流量"))
o.default = 0
o.description = translate("开启后 Passwall 会自动关闭防火墙原生的软件及硬件流量分载，并继续使用自己的 PBR flowtable；停止 Passwall 时会自动开启防火墙原生的软件及硬件流量分载。")

o = s:option(Value, "iproute_shunt_gw_v4", translate("转发至IPv4网关"))
o:depends("iproute_shunt", true)
o.placeholder = '114.51.41.91'
o.datatype = 'ip4addr'

o = s:option(Value, "iproute_shunt_gw_v6", translate("转发至IPv6网关"))
o:depends("iproute_shunt", true)
o.placeholder = '0d00::0721:114:514'
o.datatype = 'ip6addr'

o = s:option(Value, "iproute_shunt_interface", translate("通过接口"))
o:depends("iproute_shunt", true)
o.placeholder = 'br-lan'

o = s:option(DummyValue, "iproute_shunt_offloading_interface", translate("自动检测的硬件加速接口"))
o:depends("iproute_shunt", true)
o.description = translate("接口列表由 OpenWrt fw4 API 自动获取。")
o.cfgvalue = function(self, section)
	local interfaces = api.trim(api.sys.exec("ucode /usr/share/passwall/offload.uc 2>/dev/null") or "")
	return interfaces ~= "" and interfaces or "无可用接口"
end

o = s:option(Flag, "accept_icmp", translate("Hijacking ICMP (PING)"))
o.default = 1

o = s:option(Flag, "accept_icmpv6", translate("Hijacking ICMPv6 (IPv6 PING)"))
o.default = 1

if has_xray then
	s_xray = m:section(TypedSection, "global_xray", "Xray " .. translate("Settings"))
	s_xray.anonymous = true
	s_xray.addremove = false

	o = s_xray:option(Flag, "fragment", translate("Fragment"), translate("TCP fragments, which can deceive the censorship system in some cases, such as bypassing SNI blacklists."))
	o.default = 0

	o = s_xray:option(ListValue, "fragment_packets", translate("Fragment Packets"), translate("\"1-3\" is for segmentation at TCP layer, applying to the beginning 1 to 3 data writes by the client. \"tlshello\" is for TLS client hello packet fragmentation."))
	o.default = "tlshello"
	o:value("tlshello", "tlshello")
	o:value("1-2", "1-2")
	o:value("1-3", "1-3")
	o:value("1-5", "1-5")
	o:depends("fragment", true)

	o = s_xray:option(Value, "fragment_length", translate("Fragment Length"), translate("Fragmented packet length (byte)"))
	o.default = "100-200"
	o:depends("fragment", true)

	o = s_xray:option(Value, "fragment_interval", translate("Fragment Interval"), translate("Fragmentation interval (ms)"))
	o.default = "10-20"
	o:depends("fragment", true)

	o = s_xray:option(Flag, "sniffing_override_dest", translate("Override the connection destination address"), translate("Override the connection destination address with the sniffed domain."))
	o.default = 0

	local domains_excluded = string.format("/usr/share/%s/rules/domains_excluded", appname)
	o = s_xray:option(TextValue, "excluded_domains", translate("Excluded Domains"), translate("If the traffic sniffing result is in this list, the destination address will not be overridden."))
	o.rows = 15
	o.wrap = "off"
	o.cfgvalue = function(self, section) return fs.readfile(domains_excluded) or "" end
	o.write = function(self, section, value) fs.writefile(domains_excluded, value:gsub("\r\n", "\n")) end
	o:depends({sniffing_override_dest = true})

	o = s_xray:option(Value, "buffer_size", translate("Buffer Size"), translate("Buffer size for every connection (kB)"))
	o.datatype = "uinteger"
end

if has_singbox then
	s = m:section(TypedSection, "global_singbox", "Sing-Box " .. translate("Settings"))
	s.anonymous = true
	s.addremove = false

	o = s:option(Flag, "sniff_override_destination", translate("Override the connection destination address"), translate("Override the connection destination address with the sniffed domain."))
	o.default = 0
	o.rmempty = false

end

return m
