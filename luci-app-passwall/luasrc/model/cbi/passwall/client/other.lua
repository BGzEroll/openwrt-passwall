local api = require "luci.passwall.api"
local appname = "passwall"
local fs = api.fs
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")
local has_fw3 = api.is_finded("fw3")
local has_fw4 = api.is_finded("fw4")

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
o.default = "1"
o.rmempty = true

---- Open and close Daemon
o = s:option(Flag, "start_daemon", translate("Open and close Daemon"))
o.default = 1
o.rmempty = false

--[[
---- Open and close automatically
o = s:option(Flag, "auto_on", translate("Open and close automatically"))
o.default = 0
o.rmempty = false

---- Automatically turn off time
o = s:option(ListValue, "time_off", translate("Automatically turn off time"))
o.default = nil
o:depends("auto_on", true)
o:value(nil, translate("Disable"))
for e = 0, 23 do o:value(e, e .. translate("oclock")) end

---- Automatically turn on time
o = s:option(ListValue, "time_on", translate("Automatically turn on time"))
o.default = nil
o:depends("auto_on", true)
o:value(nil, translate("Disable"))
for e = 0, 23 do o:value(e, e .. translate("oclock")) end

---- Automatically restart time
o = s:option(ListValue, "time_restart", translate("Automatically restart time"))
o.default = nil
o:depends("auto_on", true)
o:value(nil, translate("Disable"))
for e = 0, 23 do o:value(e, e .. translate("oclock")) end
--]]

-- [[ Forwarding Settings ]]--
s = m:section(TypedSection, "global_forwarding",
			  translate("Forwarding Settings"))
s.anonymous = true
s.addremove = false

---- TCP No Redir Ports
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o.default = "disable"
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP No Redir Ports
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
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
o.default = "443"
o:value("disable", translate("No patterns are used"))
o:value("443", translate("QUIC"))
o.validate = port_validate

---- TCP Redir Ports
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"))
o.default = "22,25,53,143,465,587,853,993,995,80,443"
o:value("1:65535", translate("All"))
o:value("22,25,53,143,465,587,853,993,995,80,443", translate("Common Use"))
o:value("80,443", translate("Only Web"))
o.validate = port_validate

---- UDP Redir Ports
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"))
o.default = "1:65535"
o:value("1:65535", translate("All"))
o:value("53", "DNS")
o.validate = port_validate

---- Use nftables
o = s:option(ListValue, "use_nft", translate("Firewall tools"))
o.default = "0"
if has_fw3 then
	o:value("0", "IPtables")
end
if has_fw4 then
	o:value("1", "NFtables")
end

if (os.execute("lsmod | grep -i REDIRECT >/dev/null") == 0 and os.execute("lsmod | grep -i TPROXY >/dev/null") == 0) or (os.execute("lsmod | grep -i nft_redir >/dev/null") == 0 and os.execute("lsmod | grep -i nft_tproxy >/dev/null") == 0) then
	o = s:option(ListValue, "tcp_proxy_way", translate("TCP Proxy Way"))
	o.default = "redirect"
	o:value("redirect", "REDIRECT")
	o:value("tproxy", "TPROXY")
	o:depends("ipv6_tproxy", false)

	o = s:option(ListValue, "_tcp_proxy_way", translate("TCP Proxy Way"))
	o.default = "tproxy"
	o:value("tproxy", "TPROXY")
	o:depends("ipv6_tproxy", true)
	o.write = function(self, section, value)
		return self.map:set(section, "tcp_proxy_way", value)
	end

	if os.execute("lsmod | grep -i ip6table_mangle >/dev/null") == 0 or os.execute("lsmod | grep -i nft_tproxy >/dev/null") == 0 then
		---- IPv6 TProxy
		o = s:option(Flag, "ipv6_tproxy", translate("IPv6 TProxy"),
					"<font color='red'>" .. translate(
						"Experimental feature. Make sure that your node supports IPv6.") ..
						"</font>")
		o.default = 0
		o.rmempty = false
	end
end

o = s:option(Flag, "iproute_shunt", translate("通过策略路由转发代理流量"))
o.default = 0
o.description = translate("开启后必须确保防火墙中的“软件及硬件流量分载”处于关闭状态，关闭后记得重新开启“软件及硬件流量分载”。")

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

o = s:option(Value, "iproute_shunt_offloading_interface", translate("使用硬件加速的接口"))
o.default = 'lan1,lan2,lan3,wan'
o.rmempty = false
o.placeholder = 'lan1,lan2,lan3,wan'
o.description = translate("必须填写物理接口名称，且更改内容后必须点击一次“清空NFSET”按钮。")

o = s:option(Flag, "accept_icmp", translate("Hijacking ICMP (PING)"))
o.default = 0

o = s:option(Flag, "accept_icmpv6", translate("Hijacking ICMPv6 (IPv6 PING)"))
o:depends("ipv6_tproxy", true)
o.default = 0

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

	o = s:option(Value, "geoip_path", translate("Custom geoip Path"))
	o.default = "/usr/share/singbox/geoip.db"
	o.rmempty = false

	o = s:option(Value, "geoip_url", translate("Custom geoip URL"))
	o.default = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.db"
	o:value("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.db")
	o:value("https://github.com/1715173329/sing-geoip/releases/latest/download/geoip.db")
	o:value("https://github.com/lyc8503/sing-box-rules/releases/latest/download/geoip.db")
	o.rmempty = false

	o = s:option(Value, "geosite_path", translate("Custom geosite Path"))
	o.default = "/usr/share/singbox/geosite.db"
	o.rmempty = false

	o = s:option(Value, "geosite_url", translate("Custom geosite URL"))
	o.default = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.db"
	o:value("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.db")
	o:value("https://github.com/1715173329/sing-geosite/releases/latest/download/geosite.db")
	o:value("https://github.com/lyc8503/sing-box-rules/releases/latest/download/geosite.db")
	o.rmempty = false

	o = s:option(Button, "_remove_resource", translate("Remove resource files"))
	o.description = translate("Sing-Box will automatically download resource files when starting, you can use this feature achieve upgrade resource files.")
	o.inputstyle = "remove"
	function o.write(self, section, value)
		local geoip_path = s.fields["geoip_path"] and s.fields["geoip_path"]:formvalue(section) or nil
		if geoip_path then
			os.remove(geoip_path)
		end
		local geosite_path = s.fields["geosite_path"] and s.fields["geosite_path"]:formvalue(section) or nil
		if geosite_path then
			os.remove(geosite_path)
		end
	end
end

return m
