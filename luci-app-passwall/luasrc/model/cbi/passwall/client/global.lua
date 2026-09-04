local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local datatypes = api.datatypes
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")
local has_gfwlist = api.fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = api.fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = api.fs.access("/usr/share/passwall/rules/chnroute")

m = Map(appname)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local normal_list = {}
local balancing_list = {}
local shunt_list = {}
local iface_list = {}
for k, v in pairs(nodes_table) do
	if v.node_type == "normal" then
		normal_list[#normal_list + 1] = v
	end
	if v.protocol and v.protocol == "_balancing" then
		balancing_list[#balancing_list + 1] = v
	end
	if v.protocol and v.protocol == "_shunt" then
		shunt_list[#shunt_list + 1] = v
	end
	if v.protocol and v.protocol == "_iface" then
		iface_list[#iface_list + 1] = v
	end
end

local tcp_socks_server = "127.0.0.1" .. ":" .. (uci:get(appname, "@global[0]", "tcp_node_socks_port") or "1070")
local socks_table = {{
	id = tcp_socks_server,
	remark = tcp_socks_server .. " - " .. translate("TCP Node")
}}

local doh_validate = function(self, value, t)
	if value ~= "" then
		value = api.trim(value)
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not datatypes.ipmask4(v) and not datatypes.ipmask6(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
end

local chinadns_dot_validate = function(self, value, t)
	local function isValidDoTString(s)
		local prefix = "tls://"
		if s:sub(1, #prefix) ~= prefix then
			return false
		end
		local address = s:sub(#prefix + 1)
		local at_index = address:find("@")
		local hash_index = address:find("#")
		local domain, ip, port
		if at_index then
			if hash_index then
				domain = address:sub(1, at_index - 1)
				ip = address:sub(at_index + 1, hash_index - 1)
				port = address:sub(hash_index + 1)
			else
				domain = address:sub(1, at_index - 1)
				ip = address:sub(at_index + 1)
				port = nil
			end
		else
			if hash_index then
				ip = address:sub(1, hash_index - 1)
				port = address:sub(hash_index + 1)
			else
				ip = address
				port = nil
			end
		end
		local function isValidPort(port)
			if not port then return true end
			local num = tonumber(port)
			return num and num > 0 and num < 65536
		end
		local function isValidDomain(domain)
			if not domain then return true end
			return #domain > 0
		end
		local function isValidIP(ip)
			return datatypes.ipaddr(ip) or datatypes.ip6addr(ip)
		end
		if not isValidIP(ip) or not isValidPort(port) then
			return false
		end
		if not isValidDomain(domain) then
			return false
		end
		return true
	end

	if value ~= "" then
		value = api.trim(value)
		if isValidDoTString(value) then
			return value
		end
	end
	return nil, translate("Direct DNS") .. " DoT " .. translate("Format must be:") .. " tls://Domain@IP(#Port) or tls://IP(#Port)"
end

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- TCP Node
tcp_node = s:taboption("Main", ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
tcp_node:value("nil", translate("Close"))

---- UDP Node
udp_node = s:taboption("Main", ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
udp_node:value("nil", translate("Close"))
udp_node:value("tcp", translate("Same as the tcp node"))

-- 分流
if (has_singbox or has_xray) and #nodes_table > 0 then
	local function get_cfgvalue(shunt_node_id, option)
		return function(self, section)
			return m:get(shunt_node_id, option) or "nil"
		end
	end
	local function get_write(shunt_node_id, option)
		return function(self, section, value)
			m:set(shunt_node_id, option, value)
		end
	end
	if #normal_list > 0 then
		for k, v in pairs(shunt_list) do
			local vid = v.id
			-- shunt node type, Sing-Box or Xray
			local type = s:taboption("Main", ListValue, vid .. "-type", translate("Type"))
			if has_singbox then
				type:value("sing-box", "Sing-Box")
			end
			if has_xray then
				type:value("Xray", translate("Xray"))
			end
			type.cfgvalue = get_cfgvalue(v.id, "type")
			type.write = get_write(v.id, "type")

			-- pre-proxy
			o = s:taboption("Main", Flag, vid .. "-preproxy_enabled", translate("Preproxy"))
			o:depends("tcp_node", v.id)
			o.rmempty = false
			o.cfgvalue = get_cfgvalue(v.id, "preproxy_enabled")
			o.write = get_write(v.id, "preproxy_enabled")

			o = s:taboption("Main", ListValue, vid .. "-main_node", string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
			o:depends(vid .. "-preproxy_enabled", "1")
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(iface_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end
			o.cfgvalue = get_cfgvalue(v.id, "main_node")
			o.write = get_write(v.id, "main_node")

			if (has_singbox and has_xray) or (v.type == "sing-box" and not has_singbox) or (v.type == "Xray" and not has_xray) then
				type:depends("tcp_node", v.id)
			else
				type:depends("tcp_node", "hide") --不存在的依赖，即始终隐藏
			end

			uci:foreach(appname, "shunt_rules", function(e)
				local id = e[".name"]
				local node_option = vid .. "-" .. id .. "_node"
				if id and e.remarks then
					o = s:taboption("Main", ListValue, node_option, string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
					o.cfgvalue = get_cfgvalue(v.id, id)
					o.write = get_write(v.id, id)
					o:depends("tcp_node", v.id)
					o:value("nil", translate("Close"))
					o:value("_default", translate("Default"))
					o:value("_direct", translate("Direct Connection"))
					o:value("_blackhole", translate("Blackhole"))

					local pt = s:taboption("Main", ListValue, vid .. "-".. id .. "_proxy_tag", string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
					pt.cfgvalue = get_cfgvalue(v.id, id .. "_proxy_tag")
					pt.write = get_write(v.id, id .. "_proxy_tag")
					pt:value("nil", translate("Close"))
					pt:value("main", translate("Preproxy Node"))
					pt.default = "nil"
					for k1, v1 in pairs(balancing_list) do
						o:value(v1.id, v1.remark)
					end
					for k1, v1 in pairs(iface_list) do
						o:value(v1.id, v1.remark)
					end
					for k1, v1 in pairs(normal_list) do
						o:value(v1.id, v1.remark)
						pt:depends({ [node_option] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
					end
				end
			end)

			local id = "default_node"
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default")))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:depends("tcp_node", v.id)
			o:value("_direct", translate("Direct Connection"))
			o:value("_blackhole", translate("Blackhole"))
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(iface_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end

			local id = "default_proxy_tag"
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:value("nil", translate("Close"))
			o:value("main", translate("Preproxy Node"))
			for k1, v1 in pairs(normal_list) do
				if v1.protocol ~= "_balancing" then
					o:depends({ [vid .. "-default_node"] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
				end
			end
		end
	else
		local tips = s:taboption("Main", DummyValue, "tips", " ")
		tips.rawhtml = true
		tips.cfgvalue = function(t, n)
			return string.format('<a style="color: red">%s</a>', translate("There are no available nodes, please add or subscribe nodes first."))
		end
		tips:depends({ tcp_node = "nil", ["!reverse"] = true })
		for k, v in pairs(shunt_list) do
			tips:depends("udp_node", v.id)
		end
		for k, v in pairs(balancing_list) do
			tips:depends("udp_node", v.id)
		end
	end
end

tcp_node_socks_port = s:taboption("Main", Value, "tcp_node_socks_port", translate("TCP Node") .. " Socks " .. translate("Listen Port"))
tcp_node_socks_port.default = 1070
tcp_node_socks_port.datatype = "port"
tcp_node_socks_port:depends({ tcp_node = "nil", ["!reverse"] = true })
--[[
if has_singbox or has_xray then
	tcp_node_http_port = s:taboption("Main", Value, "tcp_node_http_port", translate("TCP Node") .. " HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	tcp_node_http_port.default = 0
	tcp_node_http_port.datatype = "port"
end
]]--
tcp_node_socks_bind_local = s:taboption("Main", Flag, "tcp_node_socks_bind_local", translate("TCP Node") .. " Socks " .. translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
tcp_node_socks_bind_local.default = "1"
tcp_node_socks_bind_local:depends({ tcp_node = "nil", ["!reverse"] = true })

s:tab("DNS", translate("DNS"))

dns_shunt = s:taboption("DNS", ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
dns_shunt:value("dnsmasq", "Dnsmasq")
dns_shunt:value("chinadns-ng", "Dnsmasq + ChinaDNS-NG")

o = s:taboption("DNS", ListValue, "direct_dns_mode", translate("Direct DNS") .. " " .. translate("Request protocol"))
o.default = ""
o:value("", translate("Auto"))
o:value("udp", translatef("Requery DNS By %s", "UDP"))
o:value("tcp", translatef("Requery DNS By %s", "TCP"))
if os.execute("chinadns-ng -V | grep -i wolfssl >/dev/null") == 0 then
	o:value("dot", translatef("Requery DNS By %s", "DoT"))
end
--TO DO
--o:value("doh", "DoH")
o:depends({dns_shunt = "dnsmasq"})
o:depends({dns_shunt = "chinadns-ng"})

o = s:taboption("DNS", Value, "direct_dns_udp", translate("Direct DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("119.29.29.29")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:value("114.114.114.114")
o:depends("direct_dns_mode", "udp")

o = s:taboption("DNS", Value, "direct_dns_tcp", translate("Direct DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:depends("direct_dns_mode", "tcp")

o = s:taboption("DNS", Value, "direct_dns_dot", translate("Direct DNS"))
o.default = "tls://dot.pub@1.12.12.12"
o:value("tls://dot.pub@1.12.12.12")
o:value("tls://dot.pub@120.53.53.53")
o:value("tls://dot.360.cn@36.99.170.86")
o:value("tls://dot.360.cn@101.198.191.4")
o:value("tls://dns.alidns.com@2400:3200::1")
o:value("tls://dns.alidns.com@2400:3200:baba::1")
o.validate = chinadns_dot_validate
o:depends("direct_dns_mode", "dot")

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"

---- DNS Forward Mode
dns_mode = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
dns_mode:value("udp", translatef("Requery DNS By %s", "UDP"))
dns_mode:value("tcp", translatef("Requery DNS By %s", "TCP"))
if api.is_finded("dns2socks") then
	dns_mode:value("dns2socks", "dns2socks")
end
if has_singbox then
	dns_mode:value("sing-box", "Sing-Box")
end
if has_xray then
	dns_mode:value("xray", "Xray")
end

o = s:taboption("DNS", ListValue, "xray_dns_mode", translate("Request protocol"))
o:value("tcp", "TCP")
o:value("tcp+doh", "TCP + DoH (" .. translate("A/AAAA type") .. ")")
o:depends("dns_mode", "xray")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if dns_mode:formvalue(section) == "xray" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:taboption("DNS", ListValue, "singbox_dns_mode", translate("Request protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:depends("dns_mode", "sing-box")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if dns_mode:formvalue(section) == "sing-box" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:taboption("DNS", Value, "socks_server", translate("Socks Server"), translate("Make sure socks service is available on this address."))
for k, v in pairs(socks_table) do o:value(v.id, v.remark) end
o.default = socks_table[1].id
o.validate = function(self, value, t)
	if not datatypes.ipaddrport(value) then
		return nil, translate("Socks Server") .. " " .. translate("Not valid IP format, please re-enter!")
	end
	return value
end
o:depends({dns_mode = "dns2socks"})

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({dns_mode = "tcp"})
o:depends({dns_mode = "udp"})
o:depends({xray_dns_mode = "tcp"})
o:depends({xray_dns_mode = "tcp+doh"})
o:depends({singbox_dns_mode = "tcp"})

---- DoH
o = s:taboption("DNS", Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.default = "https://1.1.1.1/dns-query"
o:value("https://1.1.1.1/dns-query", "CloudFlare")
o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
o:value("https://8.8.4.4/dns-query", "Google 8844")
o:value("https://8.8.8.8/dns-query", "Google 8888")
o:value("https://9.9.9.9/dns-query", "Quad9-Recommended 9.9.9.9")
o:value("https://149.112.112.112/dns-query", "Quad9-Recommended 149.112.112.112")
o:value("https://208.67.222.222/dns-query", "OpenDNS")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o.validate = doh_validate
o:depends({xray_dns_mode = "tcp+doh"})
o:depends({singbox_dns_mode = "doh"})

o = s:taboption("DNS", Value, "dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends({dns_mode = "xray"})

o = s:taboption("DNS", Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the shunt domain that proxy."))
o.default = "0"
o:depends({dns_mode = "sing-box", dns_shunt = "dnsmasq"})
o.validate = function(self, value, t)
	if value and value == "1" then
		local _dns_mode = dns_mode:formvalue(t)
		local _tcp_node = tcp_node:formvalue(t)
		if _dns_mode and _tcp_node and _tcp_node ~= "nil" then
			if m:get(_tcp_node, "type"):lower() ~= _dns_mode then
				return nil, translatef("TCP node must be '%s' type to use FakeDNS.", _dns_mode)
			end
		end
	end
	return value
end

o = s:taboption("DNS", ListValue, "chinadns_ng_default_tag", translate("Default DNS"))
o.default = "none"
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o:value("none", translate("Smart, Do not accept no-ip reply from Direct DNS"))
o:value("none_noip", translate("Smart, Accept no-ip reply from Direct DNS"))
local desc = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
o.description = desc
		.. "<li>" .. translate("Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.") .. "</li>"
		.. "<li>" .. translate("In smart mode, no-ip reply from Direct DNS:") .. "</li>"
		.. "<li>" .. translate("Do not accept: Wait and use Remote DNS Reply.") .. "</li>"
		.. "<li>" .. translate("Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.") .. "</li>"
		.. "</ul>"
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", Flag, "dns_redirect", "DNS " .. translate("Redirect"), translate("Force Router DNS server to all local devices. Disable DNS redirect in DNSMASQ."))
o.default = "1"

o = s:taboption("DNS", Button, "clear_ipset", translate("Clear NFTSET"), translate("Try this feature if the rule modification does not take effect."))
o.inputstyle = "remove"
function o.write(e, e)
	luci.sys.call('sh /usr/share/passwall/nftables.sh flush_nftset_reload > /dev/null 2>&1 &')
	luci.http.redirect(api.url("log"))
end

s:tab("Proxy", translate("Mode"))

o = s:taboption("Proxy", Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "0"

o = s:taboption("Proxy", Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "0"

o = s:taboption("Proxy", Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "0"

if has_gfwlist then
	o = s:taboption("Proxy", Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "0"
end

if has_chnlist or has_chnroute then
	o = s:taboption("Proxy", ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
end

---- TCP Default Proxy Mode
tcp_proxy_mode = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("Default Proxy Mode"))
tcp_proxy_mode:value("disable", translate("No Proxy"))
tcp_proxy_mode:value("proxy", translate("Proxy"))
tcp_proxy_mode.default = "proxy"

---- UDP Default Proxy Mode
udp_proxy_mode = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("Default Proxy Mode"))
udp_proxy_mode:value("disable", translate("No Proxy"))
udp_proxy_mode:value("proxy", translate("Proxy"))
udp_proxy_mode.default = "proxy"

o = s:taboption("Proxy", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
o.default = "0"
o.rmempty = false

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "log_tcp", translate("Enable") .. " " .. translatef("%s Node Log", "TCP"))
o.default = "0"
o.rmempty = false

o = s:taboption("log", Flag, "log_udp", translate("Enable") .. " " .. translatef("%s Node Log", "UDP"))
o.default = "0"
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", "Sing-Box/Xray " .. translate("Log Level"))
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

trojan_loglevel = s:taboption("log", ListValue, "trojan_loglevel", "Trojan " ..  translate("Log Level"))
trojan_loglevel.default = "2"
trojan_loglevel:value("0", "all")
trojan_loglevel:value("1", "info")
trojan_loglevel:value("2", "warn")
trojan_loglevel:value("3", "error")
trojan_loglevel:value("4", "fatal")

for k, v in pairs(nodes_table) do
	tcp_node:value(v.id, v["remark"])
	udp_node:value(v.id, v["remark"])
end

m:append(Template(appname .. "/global/footer"))

return m
