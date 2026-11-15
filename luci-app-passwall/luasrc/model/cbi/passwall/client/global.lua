local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local datatypes = api.datatypes
local has_gfwlist = api.fs.access("/usr/share/passwall/rules/gfwlist")
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

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("基础设置"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("启用"))
o.rmempty = false

---- TCP Node
tcp_node = s:taboption("Main", ListValue, "tcp_node", translate("TCP 节点"))
tcp_node:value("nil", translate("关闭"))

---- UDP Node
udp_node = s:taboption("Main", ListValue, "udp_node", translate("UDP 节点"))
udp_node:value("nil", translate("关闭"))
udp_node:value("tcp", translate("与 TCP 节点相同"))

-- 分流
if #nodes_table > 0 then
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
			-- pre-proxy
			o = s:taboption("Main", Flag, vid .. "-preproxy_enabled", translate("前置代理"))
			o:depends("tcp_node", v.id)
			o.rmempty = false
			o.cfgvalue = get_cfgvalue(v.id, "preproxy_enabled")
			o.write = get_write(v.id, "preproxy_enabled")

			o = s:taboption("Main", ListValue, vid .. "-main_node", translate("前置代理节点"), translate("各规则可单独设置是否使用。"))
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

			uci:foreach(appname, "shunt_rules", function(e)
				local id = e[".name"]
				local node_option = vid .. "-" .. id .. "_node"
				if id and e.remarks then
					o = s:taboption("Main", ListValue, node_option, string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
					o.cfgvalue = get_cfgvalue(v.id, id)
					o.write = get_write(v.id, id)
					o:depends("tcp_node", v.id)
					o:value("nil", translate("关闭"))
					o:value("_default", translate("默认"))
					o:value("_direct", translate("直连"))
					o:value("_blackhole", translate("黑洞"))

					local pt = s:taboption("Main", ListValue, vid .. "-".. id .. "_proxy_tag", string.format('* %s', e.remarks .. " " .. translate("前置代理")))
					pt.cfgvalue = get_cfgvalue(v.id, id .. "_proxy_tag")
					pt.write = get_write(v.id, id .. "_proxy_tag")
					pt:value("nil", translate("关闭"))
					pt:value("main", translate("前置代理节点"))
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
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* %s', translate("默认")))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:depends("tcp_node", v.id)
			o:value("_direct", translate("直连"))
			o:value("_blackhole", translate("黑洞"))
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
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* %s', translate("默认前置代理")), translate("本机先连接此前置代理，再连接默认节点。"))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:value("nil", translate("关闭"))
			o:value("main", translate("前置代理节点"))
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
			return translate("没有可用节点，请先添加节点。")
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

tcp_node_socks_port = s:taboption("Main", Value, "tcp_node_socks_port", translate("TCP 节点 SOCKS 监听端口"))
tcp_node_socks_port.default = 1070
tcp_node_socks_port.datatype = "port"
tcp_node_socks_port:depends({ tcp_node = "nil", ["!reverse"] = true })
tcp_node_socks_bind_local = s:taboption("Main", Flag, "tcp_node_socks_bind_local", translate("TCP 节点 SOCKS 仅本机访问"))
tcp_node_socks_bind_local.default = "1"
tcp_node_socks_bind_local:depends({ tcp_node = "nil", ["!reverse"] = true })

s:tab("DNS", translate("DNS"))

dns_shunt = s:taboption("DNS", ListValue, "dns_shunt", translate("DNS 分流组件"))
dns_shunt:value("dnsmasq", "dnsmasq")
dns_shunt:value("chinadns-ng", "dnsmasq + ChinaDNS-NG")

o = s:taboption("DNS", ListValue, "direct_dns_mode", translate("直连 DNS 请求协议"))
o.default = ""
o:value("", translate("自动"))
o:value("udp", "UDP")
o:value("tcp", "TCP")
--TO DO
--o:value("doh", "DoH")
o:depends({dns_shunt = "dnsmasq"})
o:depends({dns_shunt = "chinadns-ng"})

o = s:taboption("DNS", Value, "direct_dns_udp", translate("直连 DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("119.29.29.29")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:value("114.114.114.114")
o:depends("direct_dns_mode", "udp")

o = s:taboption("DNS", Value, "direct_dns_tcp", translate("直连 DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:depends("direct_dns_mode", "tcp")

---- DNS Forward Mode
dns_mode = s:taboption("DNS", ListValue, "dns_mode", translate("代理 DNS 处理方式"))
dns_mode:value("udp", "UDP")
dns_mode:value("tcp", "TCP")
dns_mode:value("xray", "Xray")

o = s:taboption("DNS", ListValue, "xray_dns_mode", translate("上游协议"))
o:value("tcp", "TCP")
o:value("tcp+doh", "TCP + DoH（" .. translate("A/AAAA 类型") .. "）")
o:depends("dns_mode", "xray")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if dns_mode:formvalue(section) == "xray" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("远程 DNS"))
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
o:depends({dns_mode = "tcp"})
o:depends({dns_mode = "udp"})
o:depends({xray_dns_mode = "tcp"})
o:depends({xray_dns_mode = "tcp+doh"})

---- DoH
o = s:taboption("DNS", Value, "remote_dns_doh", translate("远程 DNS DoH"))
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

o = s:taboption("DNS", Value, "dns_client_ip", translate("EDNS 客户端子网"))
o.description = translate("上游 DNS 须支持 RFC 7871，且仅填写公网 IP。")
o.datatype = "ipaddr"
o:depends({dns_mode = "xray"})

o = s:taboption("DNS", ListValue, "chinadns_ng_default_tag", translate("默认 DNS"))
o.default = "none"
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o:value("none", translate("智能（不接受直连 DNS 空响应）"))
o:value("none_noip", translate("智能（接受直连 DNS 空响应）"))
local desc = translate("未命中域名列表时使用；智能模式并行查询，直连结果为中国 IP 时优先返回。")
o.description = desc
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", ListValue, "use_default_dns", translate("默认 DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", Flag, "dns_redirect", translate("DNS 劫持"), translate("启用后关闭系统 DNS 重定向；关闭 Passwall 后重新开启。"))
o.default = "1"

s:tab("Proxy", translate("分流"))

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

if has_chnroute then
	o = s:taboption("Proxy", ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
end

---- TCP Default Proxy Mode
tcp_proxy_mode = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("默认代理方式"))
tcp_proxy_mode:value("disable", translate("No Proxy"))
tcp_proxy_mode:value("proxy", translate("Proxy"))
tcp_proxy_mode.default = "proxy"

---- UDP Default Proxy Mode
udp_proxy_mode = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("默认代理方式"))
udp_proxy_mode:value("disable", translate("No Proxy"))
udp_proxy_mode:value("proxy", translate("Proxy"))
udp_proxy_mode.default = "proxy"

o = s:taboption("Proxy", Flag, "localhost_proxy", translate("本机代理"))
o.default = "0"
o.rmempty = false

for k, v in pairs(nodes_table) do
	tcp_node:value(v.id, v["remark"])
	udp_node:value(v.id, v["remark"])
end


m:append(Template("passwall/style"))

return m
