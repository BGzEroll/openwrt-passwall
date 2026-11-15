local api = require "luci.passwall.api"
local appname = "passwall"
local fs = api.fs

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

m = Map(appname)

-- [[ Delay Settings ]]--
s = m:section(TypedSection, "global_delay", translate("启动设置"))
s.anonymous = true
s.addremove = false

---- Delay Start
o = s:option(Value, "start_delay", translate("启动延迟（秒）"))
o.default = "60"
o.datatype = "uinteger"
o.rmempty = true

-- [[ Forwarding Settings ]]--
s = m:section(TypedSection, "global_forwarding",
			  translate("转发与高级设置"))
s.anonymous = true
s.addremove = false

---- TCP Bypass Ports
o = s:option(Value, "tcp_no_redir_ports", translate("TCP 不代理端口"),
				 translate("这些端口优先绕过 Passwall。"))
o.default = "disable"
o:value("disable", translate("不使用"))
o:value("1:65535", translate("全部"))
o.validate = port_validate

---- UDP Bypass Ports
o = s:option(Value, "udp_no_redir_ports", translate("UDP 不代理端口"),
				 translate("这些端口优先绕过 Passwall。"))
o.default = "disable"
o:value("disable", translate("不使用"))
o:value("1:65535", translate("全部"))
o.validate = port_validate

---- TCP Proxy Drop Ports
o = s:option(Value, "tcp_proxy_drop_ports", translate("TCP 代理丢弃端口"))
o.default = "disable"
o:value("disable", translate("不使用"))
o.validate = port_validate

---- UDP Proxy Drop Ports
o = s:option(Value, "udp_proxy_drop_ports", translate("UDP 代理丢弃端口"))
o.default = "disable"
o:value("disable", translate("不使用"))
o:value("443", translate("QUIC"))
o.validate = port_validate

---- TCP Proxy Ports
o = s:option(Value, "tcp_redir_ports", translate("TCP 代理端口"))
o.default = "1:65535"
o:value("1:65535", translate("全部"))
o:value("22,25,53,143,465,587,853,993,995,80,443", translate("常用端口"))
o:value("80,443", translate("仅 Web"))
o.validate = port_validate

---- UDP Proxy Ports
o = s:option(Value, "udp_redir_ports", translate("UDP 代理端口"))
o.default = "1:65535"
o:value("1:65535", translate("全部"))
o:value("53", "DNS")
o.validate = port_validate

o = s:option(Flag, "iproute_shunt", translate("通过策略路由转发代理流量"))
o.default = 0
o.description = translate("启用后关闭防火墙原生软硬件分载；关闭 Passwall 后重新开启。")

o = s:option(Value, "iproute_shunt_gw_v4", translate("转发至 IPv4 网关"))
o:depends("iproute_shunt", true)
o.placeholder = '192.168.113.10'
o.datatype = 'ip4addr'

o = s:option(Value, "iproute_shunt_gw_v6", translate("转发至 IPv6 网关"))
o:depends("iproute_shunt", true)
o.placeholder = 'fd00::10'
o.datatype = 'ip6addr'

o = s:option(Value, "iproute_shunt_interface", translate("通过接口"))
o:depends("iproute_shunt", true)
o.placeholder = 'br-lan'

o = s:option(DummyValue, "iproute_shunt_offloading_interface", translate("自动检测的硬件加速接口"))
o.template = "passwall/value_text"
o:depends("iproute_shunt", true)
o.cfgvalue = function(self, section)
	local interfaces = api.trim(api.sys.exec("ucode /usr/share/passwall/offload.uc 2>/dev/null") or "")
	return interfaces ~= "" and interfaces or "无可用接口"
end

o = s:option(Flag, "accept_icmp", translate("接管 ICMP"))
o.default = 1

o = s:option(Flag, "accept_icmpv6", translate("接管 ICMPv6"))
o.default = 1

s_xray = m:section(TypedSection, "global_xray", "Xray " .. translate("设置"))
s_xray.anonymous = true
s_xray.addremove = false

o = s_xray:option(Flag, "fragment", translate("TCP 分片"), translate("尝试通过 TCP/TLS 分片绕过 SNI 封锁。"))
o.default = 0

o = s_xray:option(ListValue, "fragment_packets", translate("分片方式"), translate("数字选项按客户端最初的 TCP 写入次数分片；tlshello 分割 TLS ClientHello。"))
o.default = "tlshello"
o:value("tlshello", "tlshello")
o:value("1-2", "1-2")
o:value("1-3", "1-3")
o:value("1-5", "1-5")
o:depends("fragment", true)

o = s_xray:option(Value, "fragment_length", translate("分片长度（字节）"))
o.default = "100-200"
o:depends("fragment", true)

o = s_xray:option(Value, "fragment_interval", translate("分片间隔（毫秒）"))
o.default = "10-20"
o:depends("fragment", true)

o = s_xray:option(Flag, "sniffing_override_dest", translate("按嗅探域名覆盖目标地址"))
o.default = 0

local domains_excluded = string.format("/usr/share/%s/rules/domains_excluded", appname)
o = s_xray:option(TextValue, "excluded_domains", translate("排除域名"), translate("嗅探结果命中此列表时不覆盖目标地址。"))
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section) return fs.readfile(domains_excluded) or "" end
o.write = function(self, section, value) fs.writefile(domains_excluded, value:gsub("\r\n", "\n")) end
o:depends({sniffing_override_dest = true})

o = s_xray:option(Value, "buffer_size", translate("单连接缓冲区大小（KB）"))
o.datatype = "uinteger"

m:append(Template("passwall/style"))

return m
