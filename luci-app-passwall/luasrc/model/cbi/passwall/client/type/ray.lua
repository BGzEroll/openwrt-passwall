local m, s = ...

local api = require "luci.passwall.api"

local appname = "passwall"
local uci = api.uci

local option_prefix = "xray_"

local function option_name(name)
	return option_prefix .. name
end

local ss_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
}

local xray_version = api.get_app_version("xray")
-- [[ Xray ]]

o = s:option(ListValue, option_name("protocol"), translate("Protocol"))
o:value("vmess", "VMess")
o:value("vless", translate("VLESS"))
o:value("http", translate("HTTP"))
o:value("socks", "SOCKS")
o:value("shadowsocks", translate("Shadowsocks"))
o:value("trojan", translate("Trojan"))
o:value("wireguard", translate("WireGuard"))
o:value("_balancing", translate("Balancing"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))

o = s:option(Value, option_name("iface"), translate("Interface"))
o.default = "eth1"
o:depends({ [option_name("protocol")] = "_iface" })

local nodes_table = {}
local balancers_table = {}
local fallback_table = {}
local iface_table = {}
local is_balancer = nil
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"]
		}
	end
	if e.protocol == "_balancing" then
		balancers_table[#balancers_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
		if e[".name"] ~= arg[1] then
			fallback_table[#fallback_table + 1] = {
				id = e[".name"],
				remark = e["remark"],
				fallback = e["fallback_node"]
			}
		else
			is_balancer = true
		end
	end
	if e.protocol == "_iface" then
		iface_table[#iface_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
	end
end

-- 负载均衡列表
local o = s:option(DynamicList, option_name("balancing_node"), translate("均衡节点"))
o:depends({ [option_name("protocol")] = "_balancing" })
for k, v in pairs(nodes_table) do o:value(v.id, v.remark) end

local o = s:option(ListValue, option_name("balancingStrategy"), translate("Balancing Strategy"))
o:depends({ [option_name("protocol")] = "_balancing" })
o:value("random")
o:value("roundRobin")
o:value("leastPing")
o.default = "leastPing"

-- Fallback Node
if api.compare_versions(xray_version, ">=", "1.8.10") then
	local o = s:option(ListValue, option_name("fallback_node"), translate("Fallback Node"))
	if api.compare_versions(xray_version, ">=", "1.8.12") then
		o:depends({ [option_name("protocol")] = "_balancing" })
	else
		o:depends({ [option_name("balancingStrategy")] = "leastPing" })
	end
	local function check_fallback_chain(fb)
		for k, v in pairs(fallback_table) do
			if v.fallback == fb then
				fallback_table[k] = nil
				check_fallback_chain(v.id)
			end
		end
	end
	-- 检查fallback链，去掉会形成闭环的balancer节点
	if is_balancer then
		check_fallback_chain(arg[1])
	end
	for k, v in pairs(fallback_table) do o:value(v.id, v.remark) end
	for k, v in pairs(nodes_table) do o:value(v.id, v.remark) end
end

-- 探测地址
local ucpu = s:option(Flag, option_name("useCustomProbeUrl"), translate("自定义探测地址"))
ucpu:depends({ [option_name("balancingStrategy")] = "leastPing" })

local pu = s:option(Value, option_name("probeUrl"), translate("Probe URL"))
pu:depends({ [option_name("useCustomProbeUrl")] = true })
pu:value("https://cp.cloudflare.com/", "Cloudflare")
pu:value("https://www.gstatic.com/generate_204", "Gstatic")
pu:value("https://www.google.com/generate_204", "Google")
pu:value("https://www.youtube.com/generate_204", "YouTube")
pu:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
pu:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
pu.default = "https://www.google.com/generate_204"


-- 探测间隔
local pi = s:option(Value, option_name("probeInterval"), translate("Probe Interval"))
pi:depends({ [option_name("balancingStrategy")] = "leastPing" })
pi.default = "1m"
pi.description = translate("例如 10s、1m、2h45m。")

if api.compare_versions(xray_version, ">=", "1.8.12") then
	ucpu:depends({ [option_name("protocol")] = "_balancing" })
	pi:depends({ [option_name("protocol")] = "_balancing" })
else
	ucpu:depends({ [option_name("balancingStrategy")] = "leastPing" })
	pi:depends({ [option_name("balancingStrategy")] = "leastPing" })
end


-- [[ 分流模块 ]]
if #nodes_table > 0 then
	o = s:option(Flag, option_name("preproxy_enabled"), translate("Preproxy"))
	o:depends({ [option_name("protocol")] = "_shunt" })

	o = s:option(ListValue, option_name("main_node"), translate("前置代理节点"), translate("各分流规则可单独选择是否使用。"))
	o:depends({ [option_name("protocol")] = "_shunt", [option_name("preproxy_enabled")] = true })
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
	end
	o.default = "nil"
end
uci:foreach(appname, "shunt_rules", function(e)
	if e[".name"] and e.remarks then
		o = s:option(ListValue, option_name(e[".name"]), string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", e[".name"]), e.remarks))
		o:value("nil", translate("Close"))
		o:value("_default", translate("Default"))
		o:value("_direct", translate("Direct Connection"))
		o:value("_blackhole", translate("Blackhole"))
		o:depends({ [option_name("protocol")] = "_shunt" })

		if #nodes_table > 0 then
			for k, v in pairs(balancers_table) do
				o:value(v.id, v.remark)
			end
			for k, v in pairs(iface_table) do
				o:value(v.id, v.remark)
			end
			local pt = s:option(ListValue, option_name(e[".name"] .. "_proxy_tag"), string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
			pt:value("nil", translate("Close"))
			pt:value("main", translate("Preproxy Node"))
			pt.default = "nil"
			for k, v in pairs(nodes_table) do
				o:value(v.id, v.remark)
				pt:depends({ [option_name("protocol")] = "_shunt", [option_name("preproxy_enabled")] = true, [option_name(e[".name"])] = v.id })
			end
		end
	end
end)

o = s:option(DummyValue, option_name("shunt_tips"), " ")
o.not_rewrite = true
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="../rule">%s</a>', translate("No shunt rules? Click me to go to add."))
end
o:depends({ [option_name("protocol")] = "_shunt" })

local o = s:option(ListValue, option_name("default_node"), string.format('* <a style="color:red">%s</a>', translate("Default")))
o:depends({ [option_name("protocol")] = "_shunt" })
o:value("_direct", translate("Direct Connection"))
o:value("_blackhole", translate("Blackhole"))

if #nodes_table > 0 then
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
	end
	local dpt = s:option(ListValue, option_name("default_proxy_tag"), translate("默认前置代理"))
	dpt:value("nil", translate("Close"))
	dpt:value("main", translate("Preproxy Node"))
	dpt.default = "nil"
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
		dpt:depends({ [option_name("protocol")] = "_shunt", [option_name("preproxy_enabled")] = true, [option_name("default_node")] = v.id })
	end
end

o = s:option(ListValue, option_name("domainStrategy"), translate("Domain Strategy"))
o:value("AsIs")
o:value("IPIfNonMatch")
o:value("IPOnDemand")
o.default = "IPOnDemand"
o.description = translate("AsIs：仅按域名；IPIfNonMatch：域名未命中后解析；IPOnDemand：需要 IP 规则时解析。")
o:depends({ [option_name("protocol")] = "_shunt" })

o = s:option(ListValue, option_name("domainMatcher"), translate("Domain matcher"))
o:value("hybrid")
o:value("linear")
o:depends({ [option_name("protocol")] = "_shunt" })

-- [[ 分流模块 End ]]

o = s:option(Value, option_name("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, option_name("port"), translate("Port"))
o.datatype = "port"

local protocols = s.fields[option_name("protocol")].keylist
if #protocols > 0 then
	for index, value in ipairs(protocols) do
		if not value:find("_") then
			s.fields[option_name("address")]:depends({ [option_name("protocol")] = value })
			s.fields[option_name("port")]:depends({ [option_name("protocol")] = value })
		end
	end
end

o = s:option(Value, option_name("username"), translate("Username"))
o:depends({ [option_name("protocol")] = "http" })
o:depends({ [option_name("protocol")] = "socks" })

o = s:option(Value, option_name("password"), translate("Password"))
o.password = true
o:depends({ [option_name("protocol")] = "http" })
o:depends({ [option_name("protocol")] = "socks" })
o:depends({ [option_name("protocol")] = "shadowsocks" })
o:depends({ [option_name("protocol")] = "trojan" })

o = s:option(ListValue, option_name("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [option_name("protocol")] = "vmess" })

o = s:option(Value, option_name("encryption"), translate("Encrypt Method"))
o.default = "none"
o:value("none")
o:depends({ [option_name("protocol")] = "vless" })

o = s:option(ListValue, option_name("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [option_name("protocol")] = "shadowsocks" })

o = s:option(Flag, option_name("iv_check"), translate("IV Check"))
o:depends({ [option_name("protocol")] = "shadowsocks", [option_name("ss_method")] = "aes-128-gcm" })
o:depends({ [option_name("protocol")] = "shadowsocks", [option_name("ss_method")] = "aes-256-gcm" })
o:depends({ [option_name("protocol")] = "shadowsocks", [option_name("ss_method")] = "chacha20-poly1305" })
o:depends({ [option_name("protocol")] = "shadowsocks", [option_name("ss_method")] = "xchacha20-poly1305" })

o = s:option(Flag, option_name("uot"), translate("UDP over TCP"))
o:depends({ [option_name("protocol")] = "shadowsocks" })

o = s:option(Value, option_name("uuid"), translate("ID"))
o.password = true
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })

o = s:option(ListValue, option_name("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [option_name("protocol")] = "vless", [option_name("tls")] = true, [option_name("transport")] = "tcp" })

o = s:option(Flag, option_name("tls"), translate("TLS"))
o.default = 0
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })
o:depends({ [option_name("protocol")] = "http" })
o:depends({ [option_name("protocol")] = "socks" })
o:depends({ [option_name("protocol")] = "trojan" })
o:depends({ [option_name("protocol")] = "shadowsocks" })

o = s:option(Flag, option_name("reality"), "REALITY", translate("建议搭配 VLESS、TCP 和 XTLS Vision。"))
o.default = 0
o:depends({ [option_name("tls")] = true, [option_name("transport")] = "tcp" })
o:depends({ [option_name("tls")] = true, [option_name("transport")] = "h2" })
o:depends({ [option_name("tls")] = true, [option_name("transport")] = "grpc" })

o = s:option(ListValue, option_name("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [option_name("tls")] = true, [option_name("reality")] = false })

-- o = s:option(Value, option_name("minversion"), translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ [option_name("tls")] = true })

o = s:option(Value, option_name("tls_serverName"), translate("Domain"))
o:depends({ [option_name("tls")] = true })

o = s:option(Flag, option_name("tls_allowInsecure"), translate("跳过证书验证"))
o.default = "0"
o:depends({ [option_name("tls")] = true, [option_name("reality")] = false })

-- [[ REALITY部分 ]] --
o = s:option(Value, option_name("reality_publicKey"), translate("Public Key"))
o:depends({ [option_name("tls")] = true, [option_name("reality")] = true })

o = s:option(Value, option_name("reality_shortId"), translate("Short Id"))
o:depends({ [option_name("tls")] = true, [option_name("reality")] = true })

o = s:option(Value, option_name("reality_spiderX"), translate("Spider X"))
o.placeholder = "/"
o:depends({ [option_name("tls")] = true, [option_name("reality")] = true })

o = s:option(Flag, option_name("utls"), translate("uTLS"))
o.default = "0"
o:depends({ [option_name("tls")] = true, [option_name("reality")] = false })

o = s:option(ListValue, option_name("fingerprint"), translate("Finger Print"))
o:value("chrome")
o:value("firefox")
o:value("edge")
o:value("safari")
o:value("360")
o:value("qq")
o:value("ios")
o:value("android")
o:value("random")
o:value("randomized")
o.default = "chrome"
o:depends({ [option_name("tls")] = true, [option_name("utls")] = true })
o:depends({ [option_name("tls")] = true, [option_name("reality")] = true })

o = s:option(ListValue, option_name("transport"), translate("Transport"))
o:value("tcp", "TCP")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("h2", "HTTP/2")
o:value("ds", "DomainSocket")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("splithttp", "SplitHTTP")
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })
o:depends({ [option_name("protocol")] = "socks" })
o:depends({ [option_name("protocol")] = "shadowsocks" })
o:depends({ [option_name("protocol")] = "trojan" })

o = s:option(Value, option_name("wireguard_public_key"), translate("Public Key"))
o:depends({ [option_name("protocol")] = "wireguard" })

o = s:option(Value, option_name("wireguard_secret_key"), translate("Private Key"))
o:depends({ [option_name("protocol")] = "wireguard" })

o = s:option(Value, option_name("wireguard_preSharedKey"), translate("Pre shared key"))
o:depends({ [option_name("protocol")] = "wireguard" })

o = s:option(DynamicList, option_name("wireguard_local_address"), translate("Local Address"))
o:depends({ [option_name("protocol")] = "wireguard" })

o = s:option(Value, option_name("wireguard_mtu"), translate("MTU"))
o.default = "1420"
o:depends({ [option_name("protocol")] = "wireguard" })

if api.compare_versions(xray_version, ">=", "1.8.0") then
	o = s:option(Value, option_name("wireguard_reserved"), "Reserved", translate("逗号分隔的十进制数字，或 Base64。"))
	o:depends({ [option_name("protocol")] = "wireguard" })
end

o = s:option(Value, option_name("wireguard_keepAlive"), translate("Keep Alive"))
o.default = "0"
o:depends({ [option_name("protocol")] = "wireguard" })

-- [[ TCP部分 ]]--

-- TCP伪装
o = s:option(ListValue, option_name("tcp_guise"), translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ [option_name("transport")] = "tcp" })

-- HTTP域名
o = s:option(DynamicList, option_name("tcp_guise_http_host"), translate("HTTP Host"))
o:depends({ [option_name("tcp_guise")] = "http" })

-- HTTP路径
o = s:option(DynamicList, option_name("tcp_guise_http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [option_name("tcp_guise")] = "http" })

-- [[ mKCP部分 ]]--

o = s:option(ListValue, option_name("mkcp_guise"), translate("伪装类型"))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_mtu"), translate("KCP MTU"))
o.default = "1350"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_tti"), translate("KCP TTI"))
o.default = "20"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_uplinkCapacity"), translate("KCP uplinkCapacity"))
o.default = "5"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_downlinkCapacity"), translate("KCP downlinkCapacity"))
o.default = "20"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Flag, option_name("mkcp_congestion"), translate("KCP Congestion"))
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_readBufferSize"), translate("KCP readBufferSize"))
o.default = "1"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_writeBufferSize"), translate("KCP writeBufferSize"))
o.default = "1"
o:depends({ [option_name("transport")] = "mkcp" })

o = s:option(Value, option_name("mkcp_seed"), translate("KCP Seed"))
o:depends({ [option_name("transport")] = "mkcp" })

-- [[ WebSocket部分 ]]--
o = s:option(Value, option_name("ws_host"), translate("WebSocket Host"))
o:depends({ [option_name("transport")] = "ws" })

o = s:option(Value, option_name("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [option_name("transport")] = "ws" })

-- [[ HTTP/2部分 ]]--
o = s:option(Value, option_name("h2_host"), translate("HTTP/2 Host"))
o:depends({ [option_name("transport")] = "h2" })

o = s:option(Value, option_name("h2_path"), translate("HTTP/2 Path"))
o.placeholder = "/"
o:depends({ [option_name("transport")] = "h2" })

o = s:option(Flag, option_name("h2_health_check"), translate("Health check"))
o:depends({ [option_name("transport")] = "h2" })

o = s:option(Value, option_name("h2_read_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [option_name("h2_health_check")] = true })

o = s:option(Value, option_name("h2_health_check_timeout"), translate("Health check timeout"))
o.default = "15"
o:depends({ [option_name("h2_health_check")] = true })

-- [[ DomainSocket部分 ]]--
o = s:option(Value, option_name("ds_path"), "Path", translate("A legal file path. This file must not exist before running."))
o:depends({ [option_name("transport")] = "ds" })

-- [[ QUIC部分 ]]--
o = s:option(ListValue, option_name("quic_security"), translate("Encrypt Method"))
o:value("none")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
o:depends({ [option_name("transport")] = "quic" })

o = s:option(Value, option_name("quic_key"), translate("Encrypt Method") .. translate("Key"))
o:depends({ [option_name("transport")] = "quic" })

o = s:option(ListValue, option_name("quic_guise"), translate("Camouflage Type"))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [option_name("transport")] = "quic" })

-- [[ gRPC部分 ]]--
o = s:option(Value, option_name("grpc_serviceName"), "ServiceName")
o:depends({ [option_name("transport")] = "grpc" })

o = s:option(ListValue, option_name("grpc_mode"), "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ [option_name("transport")] = "grpc" })

o = s:option(Flag, option_name("grpc_health_check"), translate("Health check"))
o:depends({ [option_name("transport")] = "grpc" })

o = s:option(Value, option_name("grpc_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [option_name("grpc_health_check")] = true })

o = s:option(Value, option_name("grpc_health_check_timeout"), translate("Health check timeout"))
o.default = "20"
o:depends({ [option_name("grpc_health_check")] = true })

o = s:option(Flag, option_name("grpc_permit_without_stream"), translate("Permit without stream"))
o.default = "0"
o:depends({ [option_name("grpc_health_check")] = true })

o = s:option(Value, option_name("grpc_initial_windows_size"), translate("Initial Windows Size"))
o.default = "0"
o:depends({ [option_name("transport")] = "grpc" })

-- [[ HttpUpgrade部分 ]]--
o = s:option(Value, option_name("httpupgrade_host"), translate("HttpUpgrade Host"))
o:depends({ [option_name("transport")] = "httpupgrade" })

o = s:option(Value, option_name("httpupgrade_path"), translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ [option_name("transport")] = "httpupgrade" })

-- [[ SplitHTTP部分 ]]--
o = s:option(Value, option_name("splithttp_host"), translate("SplitHTTP Host"))
o:depends({ [option_name("transport")] = "splithttp" })

o = s:option(Value, option_name("splithttp_path"), translate("SplitHTTP Path"))
o.placeholder = "/"
o:depends({ [option_name("transport")] = "splithttp" })

-- [[ Mux ]]--
o = s:option(Flag, option_name("mux"), translate("Mux"))
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless", [option_name("flow")] = "" })
o:depends({ [option_name("protocol")] = "http" })
o:depends({ [option_name("protocol")] = "socks" })
o:depends({ [option_name("protocol")] = "shadowsocks" })
o:depends({ [option_name("protocol")] = "trojan" })

o = s:option(Value, option_name("mux_concurrency"), translate("Mux concurrency"))
o.default = 8
o:depends({ [option_name("mux")] = true })

-- [[ XUDP Mux ]]--
o = s:option(Flag, option_name("xmux"), translate("xMux"))
o.default = 1
o:depends({ [option_name("protocol")] = "vless", [option_name("flow")] = "xtls-rprx-vision" })

o = s:option(Value, option_name("xudp_concurrency"), translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ [option_name("xmux")] = true })

--[[tcpMptcp]]
o = s:option(Flag, option_name("tcpMptcp"), "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

o = s:option(Flag, option_name("tcpNoDelay"), "tcpNoDelay")
o.default = 0

o = s:option(ListValue, option_name("to_node"), translate("落地节点"), translate("仅支持一层链式代理。"))
o.default = ""
o:value("", translate("Close(Not use)"))
for k, v in pairs(nodes_table) do
	if v.type == "Xray" then
		o:value(v.id, v.remark)
	end
end

for i, v in ipairs(s.fields[option_name("protocol")].keylist) do
	if not v:find("_") then
		s.fields[option_name("tcpMptcp")]:depends({ [option_name("protocol")] = v })
		s.fields[option_name("tcpNoDelay")]:depends({ [option_name("protocol")] = v })
		s.fields[option_name("to_node")]:depends({ [option_name("protocol")] = v })
	end
end

api.xray_fields(m, s)
