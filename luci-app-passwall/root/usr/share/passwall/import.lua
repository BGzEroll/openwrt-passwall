#!/usr/bin/lua

require "luci.model.uci"
require "luci.jsonc"
require "luci.sys"

local appname = "passwall"
local api = require "luci.passwall.api"
local datatypes = require "luci.cbi.datatypes"
local split = api.split
local jsonParse = luci.jsonc.parse
local base64Decode = api.base64Decode
local uci = luci.model.uci.cursor()

local has_ss = api.is_finded("ss-redir")
local has_ss_rust = api.is_finded("sslocal")
local has_trojan_plus = api.is_finded("trojan-plus")
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")
local has_hysteria2 = api.finded_com("hysteria")
local allowInsecure_default = false
local ss_type_default = has_ss and "shadowsocks-libev" or has_ss_rust and "shadowsocks-rust" or has_xray and "xray" or has_singbox and "sing-box"
local trojan_type_default = has_trojan_plus and "trojan-plus" or has_singbox and "sing-box" or has_xray and "xray"
local vmess_type_default = has_xray and "xray" or has_singbox and "sing-box"
local vless_type_default = has_xray and "xray" or has_singbox and "sing-box"
local hysteria2_type_default = has_hysteria2 and "hysteria2" or has_singbox and "sing-box"

local function log(...)
	api.log(...)
end

local tinsert = table.insert
local schar = string.char
local sgsub = string.gsub

local function get_urldecode(h) return schar(tonumber(h, 16)) end
local function UrlDecode(szText)
	return (szText and szText:gsub("%+", " "):gsub("%%(%x%x)", get_urldecode)) or nil
end

-- trim
local function trim(text)
	if not text or text == "" then return "" end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end

local function processData(szType, content)
	local result = {
		timeout = 60
	}
	--ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0)
	if szType == 'ssr' then
		result.type = "SSR"

		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		if dat[1]:match('%[(.*)%]') then
			result.address = dat[1]:match('%[(.*)%]')
		else
			result.address = hostInfo[#hostInfo-5]
		end
		result.port = hostInfo[#hostInfo-4]
		result.protocol = hostInfo[#hostInfo-3]
		result.method = hostInfo[#hostInfo-2]
		result.obfs = hostInfo[#hostInfo-1]
		result.password = base64Decode(hostInfo[#hostInfo])	
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			params[t[1]] = t[2]
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		local group = base64Decode(params.group)
		if group then result.group = group end
		result.remarks = base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = jsonParse(content)
		if has_singbox then
			result.type = 'sing-box'
		end
		if has_xray then
			result.type = 'Xray'
		end
		if vmess_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		end
		if vmess_type_default == "xray" and has_xray then
			result.type = "Xray"
		end
		result.alter_id = info.aid
		result.address = info.add
		result.port = info.port
		result.protocol = 'vmess'
		result.uuid = info.id
		result.remarks = info.ps
		-- result.mux = 1
		-- result.mux_concurrency = 8

		if not info.net then
			info.net = "tcp"
		end
		info.net = string.lower(info.net)
		result.transport = info.net
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
			if result.type == "sing-box" and info.path then
				local ws_path_dat = split(info.path, "?")
				local ws_path = ws_path_dat[1]
				local ws_path_params = {}
				for _, v in pairs(split(ws_path_dat[2], '&')) do
					local t = split(v, '=')
					ws_path_params[t[1]] = t[2]
				end
				if ws_path_params.ed and tonumber(ws_path_params.ed) then
					result.ws_path = ws_path
					result.ws_enableEarlyData = "1"
					result.ws_maxEarlyData = tonumber(ws_path_params.ed)
					result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
				end
			end
		end
		if info.net == 'h2' then
			result.h2_host = info.host
			result.h2_path = info.path
		end
		if info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.tcp_guise_http_host = info.host
			result.tcp_guise_http_path = info.path
		end
		if info.net == 'kcp' or info.net == 'mkcp' then
			info.net = "mkcp"
			result.mkcp_guise = info.type
			result.mkcp_mtu = 1350
			result.mkcp_tti = 50
			result.mkcp_uplinkCapacity = 5
			result.mkcp_downlinkCapacity = 20
			result.mkcp_readBufferSize = 2
			result.mkcp_writeBufferSize = 2
			result.mkcp_seed = info.seed
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.net == 'grpc' then
			result.grpc_serviceName = info.path
		end
		if not info.security then result.security = "auto" end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_serverName = (info.sni and info.sni ~= "") and info.sni or info.host
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		else
			result.tls = "0"
		end
	elseif szType == "ss" then
		result.type = "SS"

		--SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
		--userinfo = websafe-base64-encode-utf8(method  ":" password)
		--ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1
		--ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver#Example3
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss

		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		result.remarks = UrlDecode(alias)
		local info = content:sub(1, idx_sp - 1):gsub("/%?", "?")
		local params = {}
		if info:find("?") then
			local find_index = info:find("?")
			local query = split(info, "?")
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			if params.plugin then
				local plugin_info = params.plugin
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts =
						plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
			info = info:sub(1, find_index - 1)
		end

		local hostInfo = split(UrlDecode(info), "@")
		if hostInfo and #hostInfo > 0 then
			local host_port = hostInfo[#hostInfo]
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local userinfo = nil
			if #hostInfo > 2 then
				userinfo = {}
				for i = 1, #hostInfo - 1 do
					tinsert(userinfo, hostInfo[i])
				end
				userinfo = table.concat(userinfo, '@')
			else
				userinfo = base64Decode(hostInfo[1])
			end

			local method = userinfo:sub(1, userinfo:find(":") - 1)
			local password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
			result.method = method
			result.password = password

			if ss_type_default == "shadowsocks-rust" and has_ss_rust then
				result.type = 'SS-Rust'
			end
			if ss_type_default == "xray" and has_xray then
				result.type = 'Xray'
				result.protocol = 'shadowsocks'
				result.transport = 'tcp'
			end
			if ss_type_default == "sing-box" and has_singbox then
				result.type = 'sing-box'
				result.protocol = 'shadowsocks'
			end

			if result.type == "SS-Rust" and method:lower() == "chacha20-poly1305" then
				result.method = "chacha20-ietf-poly1305"
			end

			if result.type == "Xray" and method:lower() == "chacha20-ietf-poly1305" then
				result.method = "chacha20-poly1305"
			end

			if result.plugin then
				if result.type == 'Xray' then
					--不支持插件
					result.error_msg = "Xray不支持插件."
				end
				if result.type == "sing-box" then
					result.plugin_enabled = "1"
				end
			end

			if result.type == "SS" then
				local aead2022_methods = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }
				local aead2022 = false
				for k, v in ipairs(aead2022_methods) do
					if method:lower() == v:lower() then
						aead2022 = true
					end
				end
				if aead2022 then
					-- shadowsocks-libev 不支持2022加密
					result.error_msg = "shadowsocks-libev 不支持2022加密."
				end
			end

			if params.type then
				params.type = string.lower(params.type)
				result.transport = params.type
				if result.type ~= "SS-Rust" and result.type ~= "SS" then
					if params.type == 'ws' then
						result.ws_host = params.host
						result.ws_path = params.path
						if result.type == "sing-box" and params.path then
							local ws_path_dat = split(params.path, "?")
							local ws_path = ws_path_dat[1]
							local ws_path_params = {}
							for _, v in pairs(split(ws_path_dat[2], '&')) do
								local t = split(v, '=')
								ws_path_params[t[1]] = t[2]
							end
							if ws_path_params.ed and tonumber(ws_path_params.ed) then
								result.ws_path = ws_path
								result.ws_enableEarlyData = "1"
								result.ws_maxEarlyData = tonumber(ws_path_params.ed)
								result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
							end
						end
					end
					if params.type == 'h2' or params.type == 'http' then
						if result.type == "sing-box" then
							result.transport = "http"
							result.http_host = params.host
							result.http_path = params.path
						elseif result.type == "xray" then
							result.transport = "h2"
							result.h2_host = params.host
							result.h2_path = params.path
						end
					end
					if params.type == 'tcp' then
						result.tcp_guise = params.headerType or "none"
						result.tcp_guise_http_host = params.host
						result.tcp_guise_http_path = params.path
					end
					if params.type == 'kcp' or params.type == 'mkcp' then
						result.transport = "mkcp"
						result.mkcp_guise = params.headerType or "none"
						result.mkcp_mtu = 1350
						result.mkcp_tti = 50
						result.mkcp_uplinkCapacity = 5
						result.mkcp_downlinkCapacity = 20
						result.mkcp_readBufferSize = 2
						result.mkcp_writeBufferSize = 2
						result.mkcp_seed = params.seed
					end
					if params.type == 'quic' then
						result.quic_guise = params.headerType or "none"
						result.quic_key = params.key
						result.quic_security = params.quicSecurity or "none"
					end
					if params.type == 'grpc' then
						if params.path then result.grpc_serviceName = params.path end
						if params.serviceName then result.grpc_serviceName = params.serviceName end
						result.grpc_mode = params.mode
					end
					result.tls = "0"
					if params.security == "tls" or params.security == "reality" then
						result.tls = "1"
						result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
						result.alpn = params.alpn
						result.fingerprint = (params.fp and params.fp ~= "") and params.fp or "chrome"
						if params.security == "reality" then
							result.reality = "1"
							result.reality_publicKey = params.pbk or nil
							result.reality_shortId = params.sid or nil
							result.reality_spiderX = params.spx or nil
						end
					end
					result.tls_allowInsecure = allowInsecure_default and "1" or "0"
				else
					result.error_msg = "请更换Xray或Sing-Box来支持SS更多的传输方式."
				end
			end
		end
	elseif szType == "trojan" then
		if trojan_type_default == "trojan-plus" and has_trojan_plus then
			result.type = "Trojan-Plus"
		elseif trojan_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif trojan_type_default == "xray" and has_xray then
			result.type = 'Xray'
		end
		result.protocol = 'trojan'
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				if #t > 1 then
					params[string.lower(t[1])] = UrlDecode(t[2])
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local peer, sni = nil, ""
			if params.peer then peer = params.peer end
			sni = params.sni and params.sni or ""
			result.port = port

			result.tls = '1'
			result.tls_serverName = peer and peer or sni

			if params.allowinsecure then
				if params.allowinsecure == "1" or params.allowinsecure == "0" then
					result.tls_allowInsecure = params.allowinsecure
				else
					result.tls_allowInsecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
				end
				--log(result.remarks .. ' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end

			if not params.type then
				params.type = "tcp"
			end
			params.type = string.lower(params.type)
			result.transport = params.type
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == 'h2' or params.type == 'http' then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = params.host
					result.http_path = params.path
				elseif result.type == "xray" then
					result.transport = "h2"
					result.h2_host = params.host
					result.h2_path = params.path
				end
			end
			if params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = params.host
				result.tcp_guise_http_path = params.path
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode
			end
			
			result.encryption = params.encryption or "none"

			result.flow = params.flow or nil

		end

	elseif szType == "ssd" then
		result.type = "SS"
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	elseif szType == "vless" then
		if has_singbox then
			result.type = 'sing-box'
		end
		if has_xray then
			result.type = 'Xray'
		end
		if vless_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		end
		if vless_type_default == "xray" and has_xray then
			result.type = "Xray"
		end
		result.protocol = "vless"
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.uuid = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			if not params.type then
				params.type = "tcp"
			end
			params.type = string.lower(params.type)
			result.transport = params.type
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == 'h2' or params.type == 'http' then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = params.host
					result.http_path = params.path
				elseif result.type == "xray" then
					result.transport = "h2"
					result.h2_host = params.host
					result.h2_path = params.path
				end
			end
			if params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = params.host
				result.tcp_guise_http_path = params.path
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode
			end
			if params.type == 'splithttp' then
				result.splithttp_host = params.host
				result.splithttp_path = params.path
			end
			
			result.encryption = params.encryption or "none"

			result.flow = params.flow or nil

			result.tls = "0"
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
				result.alpn = params.alpn
				result.fingerprint = (params.fp and params.fp ~= "") and params.fp or "chrome"
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
					result.reality_spiderX = params.spx or nil
				end
			end

			result.port = port
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
	elseif szType == 'hysteria' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		
		local dat = split(content:gsub("/%?", "?"), '%?')
		local host_port = dat[1]
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			if #t > 0 then
				params[t[1]] = t[2]
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.protocol = params.protocol
		result.hysteria_obfs = params.obfsParam
		result.hysteria_auth_type = "string"
		result.hysteria_auth_password = params.auth
		result.tls_serverName = params.peer
		if params.insecure and (params.insecure == "1" or params.insecure == "0") then
			result.tls_allowInsecure = params.insecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria_alpn = params.alpn
		result.hysteria_up_mbps = params.upmbps
		result.hysteria_down_mbps = params.downmbps

		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria"
		end
	elseif szType == 'hysteria2' or szType == 'hy2' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			result.hysteria2_auth_password = UrlDecode(contents[1])
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		if params.insecure and (params.insecure == "1" or params.insecure == "0") then
			result.tls_allowInsecure = params.insecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria2_tls_pinSHA256 = params.pinSHA256

		if has_hysteria2 then
			result.type = "Hysteria2"
			if params["obfs-password"] then
				result.hysteria2_obfs = params["obfs-password"]
			end
		end
		if hysteria2_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria2"
			if params["obfs-password"] then
				result.hysteria2_obfs_type = "salamander"
				result.hysteria2_obfs_password = params["obfs-password"]
			end
		end
	else
		log('暂时不支持' .. szType .. "类型的分享链接，跳过此节点。")
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end


local function parse_link(raw)
	local node_list = {}
	if not raw or trim(raw) == "" then
		return node_list
	end

	local nodes
	local szType
	if raw:find("ssd://", 1, true) then
		szType = "ssd"
		local _, nEnd = raw:find("ssd://", 1, true)
		local decoded = base64Decode(raw:sub(nEnd + 1))
		local ssd = jsonParse(decoded or "")
		if type(ssd) ~= "table" or type(ssd.servers) ~= "table" then
			log("SSD 分享链接格式无效，跳过。")
			return node_list
		end
		local extra = {
			airport = ssd.airport,
			port = ssd.port,
			encryption = ssd.encryption,
			password = ssd.password
		}
		nodes = {}
		for _, server in ipairs(ssd.servers) do
			tinsert(nodes, setmetatable(server, { __index = extra }))
		end
	else
		nodes = { raw }
	end

	for _, value in ipairs(nodes) do
		if value then
			local ok, err = xpcall(function()
				local result
				if szType == "ssd" then
					result = processData(szType, value)
				else
					local node = trim(value)
					local dat = split(node, "://")
					if dat and dat[1] and dat[2] then
						local protocol = dat[1]
						local content = dat[2]
						if protocol ~= "ss" and protocol ~= "trojan" then
							content = base64Decode(content)
						end
						result = processData(protocol, content)
					end
				end
				if result then
					if result.error_msg then
						log("丢弃节点: " .. (result.remarks or "") .. ", 原因:" .. result.error_msg)
					elseif not result.type then
						log("丢弃节点: " .. (result.remarks or "") .. ", 找不到可使用二进制。")
					elseif not result.address or result.remarks == "NULL" or result.address == "127.0.0.1" or
						(not datatypes.hostname(result.address) and not api.is_ip(result.address)) then
						log("丢弃无效节点: " .. (result.remarks or ""))
					else
						tinsert(node_list, result)
					end
				end
			end, function(err)
				return err
			end)
			if not ok then
				log(value, "解析错误，跳过此节点。", err)
			end
		end
	end
	return node_list
end

local function import_file(file_path)
	local file, err = io.open(file_path, "r")
	if not file then
		log("无法读取分享链接文件: " .. tostring(err))
		return false
	end
	local content = file:read("*all")
	file:close()
	if not content or trim(content) == "" then
		log("分享链接文件为空。")
		return false
	end

	local parsed_nodes = {}
	local lines = split(content:gsub("[ \t\r\n]+", "\n"), "\n")
	for _, raw in ipairs(lines) do
		for _, node in ipairs(parse_link(raw)) do
			tinsert(parsed_nodes, node)
		end
	end
	if #parsed_nodes == 0 then
		log("没有解析到有效的分享链接节点。")
		return false
	end

	for _, node in ipairs(parsed_nodes) do
		local section = uci:section(appname, "nodes", api.gen_short_uuid())
		if not section then
			log("创建节点配置失败。")
			return false
		end
		for key, value in pairs(node) do
			uci:set(appname, section, key, value)
		end
	end

	local ok, committed = pcall(uci.commit, uci, appname)
	if not ok or committed == false then
		log("保存分享链接节点失败。")
		return false
	end
	luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
	log("分享链接节点导入成功: " .. #parsed_nodes)
	return true
end

local file_path = arg and arg[1]
if not file_path or file_path == "" then
	log("用法: lua /usr/share/passwall/import.lua <文件路径>")
	os.exit(2)
end

if not import_file(file_path) then
	os.exit(1)
end
os.exit(0)
