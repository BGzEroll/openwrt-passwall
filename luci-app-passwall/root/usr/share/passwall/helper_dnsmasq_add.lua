local api = require "luci.passwall.api"
local appname = "passwall"

local var = api.get_args(arg)
local TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"]
local DNSMASQ_CONF_FILE = var["-DNSMASQ_CONF_FILE"]
local LOCAL_DNS = var["-LOCAL_DNS"]
local TUN_DNS = var["-TUN_DNS"]
local REMOTE_FAKEDNS = var["-REMOTE_FAKEDNS"]
local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
local CHINADNS_DNS = var["-CHINADNS_DNS"]
local TCP_NODE = var["-TCP_NODE"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local USE_GFW_LIST = var["-USE_GFW_LIST"]
local CHN_LIST = var["-CHN_LIST"]
local DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]

local uci = api.uci
local fs = api.fs
local datatypes = api.datatypes

local list1 = {}
local excluded_domain = {}

local function log(...)
	if NO_LOGIC_LOG == "1" then
		return
	end
	api.log(...)
end

local function fail_file(action, path, err)
	error(string.format("%s %s: %s", action, path, tostring(err)), 0)
end

local function read_lines(path)
	local input, err = io.open(path, "r")
	if not input then
		fail_file("cannot read", path, err)
	end

	local lines = {}
	while true do
		local line, read_err = input:read("*l")
		if line == nil then
			if read_err then
				input:close()
				fail_file("cannot read", path, read_err)
			end
			break
		end
		lines[#lines + 1] = line
	end

	local ok, close_err = input:close()
	if not ok then
		fail_file("cannot close", path, close_err)
	end
	return lines
end

local function write_file(path, content)
	local output, err = io.open(path, "w")
	if not output then
		fail_file("cannot write", path, err)
	end

	local ok, write_err = output:write(content)
	if not ok then
		output:close()
		fail_file("cannot write", path, write_err)
	end

	local close_ok, close_err = output:close()
	if not close_ok then
		fail_file("cannot close", path, close_err)
	end
end

local function ensure_output_dir(path)
	if not path or path == "" then
		error("missing -TMP_DNSMASQ_PATH", 0)
	end
	local ok, err = fs.mkdir(path)
	if not ok and not fs.access(path) then
		fail_file("cannot create directory", path, err)
	end
end

local function output_path(name)
	if TMP_DNSMASQ_PATH:sub(-1) == "/" then
		return TMP_DNSMASQ_PATH .. name
	end
	return TMP_DNSMASQ_PATH .. "/" .. name
end

ensure_output_dir(TMP_DNSMASQ_PATH)

local function check_dns(domain, dns)
	if domain == "" or domain:find("#") then
		return false
	end
	if not dns then
		return
	end
	for k,v in ipairs(list1[domain].dns) do
		if dns == v then
			return true
		end
	end
	return false
end

local function check_ipset(domain, ipset)
	if domain == "" or domain:find("#") then
		return false
	end
	if not ipset then
		return
	end
	for k,v in ipairs(list1[domain].ipsets) do
		if ipset == v then
			return true
		end
	end
	return false
end

local function set_domain_address(domain, address)
	if domain == "" or domain:find("#") then
		return
	end
	if not list1[domain] then
		list1[domain] = {
			dns = {},
			ipsets = {}
		}
	end
	if not list1[domain].address then
		list1[domain].address = address
	end
end

local function set_domain_dns(domain, dns)
	if domain == "" or domain:find("#") then
		return
	end
	if not dns then
		return
	end
	if not list1[domain] then
		list1[domain] = {
			dns = {},
			ipsets = {}
		}
	end
	for line in string.gmatch(dns, '[^' .. "," .. ']+') do
		if not check_dns(domain, line) then
			table.insert(list1[domain].dns, line)
		end
	end
end

local function set_domain_ipset(domain, ipset)
	if domain == "" or domain:find("#") then
		return
	end
	if not ipset then
		return
	end
	if not list1[domain] then
		list1[domain] = {
			dns = {},
			ipsets = {}
		}
	end
	for line in string.gmatch(ipset, '[^' .. "," .. ']+') do
		if not check_ipset(domain, line) then
			table.insert(list1[domain].ipsets, line)
		end
	end
end

local function add_excluded_domain(domain)
	if domain == "" or domain:find("#") then
		return
	end
	table.insert(excluded_domain, domain)
end

local function check_excluded_domain(domain)
	if domain == "" or domain:find("#") then
		return false
	end
	for k,v in ipairs(excluded_domain) do
		if domain:find(v) then
			return true
		end
	end
	return false
end

local dnsmasq_default_dns
if USE_DEFAULT_DNS ~= "nil" then
	if USE_DEFAULT_DNS == "direct" then
		dnsmasq_default_dns = LOCAL_DNS
	end
	if USE_DEFAULT_DNS == "remote" then
		dnsmasq_default_dns = TUN_DNS
	end
end

local only_global
if DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0" then
	--没有启用中国列表和GFW列表时
	dnsmasq_default_dns = TUN_DNS
	only_global = 1
end
if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
	dnsmasq_default_dns = CHINADNS_DNS
end

local setflag_4 = "4#inet#passwall#"
local setflag_6 = "6#inet#passwall#"

do
	--屏蔽列表
	if USE_BLOCK_LIST == "1" then
		for _, line in ipairs(read_lines("/usr/share/passwall/rules/block_host")) do
			if line ~= "" and not line:find("#") then
				set_domain_address(line, "")
			end
		end
	end

	local fwd_dns
	local ipset_flag

	--始终用国内DNS解析节点域名
	if true then
		fwd_dns = LOCAL_DNS
		if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
			fwd_dns = nil
		else
			uci:foreach(appname, "nodes", function(t)
				local address = t.address
				if address == "engage.cloudflareclient.com" then return end
				if datatypes.hostname(address) then
					set_domain_dns(address, fwd_dns)
					set_domain_ipset(address, setflag_4 .. "passwall_vpslist," .. setflag_6 .. "passwall_vpslist6")
				end
			end)
		end
		log(string.format("  - 节点列表中的域名(vpslist)：%s", fwd_dns or "默认"))
	end

	--直连（白名单）列表
	if USE_DIRECT_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/direct_host") then
			fwd_dns = LOCAL_DNS
			if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
				fwd_dns = nil
			end
			if fwd_dns then
				--始终用国内DNS解析直连（白名单）列表
				for _, line in ipairs(read_lines("/usr/share/passwall/rules/direct_host")) do
					if line ~= "" and not line:find("#") then
						add_excluded_domain(line)
						set_domain_dns(line, fwd_dns)
						set_domain_ipset(line, setflag_4 .. "passwall_whitelist," .. setflag_6 .. "passwall_whitelist6")
					end
				end
			end
			log(string.format("  - 域名白名单(whitelist)：%s", fwd_dns or "默认"))
		end
	end

	--代理（黑名单）列表
	if USE_PROXY_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/proxy_host") then
			fwd_dns = TUN_DNS
			if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
				fwd_dns = nil
			end
			if fwd_dns then
				--始终使用远程DNS解析代理（黑名单）列表
				for _, line in ipairs(read_lines("/usr/share/passwall/rules/proxy_host")) do
					if line ~= "" and not line:find("#") then
						add_excluded_domain(line)
						local ipset_flag = setflag_4 .. "passwall_blacklist," .. setflag_6 .. "passwall_blacklist6"
						if REMOTE_FAKEDNS == "1" then
							ipset_flag = nil
						end
						set_domain_dns(line, fwd_dns)
						set_domain_ipset(line, ipset_flag)
					end
				end
			end
			log(string.format("  - 代理域名表(blacklist)：%s", fwd_dns or "默认"))
		end
	end

	--GFW列表
	if USE_GFW_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/gfwlist") then
			fwd_dns = TUN_DNS
			if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
				fwd_dns = nil
			end
			if fwd_dns then
				local ipset_flag = setflag_4 .. "passwall_gfwlist," .. setflag_6 .. "passwall_gfwlist6"
				if REMOTE_FAKEDNS == "1" then
					ipset_flag = nil
				end
				for _, line in ipairs(read_lines("/usr/share/passwall/rules/gfwlist")) do
					line = line:gsub("\r$", "")
					if line ~= "" and not line:find("^#") and not check_excluded_domain(line) then
						if dnsmasq_default_dns == fwd_dns then
							fwd_dns = nil
						else
							set_domain_dns(line, fwd_dns)
						end
						set_domain_ipset(line, ipset_flag)
					end
				end
			end
			log(string.format("  - 防火墙域名表(gfwlist)：%s", fwd_dns or "默认"))
		end
	end

	--分流规则
	if uci:get(appname, TCP_NODE, "protocol") == "_shunt" then
		local t = uci:get_all(appname, TCP_NODE)
		local default_node_id = t["default_node"] or "_direct"
		uci:foreach(appname, "shunt_rules", function(s)
			if not api.is_supported_shunt_rule(s) then
				return
			end
			local _node_id = t[s[".name"]] or "nil"
			if _node_id ~= "nil" and _node_id ~= "_blackhole" then
				if _node_id == "_default" then
					_node_id = default_node_id
				end

				fwd_dns = nil
				ipset_flag = nil

				if _node_id == "_direct" then
					fwd_dns = LOCAL_DNS
					ipset_flag = setflag_4 .. "passwall_whitelist," .. setflag_6 .. "passwall_whitelist6"
				else
					fwd_dns = TUN_DNS
					ipset_flag = setflag_4 .. "passwall_shuntlist," .. setflag_6 .. "passwall_shuntlist6"
					if not only_global then
						if REMOTE_FAKEDNS == "1" then
							ipset_flag = nil
						end
					end
				end

				local domain_list = s.domain_list or ""
				for line in string.gmatch(domain_list, "[^\r\n]+") do
					if line ~= "" and not line:find("#") and not line:find("regexp:") then
						if line:find("domain:") or line:find("full:") then
							line = string.match(line, ":([^:]+)$")
						end
						add_excluded_domain(line)

						set_domain_dns(line, fwd_dns)
						set_domain_ipset(line, ipset_flag)
					end
				end
				if _node_id ~= "_direct" then
					log(string.format("  - V2ray/Xray分流规则(%s)：%s", s.remarks, fwd_dns or "默认"))
				end
			end
		end)
	end
end

local addresses = {}
local servers = {}
local ipsets = {}
local domains = {}
for domain in pairs(list1) do
	domains[#domains + 1] = domain
end
table.sort(domains)

local set_name = "nftset"
for _, key in ipairs(domains) do
	local value = list1[key]
	if value.address then
		local domain = "." .. key
		addresses[#addresses + 1] = string.format("address=/%s/%s\n", domain, value.address)
	end
	if value.dns and #value.dns > 0 then
		for _, dns in ipairs(value.dns) do
			servers[#servers + 1] = string.format("server=/.%s/%s\n", key, dns)
		end
	end
	if value.ipsets and #value.ipsets > 0 then
		local ipsets_str = table.concat(value.ipsets, ",")
		ipsets[#ipsets + 1] = string.format("%s=/.%s/%s\n", set_name, key, ipsets_str)
	end
end

write_file(output_path("000-address.conf"), table.concat(addresses))
write_file(output_path("001-server.conf"), table.concat(servers))
write_file(output_path("ipset.conf"), table.concat(ipsets))

if not DNSMASQ_CONF_FILE or DNSMASQ_CONF_FILE == "" or DNSMASQ_CONF_FILE == "nil" then
	error("missing -DNSMASQ_CONF_FILE", 0)
end

local conf = { string.format("conf-dir=%s\n", TMP_DNSMASQ_PATH) }
if dnsmasq_default_dns then
	for s in string.gmatch(dnsmasq_default_dns, '[^' .. "," .. ']+') do
		conf[#conf + 1] = string.format("server=%s\n", s)
	end
	conf[#conf + 1] = "all-servers\n"
	conf[#conf + 1] = "no-poll\n"
	conf[#conf + 1] = "no-resolv\n"
	log(string.format("  - 默认：%s", dnsmasq_default_dns))
end
write_file(DNSMASQ_CONF_FILE, table.concat(conf))

log("  - PassWall必须依赖于Dnsmasq，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！")
