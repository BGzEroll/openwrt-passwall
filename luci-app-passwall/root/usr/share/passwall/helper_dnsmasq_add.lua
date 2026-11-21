local api = require "luci.passwall.api"
local fs, uci = api.fs, api.uci
local args = api.get_args(arg)
local local_dns, remote_dns = args["-LOCAL_DNS"], args["-TUN_DNS"]
local china_dns = args["-CHINADNS_DNS"]
local use_china_dns = china_dns ~= "0"
local default_dns = args["-USE_DEFAULT_DNS"] == "direct" and local_dns
	or args["-USE_DEFAULT_DNS"] == "remote" and remote_dns
if args["-DEFAULT_PROXY_MODE"] == "proxy" and args["-CHN_LIST"] == "0" and args["-USE_GFW_LIST"] == "0" then
	default_dns = remote_dns
end
if use_china_dns then default_dns = china_dns end

local domains, excluded = {}, {}

local function domain_name(value)
	local domain = api.normalize_domain(value)
	if domain ~= "" and not domain:find("#", 1, true) then return domain end
end

local function append_unique(values, value)
	for _, existing in ipairs(values) do
		if existing == value then return end
	end
	values[#values + 1] = value
end

local function add_rule(domain, dns, set, blocked)
	local rule = domains[domain]
	if not rule then
		rule = {servers = {}, sets = {}}
		domains[domain] = rule
	end
	if blocked then rule.blocked = true end
	if dns then
		for server in dns:gmatch("[^,]+") do append_unique(rule.servers, server) end
	end
	if set then append_unique(rule.sets, set) end
end

local function read_domains(file, optional, add)
	local path = "/usr/share/passwall/rules/" .. file
	local content, code, message = fs.readfile(path)
	if not content and optional and code == 2 then return end
	assert(content, path .. ": " .. tostring(message))
	for line in content:gmatch("[^\r\n]+") do
		local domain = domain_name(line)
		if domain then add(domain) end
	end
end

if args["-USE_BLOCK_LIST"] == "1" then
	read_domains("block_host", false, function(domain) add_rule(domain, nil, nil, true) end)
end

if not use_china_dns then
	uci:foreach("passwall", "nodes", function(node)
		local address = node.address
		if address ~= "engage.cloudflareclient.com" and api.datatypes.hostname(address) then
			local domain = domain_name(address)
			if domain then add_rule(domain, local_dns, "passwall_vpslist") end
		end
	end)

	local function add_list(file, dns, set)
		read_domains(file, true, function(domain)
			excluded[domain] = true
			add_rule(domain, dns, set)
		end)
		api.log_debug("DNS", file .. "：" .. dns)
	end
	if args["-USE_DIRECT_LIST"] == "1" then
		add_list("direct_host", local_dns, "passwall_whitelist")
	end
	if args["-USE_PROXY_LIST"] == "1" then
		add_list("proxy_host", remote_dns, "passwall_blacklist")
	end
	if args["-USE_GFW_LIST"] == "1" then
		local dns = remote_dns
		if dns == default_dns then dns = nil end
		read_domains("gfwlist", true, function(domain)
			local suffix = domain
			while suffix do
				if excluded[suffix] then return end
				suffix = suffix:match("^[^.]+%.(.+)$")
			end
			add_rule(domain, dns, "passwall_gfwlist")
		end)
		api.log_debug("DNS", "GFW 列表：" .. (dns or "默认"))
	end
end

local node = uci:get_all("passwall", args["-TCP_NODE"])
if node and node.protocol == "_shunt" then
	uci:foreach("passwall", "shunt_rules", function(rule)
		local target = node[rule[".name"]]
		if not target or target == "nil" or target == "_blackhole" or not api.is_supported_shunt_rule(rule) then return end
		if target == "_default" then target = node.default_node or "_direct" end
		local direct = target == "_direct"
		local dns, set = remote_dns, "passwall_shuntlist"
		if direct then dns, set = local_dns, "passwall_whitelist" end
		for line in (rule.domain_list or ""):gmatch("[^\r\n]+") do
			if not line:find("#", 1, true) and not line:find("regexp:", 1, true) then
				if line:find("domain:", 1, true) or line:find("full:", 1, true) then
					line = line:match(":([^:]+)$")
				end
				local domain = domain_name(line)
				if domain then add_rule(domain, dns, set) end
			end
		end
		if not direct then api.log_debug("DNS", "分流规则（" .. (rule.remarks or "") .. "）：" .. dns) end
	end)
end

local lines, order = {}, {}
if default_dns then
	for server in default_dns:gmatch("[^,]+") do lines[#lines + 1] = "server=" .. server end
	lines[#lines + 1] = "all-servers\nno-poll\nno-resolv"
	api.log_debug("DNS", "默认：" .. default_dns)
end
for domain in pairs(domains) do order[#order + 1] = domain end
table.sort(order)
for _, domain in ipairs(order) do
	local rule = domains[domain]
	if rule.blocked then lines[#lines + 1] = "address=/." .. domain .. "/" end
	for _, server in ipairs(rule.servers) do
		lines[#lines + 1] = "server=/." .. domain .. "/" .. server
	end
	if #rule.sets > 0 then
		local sets = {}
		for _, set in ipairs(rule.sets) do
			sets[#sets + 1] = "4#inet#passwall#" .. set
			sets[#sets + 1] = "6#inet#passwall#" .. set .. "6"
		end
		lines[#lines + 1] = "nftset=/." .. domain .. "/" .. table.concat(sets, ",")
	end
end
local path = args["-DNSMASQ_CONF_FILE"]
assert(fs.writefile(path, table.concat(lines, "\n") .. "\n"), "写入 DNS 配置失败：" .. path)
