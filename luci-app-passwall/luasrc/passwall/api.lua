module("luci.passwall.api", package.seeall)
bin = require "nixio".bin
fs = require "nixio.fs"
sys = require "luci.sys"
local config_dir = os.getenv("PASSWALL_CONFIG_DIR")
uci = config_dir and require("uci").cursor(config_dir, config_dir) or require("luci.model.uci").cursor()
util = require "luci.util"
datatypes = require "luci.cbi.datatypes"
jsonc = require "luci.jsonc"
i18n = require "luci.i18n"

appname = "passwall"
curl_args = { "-skfL", "--connect-timeout 3", "--retry 3" }

LOG_FILE = "/tmp/log/" .. appname .. ".log"

function log(component, ...)
	local message = table.concat({...}, " "):gsub("[\r\n]+", " ")
	local f = io.open(LOG_FILE, "a")
	if f then
		f:write(os.date("%Y-%m-%d %H:%M:%S") .. " [" .. component .. "] " .. message .. "\n")
		f:close()
	end
end

local debug_logging
function log_debug(component, ...)
	if debug_logging == nil then debug_logging = uci:get(appname, "@global[0]", "log_debug") == "1" end
	if debug_logging then log(component, ...) end
end

function normalize_domain(value)
	local domain = (value or ""):gsub("^%s+", ""):gsub("%s+$", ""):lower():gsub("%.$", "")
	return domain
end

function domain_matches(value, suffix)
	value, suffix = normalize_domain(value), normalize_domain(suffix)
	return suffix ~= "" and (value == suffix or value:sub(-#suffix - 1) == "." .. suffix)
end

-- Reject the whole old rule so removing a Geo selector cannot widen its match.
function is_supported_shunt_rule(rule)
	for _, key in ipairs({"source", "domain_list", "ip_list"}) do
		local value = rule[key]
		if type(value) == "string" then
			local pattern = key == "source" and "%S+" or "[^\r\n]+"
			for item in value:gmatch(pattern) do
				item = item:gsub("^%s+", "")
				if item:find("^geoip:") or item:find("^geosite:") or item:find("^ext:") then
					return false
				end
			end
		end
	end
	return true
end

function exec_call(cmd)
	local process = io.popen(cmd .. '; echo -e "\n$?"')
	local lines = {}
	local result = ""
	local return_code
	for line in process:lines() do
		lines[#lines + 1] = line
	end
	process:close()
	if #lines > 0 then
		return_code = lines[#lines]
		for i = 1, #lines - 1 do
			result = result .. lines[i] .. ((i == #lines - 1) and "" or "\n")
		end
	end
	return tonumber(return_code), trim(result)
end

function base64Decode(text)
	local raw = text
	if not text then return '' end
	text = text:gsub("%z", "")
	text = text:gsub("%c", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = nixio.bin.b64decode(text)
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end

function curl_base(url, file, args)
	if not args then args = {} end
	if file then
		args[#args + 1] = "-o " .. util.shellquote(file)
	end
	local cmd = string.format('curl %s -- %s', table.concat(args, " "), util.shellquote(url))
	return exec_call(cmd)
end

function curl_proxy(url, file, args)
	--使用代理
	local socks_server = (fs.readfile("/tmp/etc/passwall/acl/default/TCP_SOCKS_server") or ""):gsub("%s+$", "")
	if socks_server ~= "" then
		if not args then args = {} end
		local tmp_args = clone(args)
		tmp_args[#tmp_args + 1] = "-x " .. util.shellquote("socks5h://" .. socks_server)
		return curl_base(url, file, tmp_args)
	end
	return nil, nil
end

function curl_logic(url, file, args)
	local return_code, result = curl_proxy(url, file, args)
	if not return_code or return_code ~= 0 then
		return_code, result = curl_base(url, file, args)
	end
	return return_code, result
end

function url(...)
	local url = string.format("admin/services/%s", appname)
	local args = { ... }
	for i, v in pairs(args) do
		if v ~= "" then
			url = url .. "/" .. v
		end
	end
	return require "luci.dispatcher".build_url(url)
end

function trim(s)
	return (s:gsub("^%s*(.-)%s*$", "%1"))
end

-- 分割字符串
-- Internal generators accept explicit key/value pairs, preserving whitespace.
function get_args(args, first)
 local values = {}
 for i = first or 1, #args, 2 do
  local key, value = args[i], args[i + 1]
  assert(key:match('^%-[%w_]+$') and value ~= nil, '无效生成参数：' .. tostring(key))
  if value ~= '' then values[key] = value end
 end
 return values
end

function is_normal_node(e)
	if e and e.type and e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface") then
		return false
	end
	return true
end

function is_ip(val)
	if is_ipv6(val) then
		val = get_ipv6_only(val)
	end
	return datatypes.ipaddr(val)
end

function is_ipv6(val)
	local str = val
	local address = val:match('%[(.*)%]')
	if address then
		str = address
	end
	if datatypes.ip6addr(str) then
		return true
	end
	return false
end

function get_ipv6_only(val)
	local result = ""
	if is_ipv6(val) then
		result = val
		if val:match('%[(.*)%]') then
			result = val:match('%[(.*)%]')
		end
	end
	return result
end

function get_valid_nodes()
	local nodes = {}
	uci:foreach(appname, "nodes", function(e)
		e.id = e[".name"]
		if e.type == "Xray" and e.remarks then
			if e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface") then
				local type = e.type
				e["remark"] = "%s：%s" % {type .. " " .. i18n.translatef(e.protocol), e.remarks}
				e["node_type"] = "special"
				nodes[#nodes + 1] = e
			end
			if e.port and e.address then
				local address = e.address
				if is_ip(address) or datatypes.hostname(address) then
					local type = e.type
					if e.protocol then
						local protocol = e.protocol
						if protocol == "socks" then
							protocol = "SOCKS"
						elseif protocol == "http" then
							protocol = "HTTP"
						elseif protocol == "vmess" then
							protocol = "VMess"
						elseif protocol == "vless" then
							protocol = "VLESS"
						elseif protocol == "shadowsocks" then
							protocol = "SS"
						elseif protocol == "wireguard" then
							protocol = "WG"
						else
							protocol = protocol:gsub("^%l",string.upper)
						end
						type = type .. " " .. protocol
					end
					e["remark"] = "%s：%s" % {type, e.remarks}
					e.node_type = "normal"
					nodes[#nodes + 1] = e
				end
			end
		end
	end)
	return nodes
end

function gen_short_uuid()
	return sys.exec("echo -n $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)")
end

function clone(org)
	local function copy(org, res)
		for k,v in pairs(org) do
			if type(v) ~= "table" then
				res[k] = v;
			else
				res[k] = {};
				copy(v, res[k])
			end
		end
	end

	local res = {}
	copy(org, res)
	return res
end

-- Xray form fields use a prefix only to group protocol-specific controls.
function xray_fields(m, s)
	local option_prefix = "xray_"
	local counts = {}
	for key, field in pairs(s.fields) do
		if key:sub(1, #option_prefix) == option_prefix and field.rewrite_option then
			counts[field.rewrite_option] = (counts[field.rewrite_option] or 0) + 1
		end
	end
	for key, field in pairs(s.fields) do
		if key:sub(1, #option_prefix) == option_prefix and not field.not_rewrite then
			local option = field.rewrite_option or key:sub(#option_prefix + 1)
			field.cfgvalue = function(self, section) return m:get(section, option) end
			field.write = function(self, section, value) m:set(section, option, value) end
			field.remove = function(self, section)
				if not self.rewrite_option or counts[option] == 1 then m:del(section, option) end
			end
		end
	end
end
