local api = require "luci.passwall.api"
local appname = "passwall"
local fs = api.fs
local sys = api.sys
local datatypes = api.datatypes
local rules_path = "/usr/share/passwall/rules/"

local m = Map(appname)
local pending_files = {}
function m.on_before_save()
	for path, content in pairs(pending_files) do
		if fs.readfile(path) ~= content then
			assert(fs.writefile(path, content), "规则文件写入失败：" .. path)
		end
	end
end
local rules = m:section(TypedSection, "global_rules", translate("规则管理"))
rules.anonymous = true

rules:tab("direct_list", translate("直连"))
rules:tab("proxy_list", translate("代理"))
rules:tab("block_list", translate("屏蔽"))
rules:tab("lan_ip_list", translate("局域网 IP"))
rules:tab("route_hosts", translate("Hosts"))
rules:tab("update", translate("更新"))

local function normalize_text(value)
	value = (value or ""):gsub("\r\n", "\n"):gsub("\r", "\n")
	value = value:gsub("^[ \t\n]+", ""):gsub("[ \t\n]+$", "\n")
	return (value:gsub("[ \t]*\n[ \t]*", "\n"))
end

local function validate_lines(value, validator, error_message, normalize_domains)
	local text = normalize_text(value)
	local lines = {}
	local seen = {}

	for line in (text .. "\n"):gmatch("(.-)\n") do
		if line == "" or line:sub(1, 1) == "#" then
			lines[#lines + 1] = line
		else
			local entry = line
			if normalize_domains then
				entry = api.normalize_domain(entry)
			end

			if not validator(entry) then
				return nil, entry .. "：" .. error_message
			end

			if not normalize_domains or not seen[entry] then
				lines[#lines + 1] = entry
			end
			if normalize_domains then
				seen[entry] = true
			end
		end
	end

	local result = table.concat(lines, "\n"):gsub("\n+$", "")
	return result ~= "" and (result .. "\n") or ""
end

local function add_file_editor(tab, option, filepath, help, validator, error_message, normalize_domains)
	local o = rules:taboption(tab, TextValue, option, "", help)
	o.rows = 15
	o.wrap = "off"
	o.cfgvalue = function(self, section)
		if self.map.save == false then return self:formvalue(section) end
		return fs.readfile(filepath) or ""
	end
	o.write = function(self, section, value)
		pending_files[filepath] = normalize_text(value)
	end
	o.remove = function(self, section)
		pending_files[filepath] = ""
	end
	if validator then
		o.validate = function(self, value)
			return validate_lines(value, validator, error_message, normalize_domains)
		end
	end
	return o
end

local domain_help = translate("域名，每行一项；# 开头为注释。")
local ip_help = translate("IP 或 CIDR，每行一项；# 开头为注释。")

add_file_editor("direct_list", "direct_host", rules_path .. "direct_host", domain_help,
	datatypes.hostname, translate("域名格式无效"), true)
add_file_editor("direct_list", "direct_ip", rules_path .. "direct_ip", ip_help,
	function(value) return datatypes.ipmask4(value) or datatypes.ipmask6(value) end,
	translate("IP/CIDR 格式无效"))

add_file_editor("proxy_list", "proxy_host", rules_path .. "proxy_host", domain_help,
	datatypes.hostname, translate("域名格式无效"), true)
add_file_editor("proxy_list", "proxy_ip", rules_path .. "proxy_ip", ip_help,
	function(value) return datatypes.ipmask4(value) or datatypes.ipmask6(value) end,
	translate("IP/CIDR 格式无效"))

add_file_editor("block_list", "block_host", rules_path .. "block_host", domain_help,
	datatypes.hostname, translate("域名格式无效"), true)
add_file_editor("block_list", "block_ip", rules_path .. "block_ip", ip_help,
	function(value) return datatypes.ipmask4(value) or datatypes.ipmask6(value) end,
	translate("IP/CIDR 格式无效"))

local lan_help = translate("每行一个 %s 直连网段；# 开头为注释。")
add_file_editor("lan_ip_list", "lanlist_ipv4", rules_path .. "lanlist_ipv4", lan_help:format("IPv4"),
	datatypes.ipmask4, translate("IPv4/CIDR 格式无效"))
add_file_editor("lan_ip_list", "lanlist_ipv6", rules_path .. "lanlist_ipv6", lan_help:format("IPv6"),
	datatypes.ipmask6, translate("IPv6/CIDR 格式无效"))

local hosts = rules:taboption("route_hosts", TextValue, "hosts", "",
	translate("每行一个 IP 及对应域名，以空格分隔。"))
hosts.rows = 15
hosts.wrap = "off"
hosts.cfgvalue = function(self, section)
	if self.map.save == false then return self:formvalue(section) end
	return fs.readfile("/etc/hosts") or ""
end
hosts.write = function(self, section, value)
	pending_files["/etc/hosts"] = normalize_text(value)
end
hosts.remove = function(self, section)
	pending_files["/etc/hosts"] = ""
end

local readonly_lists = {
	{ "gfw_list", translate("GFW 域名"), "gfwlist" },
	{ "chnroute_list", translate("中国列表（IPv4）"), "chnroute" },
	{ "chnroute6_list", translate("中国列表（IPv6）"), "chnroute6" }
}

local function format_rule_size(size)
	size = tonumber(size) or 0
	if size < 1024 then
		return string.format("%d B", size)
	elseif size < 1024 * 1024 then
		return string.format("%.1f KiB", size / 1024)
	end
	return string.format("%.1f MiB", size / (1024 * 1024))
end

for _, item in ipairs(readonly_lists) do
	local option, label, filename = item[1], item[2], item[3]
	local filepath = rules_path .. filename
	if fs.access(filepath) then
		rules:tab(option, label)
		local stat = fs.stat(filepath)
		local size = stat and format_rule_size(stat.size) or translate("未知")
		local modified = stat and stat.mtime and os.date("%Y-%m-%d %H:%M:%S", stat.mtime) or translate("未知")
		local list = rules:taboption(option, DummyValue, option, label)
		list.template = "passwall/rule/lazy_list"
		list.rule_name = filename
		list.rule_tab = option
		list.summary = string.format(translate("文件大小：%s；修改时间：%s"), size, modified)
	end
end

-- Rule update sources and schedule are saved with the global_rules section.
local o = rules:taboption("update", DynamicList, "gfwlist_url", translate("GFW 域名列表 URL"))
o:value("https://fastly.jsdelivr.net/gh/YW5vbnltb3Vz/domain-list-community@release/gfwlist.txt", "v2fly/domain-list-community")
o:value("https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt", "Loyalsoldier/v2ray-rules-dat")
o:value("https://fastly.jsdelivr.net/gh/Loukky/gfwlist-by-loukky/gfwlist.txt", "Loukky/gfwlist-by-loukky")
o:value("https://fastly.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt", "gfwlist/gfwlist")
o.default = "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"

o = rules:taboption("update", DynamicList, "chnroute_url", translate("中国 IPv4 列表 URL"))
o:value("https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt", "gaoyifan/china-operator-ip/china")
o:value("https://ispip.clang.cn/all_cn.txt", "Clang.CN")
o:value("https://ispip.clang.cn/all_cn_cidr.txt", "Clang.CN.CIDR")
o:value("https://fastly.jsdelivr.net/gh/soffchen/GeoIP2-CN@release/CN-ip-cidr.txt", "soffchen/GeoIP2-CN")
o:value("https://fastly.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt", "Hackl0us/GeoIP2-CN")

o.default = "https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt"

o = rules:taboption("update", DynamicList, "chnroute6_url", translate("中国 IPv6 列表 URL"))
o:value("https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt", "gaoyifan/china-operator-ip/china6")
o:value("https://ispip.clang.cn/all_cn_ipv6.txt", "Clang.CN.IPv6")

o.default = "https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt"

o = rules:taboption("update", Flag, "auto_update", translate("自动更新"))
o.default = 1
o.rmempty = false

o = rules:taboption("update", ListValue, "week_update", translate("更新日期"))
o:value(7, translate("每天"))
o:value(1, translate("每周一"))
o:value(2, translate("每周二"))
o:value(3, translate("每周三"))
o:value(4, translate("每周四"))
o:value(5, translate("每周五"))
o:value(6, translate("每周六"))
o:value(0, translate("每周日"))
o.default = 4
o:depends("auto_update", true)
o.rmempty = true

o = rules:taboption("update", ListValue, "time_update", translate("更新时间（小时）"))
for hour = 0, 23 do
	o:value(hour, hour .. ":00")
end
o.default = 6
for day = 0, 7 do
	o:depends({auto_update = "1", week_update = tostring(day)})
end
o.rmempty = true

local update_lists = {"gfwlist", "chnroute", "chnroute6"}
local update_defaults = {gfwlist="0", chnroute="1", chnroute6="1"}
o = rules:taboption("update", MultiValue, "update_selection", translate("更新列表"), translate("手动与定时共用；立即更新会保存本次勾选。"))
o:value("gfwlist", "GFW")
o:value("chnroute", "中国 IPv4")
o:value("chnroute6", "中国 IPv6")
o.rmempty = true
o.template = "passwall/rule/rule_version"
o.cfgvalue = function(self, section)
	local selected = {}
	for _, name in ipairs(update_lists) do
		if (m:get(section, name .. "_update") or update_defaults[name]) == "1" then selected[#selected + 1] = name end
	end
	return table.concat(selected, " ")
end
o.write = function(self, section, value)
	local selected = {}
	for name in (value or ""):gmatch("%S+") do selected[name] = true end
	for _, name in ipairs(update_lists) do m:set(section, name .. "_update", selected[name] and "1" or "0") end
end
o.remove = function(self, section) self:write(section, "") end

local shunt = m:section(TypedSection, "shunt_rules", translate("核心分流规则"),
	translate("供 Xray 核心分流节点使用，按列表顺序匹配。"))
shunt.template = "cbi/tblsection"
shunt.anonymous = false
shunt.addremove = true
shunt.sortable = true
shunt.extedit = api.url("shunt_rules", "%s")
function shunt.create(self, section)
	TypedSection.create(self, section)
	luci.http.redirect(self.extedit:format(section))
end
function shunt.remove(self, section)
	m.uci:foreach(appname, "nodes", function(node)
		if node.protocol == "_shunt" then
			m:del(node[".name"], section)
			m:del(node[".name"], section .. "_proxy_tag")
		end
	end)
	TypedSection.remove(self, section)
end
shunt:option(DummyValue, "remarks", translate("备注"))

m:append(Template(appname .. "/rule_list/js"))

-- Configuration signature changes restart the core; list-only edits hot-update.
m.apply_on_parse = false
function m.on_apply(self)
	sys.call("/etc/init.d/passwall reload > /dev/null 2>&1 &")
end

m:append(Template("passwall/style"))

return m
