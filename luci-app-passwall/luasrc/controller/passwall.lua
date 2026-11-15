-- Copyright (C) 2018-2020 L-WRT Team
-- Copyright (C) 2021-2023 xiaorouji

module("luci.controller.passwall", package.seeall)
local api = require "luci.passwall.api"
local appname = "passwall"			-- not available
local uci = luci.model.uci.cursor()		-- in funtion index()
local http = require "luci.http"
local util = require "luci.util"

function index()
	if not nixio.fs.access("/etc/config/passwall") then
		if nixio.fs.access("/usr/share/passwall/0_default_config") then
			luci.sys.call('cp -f /usr/share/passwall/0_default_config /etc/config/passwall')
		else return end
	end
	local appname = "passwall"			-- global definitions not available
	entry({"admin", "services", appname}).dependent = true
	local e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), _("Passwall"), -1)
	e.dependent = true
	e.acl_depends = { "luci-app-passwall" }
	--[[ Client ]]
	entry({"admin", "services", appname, "settings"}, cbi(appname .. "/client/global"), _("基础设置"), 1).dependent = true
	entry({"admin", "services", appname, "node_list"}, cbi(appname .. "/client/node_list"), _("节点"), 2).dependent = true
	entry({"admin", "services", appname, "other"}, cbi(appname .. "/client/other", {autoapply = true}), _("高级设置"), 5).leaf = true
	entry({"admin", "services", appname, "rule"}, cbi(appname .. "/client/rule"), _("规则"), 4).leaf = true
	entry({"admin", "services", appname, "node_config"}, cbi(appname .. "/client/node_config")).leaf = true
	entry({"admin", "services", appname, "shunt_rules"}, cbi(appname .. "/client/shunt_rules")).leaf = true
	entry({"admin", "services", appname, "acl"}, cbi(appname .. "/client/acl"), _("设备策略"), 3).leaf = true
	entry({"admin", "services", appname, "acl_config"}, cbi(appname .. "/client/acl_config")).leaf = true
	entry({"admin", "services", appname, "log"}, cbi(appname .. "/client/log"), _("日志"), 6).leaf = true
	--[[ API ]]
	entry({"admin", "services", appname, "get_redir_log"}, call("get_redir_log")).leaf = true
	entry({"admin", "services", appname, "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", appname, "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", appname, "index_status"}, call("index_status")).leaf = true
	entry({"admin", "services", appname, "ping_node"}, call("ping_node")).leaf = true
	entry({"admin", "services", appname, "urltest_node"}, call("urltest_node")).leaf = true
	entry({"admin", "services", appname, "copy_node"}, call("copy_node")).leaf = true
	entry({"admin", "services", appname, "clear_all_nodes"}, call("clear_all_nodes")).leaf = true
	entry({"admin", "services", appname, "delete_select_nodes"}, call("delete_select_nodes")).leaf = true
	entry({"admin", "services", appname, "update_rules"}, call("update_rules")).leaf = true
	entry({"admin", "services", appname, "get_rule_update_status"}, call("get_rule_update_status")).leaf = true
	entry({"admin", "services", appname, "get_rule_list"}, call("get_rule_list")).leaf = true

end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or {code = 1})
end

function get_redir_log()
	local proto = (http.formvalue("proto") or ""):upper()
	if proto ~= "TCP" and proto ~= "UDP" then http.status(400, "Invalid protocol"); return end
	local path = "/tmp/etc/passwall/acl/default/"
	if proto == "UDP" and uci:get(appname, "@global[0]", "udp_node") == "tcp" and not nixio.fs.access(path .. "UDP.log") then proto = "TCP" end
	http.prepare_content("text/plain; charset=utf-8")
	local content = nixio.fs.readfile(path .. proto .. ".log")
	if content then http.write(content) else http.status(404, "Log disabled"); http.write("未启用此核心的日志") end
end

function get_log()
	http.prepare_content("text/plain; charset=utf-8")
	http.write(nixio.fs.readfile(api.LOG_FILE) or "")
end

function clear_log()
	if not nixio.fs.writefile(api.LOG_FILE, "") then http.status(500, "Cannot clear log"); return end
	http_write_json()
end

function index_status()
	local output = luci.sys.exec("lua /usr/share/passwall/process.lua status")
	local data = api.jsonc.parse(output) or {service_status = "degraded", service_detail = "无法读取运行状态"}
	http.prepare_content("application/json")
	http.write_json(data)
end

function ping_node()
	local index = luci.http.formvalue("index")
	local address = luci.http.formvalue("address")
	local port = luci.http.formvalue("port")
	local type = luci.http.formvalue("type") or "icmp"
	local e = {}
	e.index = index
	if type == "tcping" and luci.sys.exec("echo -n $(command -v tcping)") ~= "" then
		if api.is_ipv6(address) then
			address = api.get_ipv6_only(address)
		end
		e.ping = luci.sys.exec(string.format("echo -n $(tcping -q -c 1 -i 1 -t 2 -p %s %s 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null", port, address))
	else
		e.ping = luci.sys.exec("echo -n $(ping -c 1 -W 1 %q 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null" % address)
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function urltest_node()
	local index = luci.http.formvalue("index")
	local id = luci.http.formvalue("id")
	local e = {}
	e.index = index
	if not id or uci:get(appname, id) ~= "nodes" then http.status(400, "Invalid node"); return end
	local result = luci.sys.exec("/usr/share/passwall/test.sh url_test_node " .. util.shellquote(id))
	local code, seconds = result:match("(%d+):([%d.]+)")
	if tonumber(code) and tonumber(code) > 0 and tonumber(seconds) then
		e.use_time = string.format("%.0f", tonumber(seconds) * 1000)
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function copy_node()
	local section = luci.http.formvalue("section")
	local node = uci:get_all(appname, section or "")
	if not node or node[".type"] ~= "nodes" then http.status(400, "Invalid node"); return end
	local uuid = api.gen_short_uuid()
	uci:section(appname, "nodes", uuid)
	for key, value in pairs(node) do
		if key:sub(1, 1) ~= "." then uci:set(appname, uuid, key, value) end
	end
	uci:commit(appname)
	luci.http.redirect(api.url("node_config", uuid))
end

function clear_all_nodes()
	uci:set(appname, '@global[0]', "enabled", "0")
	uci:set(appname, '@global[0]', "tcp_node", "nil")
	uci:set(appname, '@global[0]', "udp_node", "nil")
	uci:foreach(appname, "nodes", function(node)
		uci:delete(appname, node['.name'])
	end)

	uci:commit(appname)
	luci.sys.call("/etc/init.d/" .. appname .. " stop")
end

function delete_select_nodes()
	local ids = luci.http.formvalue("ids")
	string.gsub(ids, '[^' .. "," .. ']+', function(w)
		if (uci:get(appname, "@global[0]", "tcp_node") or "nil") == w then
			uci:set(appname, '@global[0]', "tcp_node", "nil")
		end
		if (uci:get(appname, "@global[0]", "udp_node") or "nil") == w then
			uci:set(appname, '@global[0]', "udp_node", "nil")
		end
		uci:delete(appname, w)
	end)
	uci:commit(appname)
	luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
end

function update_rules()
	local allowed = {gfwlist = true, chnroute = true, chnroute6 = true}
	local selected = {}
	for name in (http.formvalue("update") or ""):gmatch("[^,]+") do
		if not allowed[name] then
			http.status(400, "Unsupported rule list")
			return
		end
		selected[#selected + 1] = name
	end
	if #selected == 0 then
		http.status(400, "No rule list selected")
		return
	end
	local code, output = api.exec_call("/usr/share/passwall/rule_update.sh start " .. util.shellquote(table.concat(selected, ",")))
	local status = api.jsonc.parse(output)
	if code == 75 then
		http.status(409, "Rule update is running")
	elseif code ~= 0 or not status then
		http.status(500, "Cannot start rule update")
		status = {state="failed", message="无法启动更新任务"}
	end
	http_write_json(status)
end

function get_rule_update_status()
	local output = luci.sys.exec("/usr/share/passwall/rule_update.sh status")
	local status = api.jsonc.parse(output)
	if not status then http.status(500, "Cannot read rule update status") end
	http.header("Cache-Control", "no-store")
	http_write_json(status or {state="failed", message="无法读取更新状态"})
end

function get_rule_list()
	local name = http.formvalue("name")
	if name ~= "gfwlist" and name ~= "chnroute" and name ~= "chnroute6" then
		http.status(400, "Unsupported rule list"); return
	end
	local path = "/usr/share/passwall/rules/" .. name
	local content = nixio.fs.readfile(path)
	if not content then http.status(404, "Rule list unavailable"); return end
	local _, count = content:gsub("\n", "")
	if content ~= "" and content:sub(-1) ~= "\n" then count = count + 1 end
	http.header("Cache-Control", "no-store")
	http_write_json({name=name, content=content, count=count, updated_at=(nixio.fs.stat(path) or {}).mtime})
end
