-- Copyright (C) 2018-2020 L-WRT Team
-- Copyright (C) 2021-2023 xiaorouji

module("luci.controller.passwall", package.seeall)
local api = require "luci.passwall.api"
local appname = "passwall"			-- not available
local uci = luci.model.uci.cursor()		-- in funtion index()
local http = require "luci.http"
local util = require "luci.util"
local i18n = require "luci.i18n"

function index()
	if not nixio.fs.access("/etc/config/passwall") then
		if nixio.fs.access("/usr/share/passwall/0_default_config") then
			luci.sys.call('cp -f /usr/share/passwall/0_default_config /etc/config/passwall')
		else return end
	end
	local appname = "passwall"			-- global definitions not available
	entry({"admin", "services", appname}).dependent = true
	local e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), _("Pass Wall"), -1)
	e.dependent = true
	e.acl_depends = { "luci-app-passwall" }
	--[[ Client ]]
	entry({"admin", "services", appname, "settings"}, cbi(appname .. "/client/global"), _("Basic Settings"), 1).dependent = true
	entry({"admin", "services", appname, "node_list"}, cbi(appname .. "/client/node_list"), _("Node List"), 2).dependent = true
	entry({"admin", "services", appname, "node_subscribe"}, cbi(appname .. "/client/node_subscribe"), _("Node Subscribe"), 3).dependent = true
	entry({"admin", "services", appname, "other"}, cbi(appname .. "/client/other", {autoapply = true}), _("Other Settings"), 92).leaf = true
	if nixio.fs.access("/usr/sbin/haproxy") then
		entry({"admin", "services", appname, "haproxy"}, cbi(appname .. "/client/haproxy"), _("Load Balancing"), 93).leaf = true
	end
	entry({"admin", "services", appname, "app_update"}, cbi(appname .. "/client/app_update"), _("App Update"), 95).leaf = true
	entry({"admin", "services", appname, "rule"}, cbi(appname .. "/client/rule"), _("Rule Manage"), 96).leaf = true
	entry({"admin", "services", appname, "rule_list"}, cbi(appname .. "/client/rule_list"), _("Rule List"), 97).leaf = true
	entry({"admin", "services", appname, "node_subscribe_config"}, cbi(appname .. "/client/node_subscribe_config")).leaf = true
	entry({"admin", "services", appname, "node_config"}, cbi(appname .. "/client/node_config")).leaf = true
	entry({"admin", "services", appname, "shunt_rules"}, cbi(appname .. "/client/shunt_rules")).leaf = true
	entry({"admin", "services", appname, "acl"}, cbi(appname .. "/client/acl"), _("Access control"), 98).leaf = true
	entry({"admin", "services", appname, "acl_config"}, cbi(appname .. "/client/acl_config")).leaf = true
	entry({"admin", "services", appname, "log"}, form(appname .. "/client/log"), _("Watch Logs"), 999).leaf = true
	--[[ API ]]
	entry({"admin", "services", appname, "link_add_node"}, call("link_add_node")).leaf = true
	entry({"admin", "services", appname, "get_now_use_node"}, call("get_now_use_node")).leaf = true
	entry({"admin", "services", appname, "get_redir_log"}, call("get_redir_log")).leaf = true
	entry({"admin", "services", appname, "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", appname, "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", appname, "index_status"}, call("index_status")).leaf = true
	entry({"admin", "services", appname, "haproxy_status"}, call("haproxy_status")).leaf = true
	entry({"admin", "services", appname, "connect_status"}, call("connect_status")).leaf = true
	entry({"admin", "services", appname, "ping_node"}, call("ping_node")).leaf = true
	entry({"admin", "services", appname, "urltest_node"}, call("urltest_node")).leaf = true
	entry({"admin", "services", appname, "set_node"}, call("set_node")).leaf = true
	entry({"admin", "services", appname, "copy_node"}, call("copy_node")).leaf = true
	entry({"admin", "services", appname, "clear_all_nodes"}, call("clear_all_nodes")).leaf = true
	entry({"admin", "services", appname, "delete_select_nodes"}, call("delete_select_nodes")).leaf = true
	entry({"admin", "services", appname, "update_rules"}, call("update_rules")).leaf = true

	--[[Components update]]
	entry({"admin", "services", appname, "check_passwall"}, call("app_check")).leaf = true
	local coms = require "luci.passwall.com"
	local com
	for com, _ in pairs(coms) do
		entry({"admin", "services", appname, "check_" .. com}, call("com_check", com)).leaf = true
		entry({"admin", "services", appname, "update_" .. com}, call("com_update", com)).leaf = true
	end
end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or {code = 1})
end

function link_add_node()
	local lfile = "/tmp/links.conf"
	local link = luci.http.formvalue("link")
	luci.sys.call('echo \'' .. link .. '\' > ' .. lfile)
	luci.sys.call("lua /usr/share/passwall/subscribe.lua add log")
end

function get_now_use_node()
	local path = "/tmp/etc/passwall/acl/default"
	local e = {}
	local data, code, msg = nixio.fs.readfile(path .. "/TCP.id")
	if data then
		e["TCP"] = util.trim(data)
	end
	local data, code, msg = nixio.fs.readfile(path .. "/UDP.id")
	if data then
		e["UDP"] = util.trim(data)
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_redir_log()
	local name = luci.http.formvalue("name")
	local proto = luci.http.formvalue("proto")
	local path = "/tmp/etc/passwall/acl/" .. name
	proto = proto:upper()
	if proto == "UDP" and (uci:get(appname, "@global[0]", "udp_node") or "nil") == "tcp" and not nixio.fs.access(path .. "/" .. proto .. ".log") then
		proto = "TCP"
	end
	if nixio.fs.access(path .. "/" .. proto .. ".log") then
		local content = luci.sys.exec("cat ".. path .. "/" .. proto .. ".log")
		content = content:gsub("\n", "<br />")
		luci.http.write(content)
	else
		luci.http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_log()
	-- luci.sys.exec("[ -f /tmp/log/passwall.log ] && sed '1!G;h;$!d' /tmp/log/passwall.log > /tmp/log/passwall_show.log")
	luci.http.write(luci.sys.exec("[ -f '/tmp/log/passwall.log' ] && cat /tmp/log/passwall.log"))
end

function clear_log()
	luci.sys.call("echo '' > /tmp/log/passwall.log")
end

function index_status()
	local e = {}
	e.dns_mode_status = luci.sys.call("netstat -apn | grep ':15353 ' >/dev/null") == 0
	e.haproxy_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v grep | grep '%s/bin/' | grep haproxy >/dev/null", appname)) == 0
	e["tcp_node_status"] = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep 'default' | grep 'TCP' >/dev/null") == 0

	if (uci:get(appname, "@global[0]", "udp_node") or "nil") == "tcp" then
		e["udp_node_status"] = e["tcp_node_status"]
	else
		e["udp_node_status"] = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep 'default' | grep 'UDP' >/dev/null") == 0
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function haproxy_status()
	local e = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v grep | grep '%s/bin/' | grep haproxy >/dev/null", appname)) == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function connect_status()
	local e = {}
	e.use_time = ""
	local url = luci.http.formvalue("url")
	local baidu = string.find(url, "baidu")
	local enabled = uci:get(appname, "@global[0]", "enabled") or "0"
	local chn_list = uci:get(appname, "@global[0]", "chn_list") or "direct"
	local gfw_list = uci:get(appname, "@global[0]", "use_gfw_list") or "1"
	local proxy_mode = uci:get(appname, "@global[0]", "tcp_proxy_mode") or "proxy"
	local socks_port = uci:get(appname, "@global[0]", "tcp_node_socks_port") or "1070"
	local local_proxy = uci:get(appname, "@global[0]", "localhost_proxy") or "1"
	if enabled == "1" and local_proxy == "0" then
		if (chn_list == "proxy" and gfw_list == "0" and proxy_mode ~= "proxy" and baidu ~= nil) or (chn_list == "0" and gfw_list == "0" and proxy_mode == "proxy") then
		-- 中国列表+百度 or 全局
			url = "-x socks5h://127.0.0.1:" .. socks_port .. " " .. url
		elseif baidu == nil then
		-- 其他代理模式+百度以外网站
			url = "-x socks5h://127.0.0.1:" .. socks_port .. " " .. url
		end
	end
	local result = luci.sys.exec('curl --connect-timeout 3 -o /dev/null -I -sk -w "%{http_code}:%{time_appconnect}" ' .. url)
	local code = tonumber(luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $1}'") or "0")
	if code ~= 0 then
		local use_time = luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $2}'")
		if use_time:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
		e.ping_type = "curl"
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
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
	local result = luci.sys.exec(string.format("/usr/share/passwall/test.sh url_test_node %s %s", id, "urltest_node"))
	local code = tonumber(luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $1}'") or "0")
	if code ~= 0 then
		local use_time = luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $2}'")
		if use_time:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function set_node()
	local protocol = luci.http.formvalue("protocol")
	local section = luci.http.formvalue("section")
	uci:set(appname, "@global[0]", protocol .. "_node", section)
	uci:commit(appname)
	luci.sys.call("/etc/init.d/passwall restart > /dev/null 2>&1 &")
	luci.http.redirect(api.url("log"))
end

function copy_node()
	local section = luci.http.formvalue("section")
	local uuid = api.gen_short_uuid()
	uci:section(appname, "nodes", uuid)
	for k, v in pairs(uci:get_all(appname, section)) do
		local filter = k:find("%.")
		if filter and filter == 1 then
		else
			xpcall(function()
				uci:set(appname, uuid, k, v)
			end,
			function(e)
			end)
		end
	end
	uci:delete(appname, uuid, "add_from")
	uci:set(appname, uuid, "add_mode", 1)
	uci:commit(appname)
	luci.http.redirect(api.url("node_config", uuid))
end

function clear_all_nodes()
	uci:set(appname, '@global[0]', "enabled", "0")
	uci:set(appname, '@global[0]', "tcp_node", "nil")
	uci:set(appname, '@global[0]', "udp_node", "nil")
	uci:foreach(appname, "haproxy_config", function(t)
		uci:delete(appname, t[".name"])
	end)
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
		uci:foreach(appname, "haproxy_config", function(t)
			if t["lbss"] == w then
				uci:delete(appname, t[".name"])
			end
		end)
		uci:delete(appname, w)
	end)
	uci:commit(appname)
	luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
end

function update_rules()
	local update = luci.http.formvalue("update")
	luci.sys.call("lua /usr/share/passwall/rule_update.lua log '" .. update .. "' > /dev/null 2>&1 &")
	http_write_json()
end

function app_check()
	local json = api.to_check_self()
	http_write_json(json)
end

function com_check(comname)
	local json = api.to_check("",comname)
	http_write_json(json)
end

function com_update(comname)
	local json = nil
	local task = http.formvalue("task")
	if task == "extract" then
		json = api.to_extract(comname, http.formvalue("file"), http.formvalue("subfix"))
	elseif task == "move" then
		json = api.to_move(comname, http.formvalue("file"))
	else
		json = api.to_download(comname, http.formvalue("url"), http.formvalue("size"))
	end

	http_write_json(json)
end
