#!/usr/bin/lua

require 'nixio'
require 'luci.sys'
local luci = luci
local ucic = luci.model.uci.cursor()
local datatypes = require "luci.cbi.datatypes"
local name = 'passwall'
local api = require ("luci.passwall.api")
local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local rule_path = "/usr/share/" .. name .. "/rules"
local task_tmp_dir
local rule_publish_dir
local staged_rules = {}
local update_failed = false
local gfwlist_update = 0
local chnroute_update = 0
local chnroute6_update = 0

-- match comments/title/whitelist/ip address/excluded_domain
local comment_pattern = "^[#!\\[@]+"
local ip_pattern = "^%d+%.%d+%.%d+%.%d+"
local domain_pattern = "([%w%-%_]+%.[%w%.%-%_]+)[%/%*]*"
local excluded_domain = {"apple.com","sina.cn","sina.com.cn","baidu.com","byr.cn","jlike.com","weibo.com","zhongsou.com","youdao.com","sogou.com","so.com","soso.com","aliyun.com","taobao.com","jd.com","qq.com","bing.com"}

local gfwlist_url = ucic:get(name, "@global_rules[0]", "gfwlist_url") or {"https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"}
local chnroute_url = ucic:get(name, "@global_rules[0]", "chnroute_url") or {"https://ispip.clang.cn/all_cn.txt"}
local chnroute6_url =  ucic:get(name, "@global_rules[0]", "chnroute6_url") or {"https://ispip.clang.cn/all_cn_ipv6.txt"}
if arg3 == "cron" then
	arg2 = nil
end

local log = function(...)
	if arg1 then
		if arg1 == "log" then
			api.log(...)
		elseif arg1 == "print" then
			local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
			print(result)
		end
	end
end

local function trim(value)
	return (value or ""):gsub("^%s*(.-)%s*$", "%1")
end

local function shell_quote(value)
	return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function read_file(path)
	local file = io.open(path, "rb")
	if not file then
		return nil
	end
	local content = file:read("*all")
	local ok = file:close()
	if not content or ok == nil then
		return nil
	end
	return content
end

local function write_file(path, content)
	local file = io.open(path, "wb")
	if not file then
		return false
	end
	local ok = file:write(content)
	local close_ok = file:close()
	return ok ~= nil and close_ok ~= nil
end

local function create_task_tmp_dir()
	local path = trim(luci.sys.exec("mktemp -d /tmp/passwall-rule-update.XXXXXX 2>/dev/null"))
	if path:match("^/tmp/passwall%-rule%-update%.[A-Za-z0-9]+$") and nixio.fs.stat(path, "type") == "dir" then
		return path
	end
	return nil
end

local function cleanup_task_tmp_dir()
	if task_tmp_dir and task_tmp_dir:match("^/tmp/passwall%-rule%-update%.[A-Za-z0-9]+$") then
		luci.sys.call("rm -rf " .. shell_quote(task_tmp_dir) .. " >/dev/null 2>&1")
	end
end

-- curl, returning both the process status and the final HTTP status.
local function curl(url, file)
	local args = {
		"-skfL", "-w %{http_code}", "--retry 3", "--connect-timeout 3"
	}
	if file then
		args[#args + 1] = "-o " .. file
	end
	local return_code, result = api.curl_logic(url, nil, args)
	return return_code, tonumber(result)
end

local function check_excluded_domain(value)
	for _, domain in ipairs(excluded_domain) do
		if value:find(domain) then
			return true
		end
	end
	return false
end

local function parse_rule_content(content, rule_type, exclude_domain)
	local entries = {}
	content = content:gsub("\r\n", "\n"):gsub("\r", "\n")
	for line in (content .. "\n"):gmatch("(.-)\n") do
		line = trim(line)
		if line ~= "" and not line:find(comment_pattern) then
			if rule_type == "domain" then
				if not line:find(ip_pattern) and not (exclude_domain and check_excluded_domain(line)) then
					local _, _, domain = line:find(domain_pattern)
					if domain and domain ~= "" then
						entries[domain] = true
					end
				end
			elseif rule_type == "ip4" then
				if datatypes.ipmask4(line) or datatypes.ip4addr(line) then
					entries[line] = true
				end
			elseif rule_type == "ip6" then
				if datatypes.ipmask6(line) or datatypes.ip6addr(line) then
					entries[line] = true
				end
			end
		end
	end
	local sorted = {}
	for entry in pairs(entries) do
		sorted[#sorted + 1] = entry
	end
	table.sort(sorted)
	return sorted
end

local function read_old_rule(rule_name)
	local path = rule_path .. "/" .. rule_name
	local content = read_file(path)
	if content == nil and nixio.fs.access(path) then
		return nil, false
	end
	return content, true
end

-- Download, parse, and stage one text rule. The staged filename is on the
-- init-script whitelist; publication and application happen after all fetches.
local function fetch_rule(rule_name, rule_type, urls, exclude_domain)
	if type(urls) == "string" then
		urls = {urls}
	end
	if type(urls) ~= "table" or #urls == 0 then
		log(rule_name .. " 没有可用下载地址，保留原规则文件。")
		return false
	end

	log(rule_name .. " 开始更新...")
	local entries = {}
	local failed = false
	for index, url in ipairs(urls) do
		local download_path = task_tmp_dir .. "/" .. rule_name .. "_download_" .. index
		local curl_status, http_status = curl(url, download_path)
		if curl_status ~= 0 or http_status ~= 200 then
			failed = true
			log(rule_name .. " 第" .. index .. "条规则下载失败（curl=" .. tostring(curl_status) .. "，HTTP=" .. tostring(http_status) .. "），保留原规则文件。")
		else
			local content = read_file(download_path)
			if not content or #content == 0 then
				failed = true
				log(rule_name .. " 第" .. index .. "条规则下载文件为空或读取失败，保留原规则文件。")
			else
				if rule_name == "gfwlist" then
					content = api.base64Decode(content)
				end
				local parsed = parse_rule_content(content, rule_type, exclude_domain)
				if #parsed == 0 then
					failed = true
					log(rule_name .. " 第" .. index .. "条规则解析结果为空，保留原规则文件。")
				else
					for _, entry in ipairs(parsed) do
						entries[entry] = true
					end
				end
			end
		end
	end

	if failed then
		return false
	end

	local sorted = {}
	for entry in pairs(entries) do
		sorted[#sorted + 1] = entry
	end
	table.sort(sorted)
	if #sorted == 0 then
		log(rule_name .. " 解析结果为空，保留原规则文件。")
		return false
	end

	local content = table.concat(sorted, "\n") .. "\n"
	local old_content, old_readable = read_old_rule(rule_name)
	if not old_readable then
		log(rule_name .. " 原规则文件读取失败，保留原文件。")
		return false
	end
	if old_content == content then
		log(rule_name .. " 版本一致，无需更新。")
		return true
	end

	local staged_path = rule_publish_dir .. "/" .. rule_name
	if not write_file(staged_path, content) then
		os.remove(staged_path)
		log(rule_name .. " 暂存文件写入失败，保留原规则文件。")
		return false
	end
	staged_rules[#staged_rules + 1] = { name = rule_name, count = #sorted }
	return true
end

local function fetch_gfwlist()
	return fetch_rule("gfwlist", "domain", gfwlist_url, true)
end

local function fetch_chnroute()
	return fetch_rule("chnroute", "ip4", chnroute_url, false)
end

local function fetch_chnroute6()
	return fetch_rule("chnroute6", "ip6", chnroute6_url, false)
end

local function run_task(label, callback)
	local ok, result = xpcall(callback, function(e)
		return tostring(e) .. "\n" .. debug.traceback()
	end)
	if not ok then
		update_failed = true
		log(label .. " 更新发生错误：" .. tostring(result))
		return false
	elseif result == false then
		update_failed = true
		return false
	end
	return true
end

local function apply_staged_rules()
	if #staged_rules == 0 then
		return false
	end
	local command = "/etc/init.d/" .. name .. " update_rules " .. shell_quote(rule_publish_dir) .. " >/dev/null 2>&1"
	local status = luci.sys.call(command)
	if status ~= 0 then
		log("规则文件发布或应用失败，原规则文件保持不变。")
		return false
	end
	for _, rule in ipairs(staged_rules) do
		log(rule.name .. " 更新成功，总规则数 " .. rule.count .. " 条。")
	end
	return true
end


if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "gfwlist" then
			gfwlist_update = 1
		end
		if w == "chnroute" then
			chnroute_update = 1
		end
		if w == "chnroute6" then
			chnroute6_update = 1
		end
	end)
else
	gfwlist_update = ucic:get_first(name, 'global_rules', "gfwlist_update", 0)
	chnroute_update = ucic:get_first(name, 'global_rules', "chnroute_update", 1)
	chnroute6_update = ucic:get_first(name, 'global_rules', "chnroute6_update", 1)
end

if (tonumber(gfwlist_update) or 0) == 0 and (tonumber(chnroute_update) or 0) == 0 and (tonumber(chnroute6_update) or 0) == 0 then
	os.exit(0)
end

log("开始更新规则...")
task_tmp_dir = create_task_tmp_dir()
if task_tmp_dir then
	rule_publish_dir = task_tmp_dir .. "/rules"
	nixio.fs.mkdir(rule_publish_dir)
	if nixio.fs.stat(rule_publish_dir, "type") ~= "dir" then
		log("规则暂存目录创建失败，跳过本次规则更新。")
		rule_publish_dir = nil
		update_failed = true
	end
else
	log("规则更新临时目录创建失败，跳过本次规则更新。")
	update_failed = true
end

if task_tmp_dir and rule_publish_dir then
	if tonumber(gfwlist_update) == 1 then
		run_task("gfwlist", fetch_gfwlist)
	end
	if tonumber(chnroute_update) == 1 then
		run_task("chnroute", fetch_chnroute)
	end
	if tonumber(chnroute6_update) == 1 then
		run_task("chnroute6", fetch_chnroute6)
	end
end

ucic:set(name, ucic:get_first(name, 'global_rules'), "gfwlist_update", gfwlist_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute_update", chnroute_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute6_update", chnroute6_update)
ucic:save(name)
luci.sys.call("uci commit " .. name)

if rule_publish_dir then
	if #staged_rules > 0 and not apply_staged_rules() then
		update_failed = true
	end
end
cleanup_task_tmp_dir()
if update_failed then
	log("规则更新结束，部分操作失败。")
	os.exit(1)
end
log("规则更新完毕...")
