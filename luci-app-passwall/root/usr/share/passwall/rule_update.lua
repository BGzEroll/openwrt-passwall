#!/usr/bin/lua

local nixio = require "nixio"
local sys = require "luci.sys"
local ucic = require("luci.model.uci").cursor()
local datatypes = require "luci.cbi.datatypes"
local name = "passwall"
local api = require "luci.passwall.api"
local fs, json = api.fs, api.jsonc
local state_file = "/var/run/passwall/rule-update.json"

local function job_read()
	return json.parse(fs.readfile(state_file) or "") or {state="idle", message="尚未更新"}
end

local function job_write(state, message, fresh)
	local job = fresh and {started_at=os.time()} or job_read()
	job.state, job.message = state, message
	if state == "done" or state == "failed" then job.finished_at = os.time() end
	assert(fs.writefile(state_file .. ".next", json.stringify(job)), "更新状态写入失败")
	assert(fs.rename(state_file .. ".next", state_file), "更新状态发布失败")
	return job
end

local function active(job)
	return job.state == "downloading" or job.state == "applying"
end

local operation = arg[1]
if operation == "prepare" then
	if arg[2] then
		local selected, count = {}, 0
		for entry in arg[2]:gmatch("[^,]+") do
			assert(entry == "gfwlist" or entry == "chnroute" or entry == "chnroute6", "无效的更新列表")
			selected[entry], count = true, count + 1
		end
		assert(count > 0, "请选择更新列表")
		local section = assert(ucic:get_first(name, "global_rules"))
		for _, entry in ipairs({"gfwlist", "chnroute", "chnroute6"}) do
			assert(ucic:set(name, section, entry .. "_update", selected[entry] and "1" or "0"))
		end
		assert(ucic:commit(name), "更新选择保存失败")
	end
	print(json.stringify(job_write("downloading", "准备下载", true)))
	os.exit(0)
elseif operation == "status" or operation == "status-idle" or operation == "busy" or operation == "failed" then
	local job = job_read()
	if (operation == "status-idle" or operation == "failed") and active(job) then
		local detail = fs.readfile("/var/run/passwall/rule-update.error") or ""
		api.log_debug("规则", detail)
		api.log("规则", detail:match("^[^\r\n]+") or "更新任务已中断")
		job = job_write("failed", "更新任务异常结束，详情见日志")
	elseif operation == "busy" and not active(job) then
		job = {state="downloading", message="更新任务正在启动"}
	end
	print(json.stringify(job))
	os.exit(0)
end

if os.getenv("PASSWALL_RULE_UPDATE_LOCKED") ~= "1" then
	io.stderr:write("请通过 rule_update.sh 运行规则更新\n")
	os.exit(2)
end

local rule_path = "/usr/share/" .. name .. "/rules"
local task_tmp_dir, rule_publish_dir
local staged_rules = {}
local update_failed = false

-- match comments/title/whitelist/ip address/excluded_domain
local comment_pattern = "^[#!\\[@]+"
local ip_pattern = "^%d+%.%d+%.%d+%.%d+"
local domain_pattern = "([%w%-%_]+%.[%w%.%-%_]+)[%/%*]*"
local excluded_domain = {"apple.com","sina.cn","sina.com.cn","baidu.com","byr.cn","jlike.com","weibo.com","zhongsou.com","youdao.com","sogou.com","so.com","soso.com","aliyun.com","taobao.com","jd.com","qq.com","bing.com"}

local rules = {
	{
		name="gfwlist", label="GFW 域名", type="domain", exclude_domain=true, decode=true, default=0,
		urls=ucic:get(name, "@global_rules[0]", "gfwlist_url") or {"https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"}
	},
	{
		name="chnroute", label="中国 IPv4", type="ip4", default=1,
		urls=ucic:get(name, "@global_rules[0]", "chnroute_url") or {"https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt"}
	},
	{
		name="chnroute6", label="中国 IPv6", type="ip6", default=1,
		urls=ucic:get(name, "@global_rules[0]", "chnroute6_url") or {"https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt"}
	}
}

local selected = {}
if operation then
	for entry in operation:gmatch("[^,]+") do
		if entry == "gfwlist" or entry == "chnroute" or entry == "chnroute6" then
			selected[entry] = true
		end
	end
else
	for _, rule in ipairs(rules) do
		if tonumber(ucic:get_first(name, "global_rules", rule.name .. "_update", rule.default)) == 1 then
			selected[rule.name] = true
		end
	end
end

local function log(...)
	api.log("规则", ...)
end

local function shell_quote(value)
	return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function create_task_tmp_dir()
	local path = (sys.exec("mktemp -d /tmp/passwall-rule-update.XXXXXX 2>/dev/null") or ""):match("^%s*(.-)%s*$")
	if path:match("^/tmp/passwall%-rule%-update%.[A-Za-z0-9]+$") and nixio.fs.stat(path, "type") == "dir" then
		return path
	end
end

-- curl_logic retains the proxy-first fallback; curl's retry policy applies to
-- both the SOCKS attempt and the direct fallback.
local function curl(url, file)
	local args = {"-skfL", "-w %{http_code}", "--retry 3", "--connect-timeout 3", "--max-time 120", "-o " .. file}
	local return_code, result = api.curl_logic(url, nil, args)
	return return_code, tonumber(result)
end

local function check_excluded_domain(value)
	for _, domain in ipairs(excluded_domain) do
		if api.domain_matches(value, domain) then return true end
	end
	return false
end

local function parse_rule_content(content, rule_type, exclude_domain)
	local entries = {}
	content = content:gsub("\r\n", "\n"):gsub("\r", "\n")
	for line in (content .. "\n"):gmatch("(.-)\n") do
		line = line:gsub("^%s*(.-)%s*$", "%1")
		if line ~= "" and not line:find(comment_pattern) then
			if rule_type == "domain" then
				if not line:find(ip_pattern) then
					local _, _, domain = line:find(domain_pattern)
					if domain then domain = api.normalize_domain(domain) end
					if domain and domain ~= "" and not (exclude_domain and check_excluded_domain(domain)) then
						entries[domain] = true
					end
				end
			elseif rule_type == "ip4" then
				if datatypes.ipmask4(line) or datatypes.ip4addr(line) then entries[line] = true end
			elseif rule_type == "ip6" then
				if datatypes.ipmask6(line) or datatypes.ip6addr(line) then entries[line] = true end
			end
		end
	end
	return entries
end

local function read_old_rule(rule_name)
	local path = rule_path .. "/" .. rule_name
	local content = fs.readfile(path)
	if content == nil and nixio.fs.access(path) then return nil, false end
	return content, true
end

-- Stage a list only after every configured source downloads and parses.
local function fetch_rule(rule)
	local urls = rule.urls
	if type(urls) == "string" then urls = {urls} end
	if type(urls) ~= "table" or #urls == 0 then
		log(rule.name .. " 没有可用下载地址，保留原规则文件。")
		return false
	end

	job_write("downloading", "下载：" .. rule.label)
	api.log_debug("规则", rule.name .. "：开始下载")
	local entries, failed = {}, false
	for index, url in ipairs(urls) do
		local download_path = task_tmp_dir .. "/" .. rule.name .. "_download_" .. index
		local curl_status, http_status = curl(url, download_path)
		if curl_status ~= 0 or http_status ~= 200 then
			failed = true
			log(rule.name .. " 第" .. index .. "条规则下载失败（curl=" .. tostring(curl_status) .. "，HTTP=" .. tostring(http_status) .. "），保留原规则文件。")
		else
			local content = fs.readfile(download_path)
			if not content or #content == 0 then
				failed = true
				log(rule.name .. " 第" .. index .. "条规则下载文件为空或读取失败，保留原规则文件。")
			else
				if rule.decode then content = api.base64Decode(content) end
				local parsed = parse_rule_content(content, rule.type, rule.exclude_domain)
				if not next(parsed) then
					failed = true
					log(rule.name .. " 第" .. index .. "条规则解析结果为空，保留原规则文件。")
				else
					for entry in pairs(parsed) do entries[entry] = true end
				end
			end
		end
	end
	if failed then return false end

	local sorted = {}
	for entry in pairs(entries) do sorted[#sorted + 1] = entry end
	table.sort(sorted)
	local content = table.concat(sorted, "\n") .. "\n"
	local old_content, old_readable = read_old_rule(rule.name)
	if not old_readable then
		log(rule.name .. " 原规则文件读取失败，保留原文件。")
		return false
	end
	if old_content == content then
		api.log_debug("规则", rule.name .. "：内容未变化")
		return true
	end

	local staged_path = rule_publish_dir .. "/" .. rule.name
	if not fs.writefile(staged_path, content) then
		os.remove(staged_path)
		log(rule.name .. " 暂存文件写入失败，保留原规则文件。")
		return false
	end
	staged_rules[#staged_rules + 1] = {name=rule.name, label=rule.label, count=#sorted}
	return true
end

local function run_task(rule)
	local ok, result = xpcall(function() return fetch_rule(rule) end, function(err)
		api.log_debug("规则", debug.traceback())
		return tostring(err)
	end)
	if not ok then
		update_failed = true
		log(rule.name .. " 更新发生错误：" .. tostring(result))
	elseif result == false then
		update_failed = true
	end
end

local function apply_staged_rules()
	job_write("applying", "正在应用规则")
	local command = "/etc/init.d/" .. name .. " update_rules " .. shell_quote(rule_publish_dir) .. " >/dev/null 2>&1"
	if sys.call(command) ~= 0 then
		log("规则文件发布或应用失败，原规则文件保持不变。")
		return false
	end
	for _, rule in ipairs(staged_rules) do
		log("更新完成：" .. rule.label .. " " .. rule.count .. " 条")
	end
	return true
end

if not next(selected) then
	job_write("done", "没有选择需要更新的列表")
	os.exit(0)
end

job_write("downloading", "开始下载")
log("开始更新")
task_tmp_dir = create_task_tmp_dir()
if task_tmp_dir then
	rule_publish_dir = task_tmp_dir .. "/rules"
	if not fs.mkdir(rule_publish_dir) then
		log("规则暂存目录创建失败，跳过本次规则更新。")
		rule_publish_dir = nil
		update_failed = true
	end
else
	log("规则更新临时目录创建失败，跳过本次规则更新。")
	update_failed = true
end

if task_tmp_dir and rule_publish_dir then
	for _, rule in ipairs(rules) do
		if selected[rule.name] then run_task(rule) end
	end
end

if rule_publish_dir and #staged_rules > 0 and not apply_staged_rules() then
	update_failed = true
end
if task_tmp_dir then fs.remover(task_tmp_dir) end
if update_failed then
	job_write("failed", "更新未全部完成；失败的列表保留原文件")
	log("更新未全部完成；失败的列表保留原文件")
	os.exit(1)
end
job_write("done", "更新完成")
log("更新完成")
