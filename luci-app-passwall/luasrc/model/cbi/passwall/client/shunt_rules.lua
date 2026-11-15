local api = require "luci.passwall.api"
local appname = "passwall"
local datatypes = api.datatypes

m = Map(appname, "Xray " .. translate("分流规则"))
m.redirect = api.url()

s = m:section(NamedSection, arg[1], "shunt_rules", "")
s.addremove = false
s.dynamic = false

remarks = s:option(Value, "remarks", translate("备注"))
remarks.default = arg[1]
remarks.rmempty = false

protocol = s:option(MultiValue, "protocol", translate("协议"))
protocol:value("http")
protocol:value("tls")
protocol:value("bittorrent")

o = s:option(MultiValue, "inbound", translate("入站标签"))
o:value("tproxy", translate("透明代理"))
o:value("socks", "SOCKS")

network = s:option(ListValue, "network", translate("网络"))
network:value("tcp,udp", "TCP、UDP")
network:value("tcp", "TCP")
network:value("udp", "UDP")

source = s:option(DynamicList, "source", translate("来源 IP"))
source.description = translate("仅支持 IPv4 地址，例如 192.168.113.10。")
source.cast = "string"
source.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
source.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("IP 格式无效，请检查。"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
end

source.write = dynamicList_write

port = s:option(Value, "port", translate("端口"))

domain_list = s:option(TextValue, "domain_list", translate("域名规则"))
domain_list.rows = 10
domain_list.wrap = "off"
domain_list.validate = function(self, value)
	local hosts= {}
	value = value:gsub("^%s+", ""):gsub("%s+$","\n"):gsub("\r\n","\n"):gsub("[ \t]*\n[ \t]*", "\n")
	string.gsub(value, "[^\r\n]+", function(w) table.insert(hosts, w) end)
	for index, host in ipairs(hosts) do
		local flag = 1
		local tmp_host = host
		if not host:find("#") and host:find("%s") then
		elseif host:find("regexp:") and host:find("regexp:") == 1 then
			flag = 0
		elseif host:find("domain:.") and host:find("domain:.") == 1 then
			tmp_host = host:gsub("domain:", "")
		elseif host:find("full:.") and host:find("full:.") == 1 then
			tmp_host = host:gsub("full:", "")
		elseif host:find("#") and host:find("#") == 1 then
			flag = 0
		end
		if flag == 1 then
			if not datatypes.hostname(tmp_host) then
				return nil, translate("无效域名：") .. tmp_host
			end
		end
	end
	return value
end
domain_list.description = translate("普通规则按域名片段匹配；domain: 匹配域名及子域，full: 匹配完整域名，regexp: 使用正则；# 开头的行为注释。")
ip_list = s:option(TextValue, "ip_list", "IP 规则")
ip_list.rows = 10
ip_list.wrap = "off"
ip_list.validate = function(self, value)
	local ipmasks= {}
	value = value:gsub("^%s+", ""):gsub("%s+$","\n"):gsub("\r\n","\n"):gsub("[ \t]*\n[ \t]*", "\n")
	string.gsub(value, "[^\r\n]+", function(w) table.insert(ipmasks, w) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask:find("#") and ipmask:find("#") == 1 then
		else
			if not (datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask)) then
				return nil, translate("无效 IP 地址：") .. ipmask
			end
		end
	end
	return value
end
ip_list.description = translate("支持 IPv4/IPv6 地址和 CIDR；# 开头的行为注释。")

return m
