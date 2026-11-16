local api = require "luci.passwall.api"
local node_refs = require "luci.passwall.node_refs"
local appname = "passwall"

m = Map(appname)

-- [[ Node List ]]--
s = m:section(TypedSection, "nodes")
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
s.extedit = api.url("node_config", "%s")
s.template_addremove = appname .. "/node_list/nodes_actions"

function s.create(e, t)
	local uuid = api.gen_short_uuid()
	TypedSection.create(e, uuid)
	e.map:set(uuid, "type", "Xray")
	luci.http.redirect(api.url("node_config", uuid))
end

function s.remove(e, t)
	local ok, err = node_refs.check_delete(m.uci, {t})
	if not ok then
		m.message = err
		return
	end

	TypedSection.remove(e, t)
	if m:get("@global[0]", "tcp_node") == t then
		m:set("@global[0]", "tcp_node", "nil")
	end
	if m:get("@global[0]", "udp_node") == t then
		m:set("@global[0]", "udp_node", "nil")
	end
end

s.sortable = true

local function add_cell(option_name, title, width)
	local option = s:option(DummyValue, option_name, title)
	option.template = appname .. "/node_list/node_cell"
	option.width = width
	option.cfgvalue = function(self, section)
		return self.map:get(section, option_name) or ""
	end
	return option
end

add_cell("remarks", translate("节点"))
add_cell("ping", "连通性", "6em")
add_cell("tcping", "TCP 延迟", "7em")
add_cell("_url_test", translate("代理延迟"), "6em")

m:append(Template(appname .. "/node_list/node_list"))

m:append(Template("passwall/style"))

return m
