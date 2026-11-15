local M = {}

local appname = "passwall"
local special_values = {
	["_direct"] = true,
	["_blackhole"] = true,
	["_default"] = true,
	["nil"] = true,
	["tcp"] = true
}

local function is_reference(value, targets)
	return type(value) == "string" and value ~= "" and not special_values[value] and targets[value] == true
end

local function visit_values(value, callback)
	if type(value) == "table" then
		for _, item in ipairs(value) do callback(item) end
	elseif type(value) == "string" then
		for item in value:gmatch("%S+") do callback(item) end
	end
end

local function node_label(node)
	local remarks = node.remarks
	if type(remarks) == "string" and remarks ~= "" then
		return remarks .. "（" .. tostring(node[".name"]) .. "）"
	end
	return tostring(node[".name"])
end

function M.parse_ids(value)
	if type(value) ~= "string" or value == "" then
		return nil, "请先选择要删除的节点"
	end

	local ids, seen, start = {}, {}, 1
	while true do
		local comma = value:find(",", start, true)
		local id = value:sub(start, comma and comma - 1 or #value)
		if id == "" or id:match("%s") then
			return nil, "节点列表格式无效"
		end
		if not seen[id] then
			seen[id] = true
			ids[#ids + 1] = id
		end
		if not comma then break end
		start = comma + 1
	end

	if #ids == 0 then return nil, "请先选择要删除的节点" end
	return ids
end

function M.check_delete(uci, ids)
	if type(ids) ~= "table" or #ids == 0 then
		return nil, "请先选择要删除的节点"
	end

	local targets = {}
	for _, id in ipairs(ids) do
		if type(id) ~= "string" or id == "" or uci:get(appname, id) ~= "nodes" then
			return nil, "只能删除有效的节点配置"
		end
		targets[id] = true
	end

	local rules = {}
	uci:foreach(appname, "shunt_rules", function(rule)
		rules[#rules + 1] = { id = rule[".name"], label = rule.remarks }
	end)

	local blockers = {}
	local function add_blocker(source, field, target)
		blockers[#blockers + 1] = {
			source = source[".name"],
			source_label = node_label(source),
			field = field,
			target = target
		}
	end
	local function check_field(source, value, field)
		if is_reference(value, targets) then add_blocker(source, field, value) end
	end

	uci:foreach(appname, "nodes", function(node)
		if not targets[node[".name"]] then
			if node.protocol == "_balancing" then
				visit_values(node.balancing_node, function(value)
					check_field(node, value, "balancing_node")
				end)
				check_field(node, node.fallback_node, "fallback_node")
			elseif node.protocol == "_shunt" then
				if node.preproxy_enabled == "1" then
					check_field(node, node.main_node, "main_node")
				end
				check_field(node, node.default_node, "default_node")
				for _, rule in ipairs(rules) do
					local field = rule.label and rule.label ~= "" and
						("shunt_rules「%s」(%s)"):format(rule.label, rule.id) or
						("shunt_rules(%s)"):format(rule.id)
					check_field(node, node[rule.id], field)
				end
			elseif node.protocol ~= "_iface" then
				check_field(node, node.to_node, "to_node")
			end
		end
	end)

	if #blockers == 0 then return true end
	table.sort(blockers, function(a, b)
		if a.source_label ~= b.source_label then return a.source_label < b.source_label end
		if a.field ~= b.field then return a.field < b.field end
		return a.target < b.target
	end)

	local lines = { "无法删除所选节点，以下保留节点仍在引用：" }
	for _, blocker in ipairs(blockers) do
		lines[#lines + 1] = string.format("- %s 的字段 %s 引用了 %s", blocker.source_label, blocker.field, blocker.target)
	end
	return nil, table.concat(lines, "\n"), blockers
end

return M
