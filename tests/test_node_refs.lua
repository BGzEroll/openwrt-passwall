local node_refs = arg and arg[1] and dofile(arg[1]) or require "luci.passwall.node_refs"

local nodes = {
	target = { [".name"] = "target", protocol = "vmess", remarks = "目标" },
	target2 = { [".name"] = "target2", protocol = "vmess", remarks = "目标二" },
	inside_a = { [".name"] = "inside_a", protocol = "_balancing", balancing_node = "inside_b" },
	inside_b = { [".name"] = "inside_b", protocol = "_balancing", fallback_node = "inside_a" },
	balance_ref = {
		[".name"] = "balance_ref", protocol = "_balancing", remarks = "均衡器",
		balancing_node = { "target", "_direct", "_blackhole", "_default", "nil", "tcp" },
		fallback_node = "target2"
	},
	shunt_ref = {
		[".name"] = "shunt_ref", protocol = "_shunt", remarks = "分流器",
		preproxy_enabled = "1", main_node = "target", default_node = "target2",
		rule_a = "target", rule_b = "_default"
	},
	shunt_preproxy_off = {
		[".name"] = "shunt_preproxy_off", protocol = "_shunt",
		preproxy_enabled = "0", main_node = "target"
	},
	ordinary_ref = {
		[".name"] = "ordinary_ref", protocol = "vmess", remarks = "落地节点",
		to_node = "target"
	}
}

local sections = { outside = "acl_rule" }
local rules = {
	{ [".name"] = "rule_a", remarks = "规则甲" },
	{ [".name"] = "rule_b", remarks = "规则乙" }
}
local uci = {}
function uci:get(_, section)
	return nodes[section] and "nodes" or sections[section]
end
function uci:foreach(_, section_type, callback)
	local source = section_type == "nodes" and nodes or rules
	for _, section in pairs(source) do callback(section) end
end

local ids, err = node_refs.parse_ids("target,target2,target")
assert(ids and #ids == 2 and ids[1] == "target" and ids[2] == "target2", err)
assert(node_refs.parse_ids("") == nil)
assert(node_refs.parse_ids("target,") == nil)
assert(node_refs.check_delete(uci, {"outside"}) == nil, "non-node section must be rejected")

local ok = node_refs.check_delete(uci, {"inside_a", "inside_b"})
assert(ok == true, "references inside the deletion set must not block")

local permitted, message, blockers = node_refs.check_delete(uci, {"target", "target2"})
assert(permitted == nil and #blockers == 6, message)
local observed = {}
for _, blocker in ipairs(blockers) do
	observed[blocker.source .. "." .. blocker.field] = true
end
assert(observed["balance_ref.balancing_node"])
assert(observed["balance_ref.fallback_node"])
assert(observed["shunt_ref.main_node"])
assert(observed["shunt_ref.default_node"])
assert(observed["shunt_ref.shunt_rules「规则甲」(rule_a)"])
assert(observed["ordinary_ref.to_node"])
assert(not observed["shunt_preproxy_off.main_node"], "disabled preproxy must not count")
assert(message:find("均衡器（balance_ref）", 1, true))
assert(message:find("规则甲", 1, true))

print("node_refs mock checks passed")
