#!/usr/bin/lua
-- Only the selected Xray graph and DNS settings affect core lifetime.
local uci = require 'luci.model.uci'.cursor()
local json = require 'luci.jsonc'
local api = require 'luci.passwall.api'
local nodes, rules, order, selected, result = {}, {}, {}, {}, {}
uci:foreach('passwall', 'nodes', function(n) nodes[n['.name']] = n end)
uci:foreach('passwall', 'shunt_rules', function(r)
 rules[r['.name']] = r
 order[#order + 1] = r['.name']
end)
local function clean(value)
 local out = {}
 for key, item in pairs(value or {}) do
  if key:sub(1, 1) ~= '.' and key ~= 'remarks' and key ~= 'group' then out[key] = item end
 end
 return out
end
local function visit(id)
 if selected[id] or not nodes[id] then return end
 selected[id] = true
 local node = nodes[id]
 assert(node.type == 'Xray', '只支持 Xray 节点：' .. id)
 result['node:' .. id] = clean(node)
 if node.protocol == '_balancing' then
  local members = node.balancing_node or {}
  if type(members) == 'string' then members = {members} end
  for _, member in ipairs(members) do visit(member) end
  visit(node.fallback_node)
 elseif node.protocol == '_shunt' then
  if node.preproxy_enabled == '1' then visit(node.main_node) end
  visit(node.default_node)
  local matched = {}
  result['rule_order:' .. id] = matched
  for _, name in ipairs(order) do
   local rule = rules[name]
   if node[name] and api.is_supported_shunt_rule(rule) then
    matched[#matched + 1] = name
    local copy = clean(rule)
    copy.remarks = rule.remarks ~= nil and rule.remarks ~= ''
    result['rule:' .. name] = copy
    visit(node[name])
   end
  end
 elseif node.protocol ~= '_iface' then
  visit(node.to_node)
 end
end
local global = uci:get_all('passwall', '@global[0]') or {}
visit(global.tcp_node)
if global.udp_node ~= 'tcp' then visit(global.udp_node) end
result.global = {}
for _, key in ipairs({
 'tcp_node', 'udp_node', 'tcp_node_socks_port', 'tcp_node_socks_bind_local',
 'log_tcp', 'log_udp', 'loglevel', 'dns_shunt', 'dns_mode', 'direct_dns_mode',
 'direct_dns_udp', 'direct_dns_tcp', 'remote_dns', 'remote_dns_doh',
 'v2ray_dns_mode', 'dns_client_ip'
}) do result.global[key] = global[key] end
if global.dns_shunt == 'chinadns-ng' then
 for _, key in ipairs({'use_direct_list', 'use_proxy_list', 'use_gfw_list', 'chn_list', 'tcp_proxy_mode', 'chinadns_ng_default_tag'}) do
  result.global[key] = global[key]
 end
end
if next(selected) then result.xray = clean(uci:get_all('passwall', '@global_xray[0]')) end
local function encode(value)
 if type(value) ~= 'table' then return json.stringify(value) end
 local keys, out = {}, {}
 for key in pairs(value) do keys[#keys + 1] = key end
 table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
 for _, key in ipairs(keys) do out[#out + 1] = json.stringify(tostring(key)) .. ':' .. encode(value[key]) end
 return '{' .. table.concat(out, ',') .. '}'
end
print(encode(result))
