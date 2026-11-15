#!/usr/bin/lua
-- Only settings consumed by the selected core/DNS graph affect core lifetime.
local uci = require 'luci.model.uci'.cursor()
local json = require 'luci.jsonc'
local nodes, rules, rule_order, selected, result = {}, {}, {}, {}, {}
uci:foreach('passwall', 'nodes', function(n) nodes[n['.name']] = n end)
uci:foreach('passwall', 'shunt_rules', function(r)
 rules[r['.name']] = r
 rule_order[#rule_order + 1] = r['.name']
end)
local function clean(value)
 local out = {}
 for k,v in pairs(value or {}) do
  if k:sub(1,1) ~= '.' and k ~= 'remarks' and k ~= 'group' then out[k] = v end
 end
 return out
end
local function visit(id)
 if selected[id] or not nodes[id] then return end
 selected[id] = true
 local node = nodes[id]
 result['node:' .. id] = clean(node)
 for _, value in pairs(node) do
  if type(value) == 'string' then
   for token in value:gmatch('%S+') do visit(token) end
  elseif type(value) == 'table' then for _, token in ipairs(value) do visit(token) end end
 end
 if node.protocol == '_shunt' then
  local order = {}
  result['rule_order:' .. id] = order
  for _, name in ipairs(rule_order) do
   local rule = rules[name]
   if node[name] then
    order[#order + 1] = name
    local copy = clean(rule)
    copy.remarks = rule.remarks and rule.remarks ~= '' or false
    result['rule:' .. name] = copy
   end
  end
 end
end
local global = uci:get_all('passwall', '@global[0]') or {}
visit(global.tcp_node)
visit(global.udp_node)
result.global = clean(global)
result.global.dns_redirect = nil
result.global.localhost_proxy = nil
result.global.udp_proxy_mode = nil
if global.dns_shunt ~= 'chinadns-ng' then
 for _, key in ipairs({'use_direct_list', 'use_proxy_list', 'use_block_list', 'use_gfw_list', 'chn_list', 'tcp_proxy_mode'}) do
  result.global[key] = nil
 end
end
-- Read settings of used core families, including standalone DNS engines.
for _, family in ipairs({'xray', 'sing-box'}) do
 local needed = global.dns_mode == family
 for id in pairs(selected) do
  if (nodes[id].type or ''):lower() == family then needed = true end
 end
 if needed then
  local section = family == 'xray' and 'global_xray' or 'global_singbox'
  result[section] = clean(uci:get_all('passwall', '@' .. section .. '[0]'))
 end
end
local function encode(value)
 if type(value) ~= 'table' then return json.stringify(value) end
 local keys, out = {}, {}
 for key in pairs(value) do keys[#keys + 1] = key end
 table.sort(keys, function(a,b) return tostring(a) < tostring(b) end)
 for _, key in ipairs(keys) do out[#out + 1] = json.stringify(tostring(key)) .. ':' .. encode(value[key]) end
 return '{' .. table.concat(out, ',') .. '}'
end
print(encode(result))
