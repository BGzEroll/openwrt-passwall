-- Shared DNS endpoint parsing. Bare IPv6 addresses never imply a port.
local types = require 'luci.cbi.datatypes'
local M = {}
function M.parse(value, default_port)
 assert(type(value) == 'string', '缺少 DNS 地址')
 local host, port
 if value:sub(1, 1) == '[' then
  local tail
  host, tail = value:match('^%[([^%]]+)%](.*)$')
  assert(host and types.ip6addr(host), '无效 IPv6 DNS 地址：' .. value)
  if tail ~= '' then port = tail:match('^[:#](%d+)$'); assert(port, '无效 DNS 端口：' .. value) end
 elseif value:find('#', 1, true) then
  host, port = value:match('^(.-)#(%d+)$')
 elseif types.ip6addr(value) then
  host = value
 else
  host, port = value:match('^([^:]+):(%d+)$')
  host = host or value
 end
 assert(host and (types.ipaddr(host) or types.hostname(host)), '无效 DNS 地址：' .. value)
 port = tonumber(port or default_port or 53)
 assert(port and port >= 1 and port <= 65535 and port % 1 == 0, '无效 DNS 端口：' .. value)
 return host, port
end
function M.format(host, port, separator)
 if separator == ':' and host:find(':', 1, true) then host = '[' .. host .. ']' end
 return host .. (separator or '#') .. port
end
function M.list(value)
 local result = {}
 for item in (value or ''):gmatch('[^,%s]+') do
  local host, port = M.parse(item)
  result[#result + 1] = M.format(host, port)
 end
 assert(#result > 0, '缺少 DNS 地址')
 return table.concat(result, ',')
end
function M.doh(value)
 local url, bootstrap = value:match('^([^,]+),?(.*)$')
 local authority = url and url:match('^https://([^/?#]+)')
 assert(authority and not authority:find('@', 1, true), '无效 DoH 地址：' .. tostring(value))
 local host, port = M.parse(authority, 443)
 if bootstrap == '' then bootstrap = nil end
 if bootstrap then
  assert(types.ipaddr(bootstrap), '无效 DoH 引导地址：' .. bootstrap)
 end
 if types.ipaddr(host) then bootstrap = host end
 return url, host, port, bootstrap
end
return M
