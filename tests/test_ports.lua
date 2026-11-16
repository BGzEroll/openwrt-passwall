local api = require 'luci.passwall.api'
for input, expected in pairs({
 [' 80, 443 ']='80,443', ['80-90,85:100,100,443']='80:100,443',
 ['65535,0']='0,65535', ['1:65535,80']='1:65535',
 ['default']='default', ['disable']='disable'
}) do
 assert(api.normalize_ports(input, true) == expected, input)
end
for _, input in ipairs({'', 'not-a-port', '80,,443', '65536', '-1', '90:80', '1:2:3', '8 0', '80,'}) do
 assert(api.normalize_ports(input) == nil, input)
end
assert(api.normalize_ports('default') == nil)
print('port grammar, bounds and overlapping ranges passed')
