-- Run on OpenWrt with LuCI installed: lua tests/test_endpoints.lua [module path]
local endpoint = arg[1] and dofile(arg[1]) or require 'luci.passwall.endpoint'
local function check(value, host, port)
 local h, p = endpoint.parse(value)
 assert(h == host and p == port, value)
end
check('1.1.1.1', '1.1.1.1', 53)
check('1.1.1.1:5353', '1.1.1.1', 5353)
check('dns.example#5353', 'dns.example', 5353)
check('2001:db8::53', '2001:db8::53', 53)
check('2001:db8::53#5353', '2001:db8::53', 5353)
check('[2001:db8::53]:5353', '2001:db8::53', 5353)
assert(endpoint.list('1.1.1.1, [2001:db8::1]:5353') == '1.1.1.1#53,2001:db8::1#5353')
assert(endpoint.format('2001:db8::1', 53, ':') == '[2001:db8::1]:53')
local url, host, port, ip = endpoint.doh('https://[2001:db8::1]:8443/dns-query')
assert(url == 'https://[2001:db8::1]:8443/dns-query' and host == '2001:db8::1' and port == 8443 and ip == host)
url, host, port, ip = endpoint.doh('https://dns.example/dns-query,2001:db8::1')
assert(host == 'dns.example' and port == 443 and ip == '2001:db8::1')
for _, value in ipairs({'[2001:db8::1]:0', '1.1.1.1:65536', 'dns.example#bad', '127.0.0.1;touch /tmp/bad'}) do
 assert(not pcall(endpoint.parse, value), value)
end
for _, value in ipairs({'http://dns.example/dns-query', 'https://user@dns.example/dns-query', 'https://dns.example/dns-query,bad'}) do
 assert(not pcall(endpoint.doh, value), value)
end
print('DNS endpoint cases passed')
