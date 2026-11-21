#!/usr/bin/lua
local fs = require 'nixio.fs'
local nixio = require 'nixio'
local json = require 'luci.jsonc'
local sys = require 'luci.sys'
local quote = require 'luci.util'.shellquote
local ubus = require 'ubus'
local root = '/var/run/passwall'
local action, directory = arg[1], arg[2]
local api = require 'luci.passwall.api'

local function read(path)
 return assert(json.parse(assert(fs.readfile(path))), path)
end
local function plans(path)
 local result = {}
 for file in fs.dir(path) or function() end do
  if file:match('^process%d+%.json$') then result[file:gsub('%.json$', '')] = read(path .. '/' .. file) end
 end
 return result
end
local function call(method, data)
 local bus = assert(ubus.connect())
 local result, err = bus:call('service', method, data)
 bus:close()
 assert(not err or err == 0, 'procd ' .. method .. ': ' .. tostring(err))
 return result or {}
end
local function config_arg(command)
 for i = 4, #command - 1 do
  if command[i] == '-c' or command[i] == '-C' then return command[i + 1] end
 end
end
local function validate(instance)
 local binary = instance.command[3]
 if binary ~= '/usr/bin/xray' then return end
 local config = assert(config_arg(instance.command))
 local output = directory .. '/validation.log'
 if sys.call(quote(binary) .. ' run -test -c ' .. quote(config) .. ' >' .. quote(output) .. ' 2>&1') ~= 0 then
  local detail = (fs.readfile(output) or ''):gsub('%s+$', '')
  api.log_debug('核心', detail)
  error('Xray 配置校验失败：' .. (detail:match('[^\r\n]+$') or '未知原因'), 0)
 end
end
local function listening(protocol, port)
 for _, suffix in ipairs({'', '6'}) do
  local f = io.open('/proc/net/' .. protocol .. suffix)
  if f then
   for line in f:lines() do
    local p, state = line:match('^%s*%d+:%s+%x+:(%x+)%s+%S+%s+(%x+)')
    if p and tonumber(p, 16) == tonumber(port) and (protocol == 'udp' or state == '0A') then f:close(); return true end
   end
   f:close()
  end
 end
 return false
end
local function ports_ready(instance)
 local config = config_arg(instance.command)
 local command = instance.command
 if command[3] == '/usr/bin/dns2tcp' then
  for i = 4, #command - 1 do
   if command[i] == '-L' then return listening('udp', command[i + 1]:match('#(%d+)$')) end
  end
 elseif command[3] == '/usr/bin/chinadns-ng' then
  local port = assert(fs.readfile(config)):match('bind%-port%s+(%d+)')
  return port and listening('udp', port)
 end
 if not config or not config:match('%.json$') then return true end
 local data = read(config)
 for _, inbound in ipairs(data.inbounds or {}) do
  local port = inbound.port
  if port then
   local protocol = inbound.protocol
   local network = inbound.network or (inbound.settings or {}).network or 'tcp'
   if protocol == 'socks' or protocol == 'http' or network:find('tcp', 1, true) then
    if not listening('tcp', port) then return false end
   elseif network == 'udp' and not listening('udp', port) then return false end
  end
 end
 return true
end

-- ChinaDNS reads its configuration and domain files only at startup. Keep each instance's
-- inputs immutable so a failed replacement can restart the old instance.
local function dns_files(expected, direct_dns)
 local changed, created, obsolete = false, {}, {}
 for name, instance in pairs(expected) do
  if instance.command[3] == '/usr/bin/chinadns-ng' then
   local source = (instance.data or {}).source_config or config_arg(instance.command)
   local text = assert(fs.readfile(source))
   if direct_dns and direct_dns ~= '' then
    -- Refresh automatic upstreams in the candidate, preserving the old live snapshot.
    local group
    text = text:gsub('[^\r\n]+', function(line)
     group = line:match('^%s*group%s+(%S+)') or group
     local option = line:match('^%s*([%w%-]+)%s+')
     if option == 'china-dns' or (option == 'group-upstream' and (group == 'vpslist' or group == 'directlist')) then
      return option .. ' ' .. direct_dns
     end
     return line
    end)
   end
   local files, content = {}, {}
   for option, path in text:gmatch('([%w%-]+)%s+([^\r\n]+)') do
    if option == 'group-dnl' or option == 'gfwlist-file' then
     files[#files + 1] = path
     content[path] = fs.readfile(path) or ''
    end
   end
   local signature = text
   for _, path in ipairs(files) do signature = signature .. '\0' .. path .. '\0' .. content[path] end
   local folder = sys.exec('mktemp -d ' .. quote(directory .. '/dns.XXXXXX')):gsub('%s+$', '')
   assert(folder ~= '', '无法创建 DNS 规则快照')
   assert(fs.writefile(folder .. '/signature', signature))
   signature = sys.exec('sha256sum ' .. quote(folder .. '/signature')):match('^(%x+)')
   assert(signature, 'DNS 规则签名失败')
   fs.unlink(folder .. '/signature')
   if signature ~= (instance.data or {}).file_signature then
    created[#created + 1] = folder
    for i, path in ipairs(files) do
     local target = folder .. '/list' .. i
     assert(fs.writefile(target, content[path]))
     text = text:gsub('([^\r\n]+)', function(line)
      local option, value = line:match('^%s*([%w%-]+)%s+(.+)$')
      if (option == 'group-dnl' or option == 'gfwlist-file') and value == path then return option .. ' ' .. target end
      return line
     end)
    end
    assert(fs.writefile(folder .. '/config', text))
    local old = config_arg(instance.command)
    if old ~= source then obsolete[#obsolete + 1] = old:match('^(.*)/config$') end
    for i, arg in ipairs(instance.command) do
     if arg == '-C' then instance.command[i + 1] = folder .. '/config'; break end
    end
    instance.data = {source_config=source, file_signature=signature}
    changed = true
   else
    fs.rmdir(folder)
   end
  end
 end
 return changed, created, obsolete
end

local function remove_folders(folders)
 for _, folder in ipairs(folders) do fs.remover(folder) end
end

local function wait_ready(expected, message)
 for _ = 1, 50 do
  local service = call('list', {name='passwall'}).passwall or {}
  local ready = true
  for name, instance in pairs(expected) do
   local live = (service.instances or {})[name]
   if not live or not live.running or not ports_ready(instance) then
    ready = false
    break
   end
  end
  if ready then return end
  nixio.nanosleep(0, 100000000)
 end
 error(message, 0)
end

local function reload_files()
 local expected = plans(directory)
 local changed, created, obsolete = dns_files(expected, arg[3])
 if not changed then return end
 local previous = plans(directory)
 local dns = {}
 for name, instance in pairs(expected) do
  if instance.command[3] == '/usr/bin/chinadns-ng' then dns[name] = instance end
 end
 local ok, err = pcall(function()
  call('set', {name='passwall', instances=expected})
  wait_ready(dns, 'ChinaDNS-NG 配置加载失败')
 end)
 if not ok then
  call('set', {name='passwall', instances=previous})
  remove_folders(created)
  error(err, 0)
 end
 for name, instance in pairs(dns) do
  assert(fs.writefile(directory .. '/' .. name .. '.json', json.stringify(instance)))
 end
 remove_folders(obsolete)
end

local function status()
 local uci = require 'uci'.cursor(root .. '/runtime/config', root .. '/runtime/config')
 local function runtime(key)
  return (fs.readfile(root .. '/runtime/' .. key) or ''):gsub('%s+$', '')
 end
 local service = call('list', {name='passwall'}).passwall or {}
 local instances, expected = service.instances or {}, plans(root .. '/processes')
 local all_ready, core_count, core_ready, dns_count, dns_ready = true, 0, true, 0, true
 local redirect_ready = {tcp=false, udp=false}
 for name, definition in pairs(expected) do
  local running = instances[name] and instances[name].running == true
  all_ready = all_ready and running
  local binary = definition.command[3]:match('[^/]+$')
  local dns_only = binary == 'dns2tcp' or binary == 'chinadns-ng'
  local is_dns = dns_only
  local config = config_arg(definition.command)
  if config and config:match('%.json$') then
   for _, inbound in ipairs(read(config).inbounds or {}) do
    if (inbound.tag or ''):match('^dns') then is_dns = true end
    if inbound.tag == 'tcp_redir' then redirect_ready.tcp = running and listening('tcp', inbound.port) end
    if inbound.tag == 'udp_redir' then redirect_ready.udp = running and listening('udp', inbound.port) end
   end
  end
  if not dns_only then core_count = core_count + 1; core_ready = core_ready and running end
  if is_dns then dns_count = dns_count + 1; dns_ready = dns_ready and running end
 end
 local socks = (fs.readfile('/tmp/etc/passwall/acl/default/TCP_SOCKS_server') or ''):gsub('%s+$', '')
 local socks_port = socks:match(':(%d+)$')
 core_ready = core_count > 0 and core_ready and (not socks_port or listening('tcp', socks_port))
 local tun_dns, china_dns = runtime('TUN_DNS'), runtime('CHINADNS_DNS')
 local local_dns = china_dns ~= '' and china_dns ~= '0' and china_dns or tun_dns
 local local_port = local_dns:match('^127%.0%.0%.1#(%d+)$')
 if local_port then dns_ready = dns_ready and (listening('tcp', local_port) or listening('udp', local_port)) end
 local enabled = uci:get('passwall', '@global[0]', 'enabled') == '1'
 local running = not not fs.access(root .. '/running')
 local pbr = uci:get('passwall', '@global_forwarding[0]', 'iproute_shunt') == '1'
 local forwarding = running and sys.call("nft list tables | grep -Fxq 'table inet passwall'") == 0
 for _, family in ipairs({4, 6}) do
  if not forwarding then break end
  local routes = sys.exec('ip -' .. family .. ' route show table 100 2>/dev/null')
  local rules = sys.exec('ip -' .. family .. ' rule show 2>/dev/null')
  local found = false
  local device = uci:get('passwall', '@global_forwarding[0]', 'iproute_shunt_interface') or ''
  local gateway = uci:get('passwall', '@global_forwarding[0]', 'iproute_shunt_gw_v' .. family) or ''
  for line in routes:gmatch('[^\n]+') do
   if line:find('metric 100', 1, true) then
    if pbr then
     found = line:match('^default via (%S+)') == gateway and line:match(' dev (%S+)') == device
    else found = line:match('^local default dev lo') ~= nil end
    if found then break end
   end
  end
  forwarding = forwarding and found and rules:find('fwmark 0x1 lookup 100', 1, true) ~= nil
 end
 local tcp_expected = (uci:get('passwall', '@global[0]', 'tcp_node') or 'nil') ~= 'nil'
 if tcp_expected and not socks_port then core_ready = false end
 local function proxy_status(protocol)
  local node = uci:get('passwall', '@global[0]', protocol .. '_node') or 'nil'
  if node == 'tcp' then node = uci:get('passwall', '@global[0]', 'tcp_node') or 'nil' end
  if not enabled or node == 'nil' then return 'disabled' end
  return running and forwarding and redirect_ready[protocol] and 'running' or 'not_running'
 end
 local healthy = running and all_ready and forwarding and (not tcp_expected or core_ready) and dns_ready
 return {
  tcp_status=proxy_status('tcp'), udp_status=proxy_status('udp'),
  service_status=not enabled and 'disabled' or not running and 'not_running' or healthy and 'running' or 'degraded',
  service_detail=healthy and '' or running and '部分服务尚未就绪' or '服务已停止',
  forwarding_mode=pbr and 'PBR' or 'TPROXY', forwarding_status=forwarding and 'ready' or 'not_ready',
  forwarding_detail=forwarding and 'IPv4 / IPv6 转发已就绪' or '转发规则或路由尚未就绪',
  core_status=core_count == 0 and 'not_required' or core_ready and 'running' or 'not_running',
  core_detail=socks ~= '' and ('SOCKS ' .. socks) or '未启用本地 SOCKS',
  dns_status=not running and 'not_running' or dns_ready and (dns_count > 0 and 'running' or 'configured') or 'not_running',
  dns_detail=local_dns, last_error=(fs.readfile(root .. '/last_error') or ''):gsub('%s+$', ''),
  tcp_port=runtime('TCP_REDIR_PORT'), udp_port=runtime('UDP_REDIR_PORT')
 }
end

local ok, err = pcall(function()
 if action == 'status' then
  print(json.stringify(status()))
 elseif action == 'plan' then
  local command = {'/usr/share/passwall/process.sh', arg[3], arg[4]}
  for i = 5, #arg do command[#command + 1] = arg[i] end
  local count = 0
  for _ in pairs(plans(directory)) do count = count + 1 end
  local instance = {command=command, respawn={"3600", "5", "5"}, term_timeout=3,
   env={V2RAY_LOCATION_ASSET='/usr/share/v2ray/', XRAY_LOCATION_ASSET='/usr/share/v2ray/'}}
  assert(fs.writefile(directory .. '/process' .. (count + 1) .. '.json', json.stringify(instance)))
 elseif action == 'validate' then
  for _, instance in pairs(plans(directory)) do validate(instance) end
 elseif action == 'start' then
  local expected = plans(directory)
  dns_files(expected)
  for name, instance in pairs(expected) do
   assert(fs.writefile(directory .. '/' .. name .. '.json', json.stringify(instance)))
  end
  call('set', {name='passwall', instances=expected})
  wait_ready(expected, '核心或 DNS 进程未就绪')
 elseif action == 'reload_files' then
  reload_files()
 elseif action == 'stop' then
  local service = call('list', {name='passwall'}).passwall
  local pids = {}
  for _, instance in pairs(service and service.instances or {}) do
   if instance.pid then pids[#pids + 1] = instance.pid end
  end
  if service then call('delete', {name='passwall'}) end
  for _ = 1, 50 do
   local alive = false
   for _, pid in ipairs(pids) do if fs.access('/proc/' .. pid) then alive = true end end
   if not alive then return end
   nixio.nanosleep(0, 100000000)
  end
  error('procd 进程未能退出')
 else error('Unknown process operation') end
end)
if not ok then
 local message = tostring(err)
 if action ~= 'status' then
  fs.writefile(root .. '/last_error', message)
  api.log('核心', message)
 end
 io.stderr:write(message, '\n')
 os.exit(1)
end
