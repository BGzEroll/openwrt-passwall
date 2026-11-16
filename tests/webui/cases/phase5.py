def status():return json.loads(ssh('lua /usr/share/passwall/process.lua status'))
def query():
 out=ssh('nslookup example.com 127.0.0.1 2>&1 || true')
 assert 'NXDOMAIN' not in out and 'connection timed out' not in out and 'Name:' in out,out

def dns_case(component,mode,upstream):
 go('settings');tab('DNS');select('dns_shunt',component);select('direct_dns_mode','udp');fill('direct_dns_udp','192.168.114.1');select('dns_mode',mode)
 if mode=='xray':
  select('xray_dns_mode',upstream)
  if upstream=='tcp+doh':fill('remote_dns_doh','https://1.1.1.1/dns-query')
 fill('remote_dns','192.168.114.1');submit()
 wait(lambda:status().get('service_status')=='running',30)
 c=config()[section('global')];assert c['dns_mode']==mode and c['dns_shunt']==component
 if mode=='xray':assert c['v2ray_dns_mode']==upstream
 query()
for component in ['dnsmasq','chinadns-ng']:
 for mode,upstream in [('udp',None),('tcp',None),('xray','tcp'),('xray','tcp+doh')]:
  check(f'GUI DNS {component}/{mode}/{upstream} start+real DNS',lambda c=component,m=mode,u=upstream:dns_case(c,m,u))
def direct_dns_modes():
 for mode in ['tcp','']:
  go('settings');tab('DNS');select('direct_dns_mode',mode)
  if mode=='tcp':fill('direct_dns_tcp','192.168.114.1')
  submit();wait(lambda:status().get('service_status')=='running');query()
check('GUI direct DNS TCP and automatic modes',direct_dns_modes)
def hijack_local():
 for local,hijack in [(False,False),(True,False),(True,True),(False,True)]:
  go('settings');tab('Proxy');flag('localhost_proxy',local);tab('DNS');flag('dns_redirect',hijack);submit()
  wait(lambda:status().get('service_status')=='running')
  expected='0' if hijack else '1';assert ssh("uci -q get dhcp.@dnsmasq[0].dns_redirect")==expected
  query()
check('GUI DNS hijack and local proxy four combinations',hijack_local)
