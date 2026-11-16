ids=json.loads((ROOT/'ids.json').read_text())
def dns_only_xray():
 try:
  go('settings');select('tcp_node','nil');select('udp_node','nil');tab('DNS');select('dns_mode','xray');select('xray_dns_mode','tcp');submit()
  wait(lambda:json.loads(ssh('lua /usr/share/passwall/process.lua status'))['dns_status']=='running')
  assert 'Name:' in ssh('nslookup example.com 127.0.0.1 2>&1 || true')
  go('other');fill('buffer_size','12');submit()
  data=json.loads(ssh('cat /tmp/etc/passwall/DNS.json'));assert data['policy']['levels']['0']['bufferSize']==12
 finally:
  go('settings');select('tcp_node',ids['socks']);select('udp_node','tcp');tab('DNS');select('dns_mode','udp');submit()
check('GUI no proxy nodes + Xray DNS still resolves; standalone core options update',dns_only_xray)
