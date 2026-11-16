ids=json.loads((ROOT/'ids.json').read_text())
def status():return json.loads(ssh('lua /usr/share/passwall/process.lua status'))
def modes():
 for tcp,udp,t_state,u_state in [(ids['socks'],'nil','running','disabled'),('nil',ids['socks'],'disabled','running'),('nil','nil','disabled','disabled'),(ids['socks'],ids['socks'],'running','running'),(ids['socks'],'tcp','running','running')]:
  go('settings');select('tcp_node',tcp);select('udp_node',udp);tab('DNS');select('dns_mode','udp');submit()
  wait(lambda:status()['tcp_status']==t_state and status()['udp_status']==u_state,20)
  assert status()['dns_status'] in ['running','configured'],status()
  if tcp!='nil':assert ssh("curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}'")=='204'
  out=ssh('nslookup example.com 127.0.0.1 2>&1 || true');assert 'Name:' in out,out
check('GUI TCP only/UDP only/neither/separate/shared states and actual DNS',modes)
def disable_enable():
 go('settings');flag('enabled',False);submit();wait(lambda:status()['service_status']=='disabled')
 assert ssh('uci get dhcp.@dnsmasq[0].dns_redirect')=='1'
 assert ssh('uci get firewall.@defaults[0].flow_offloading_hw')=='1'
 assert ssh('nft list tables | grep -c "inet passwall" || true')=='0'
 go('settings');flag('enabled',True);submit();wait(lambda:status()['service_status']=='running')
check('GUI service off/on restores native DNS/offload and rebuilds runtime',disable_enable)
