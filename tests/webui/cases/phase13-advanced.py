ids=json.loads((ROOT/'ids.json').read_text())
def status():return json.loads(ssh('lua /usr/share/passwall/process.lua status'))
def route(mode):return status()['service_status']=='running' and status()['forwarding_mode']==mode
def advanced():
 go('other');fill('start_delay','0')
 for key,val in [('tcp_no_redir_ports','22,25'),('udp_no_redir_ports','123'),('tcp_proxy_drop_ports','465'),('udp_proxy_drop_ports','443'),('tcp_redir_ports','80-443'),('udp_redir_ports','53,123')]:fill(key,val)
 flag('accept_icmp',False);flag('accept_icmpv6',False);fill('buffer_size','8');submit()
 c=config();assert c[section('global_delay')]['start_delay']=='0';assert c[section('global_forwarding')]['tcp_redir_ports']=='80:443'
 wait(lambda:status()['service_status']=='running')
 go('other');flag('fragment',True);select('fragment_packets','1-3');fill('fragment_length','100-150');fill('fragment_interval','10-15');flag('sniffing_override_dest',True)
 field('excluded_domains','textarea').fill('ui-excluded.example\n');submit()
 data=json.loads(ssh('cat /tmp/etc/passwall/acl/default/TCP.json'))
 assert any(o['tag']=='fragment' for o in data['outbounds'])
 assert any('ui-excluded.example' in i.get('sniffing',{}).get('domainsExcluded',[]) for i in data['inbounds'])
 go('other');flag('fragment',False);submit();wait(lambda:status()['service_status']=='running')
 # Preserve full port coverage for subsequent behavior tests.
 go('other')
 for key,val in [('tcp_no_redir_ports','disable'),('udp_no_redir_ports','disable'),('tcp_proxy_drop_ports','disable'),('udp_proxy_drop_ports','disable'),('tcp_redir_ports','1:65535'),('udp_redir_ports','1:65535')]:fill(key,val)
 submit()
check('advanced GUI autoapply: delay0, all port types, ICMP, buffer, fragment, excluded domains',advanced)
def pbr():
 gateway=ssh("ip -6 route show default | head -1 | sed -n 's/.* via \\([^ ]*\\).*/\\1/p'")
 go('other');flag('iproute_shunt',True);fill('iproute_shunt_gw_v4','192.168.114.1');fill('iproute_shunt_gw_v6',gateway);fill('iproute_shunt_interface','eth0')
 root=page.locator('.cbi-value[id$="-iproute_shunt_offloading_interface"]');assert not root.locator('input,select').filter(visible=True).count()
 submit();wait(lambda:route('PBR'))
 assert 'via 192.168.114.1 dev eth0' in ssh('ip -4 route show table 100')
 assert ssh('uci get firewall.@defaults[0].flow_offloading_hw')=='0'
 assert ssh("curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}'")=='204'
 # Reachable family with a non-link gateway must fail without breaking old service.
 before=ssh("ubus call service list '{\"name\":\"passwall\"}'")
 go('other');fill('iproute_shunt_gw_v4','192.0.2.1');submit()
 wait(lambda:status()['last_error']!='')
 assert route('PBR');assert before==ssh("ubus call service list '{\"name\":\"passwall\"}'")
 go('log');wait(lambda:('失败' in page.locator('#log_textarea').input_value()),15)
 go('other');fill('iproute_shunt_gw_v4','192.168.114.1');submit();wait(lambda:status()['last_error']=='')
 go('other');flag('iproute_shunt',False);submit();wait(lambda:route('TPROXY'))
check('GUI PBR enable/routes/SOCKS, invalid gateway retains runtime, recovery and TPROXY',pbr)
