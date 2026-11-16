def textarea(key):return field(key,'textarea')
def rule_files():
 go('rule')
 cases=[('direct_list','direct_host','UI-DIRECT.Example.\nui-direct.example\n# direct note\n','ui-direct.example'),('direct_list','direct_ip','192.0.2.11\n2001:db8::11\n','192.0.2.11'),('proxy_list','proxy_host','ui-proxy.example\n','ui-proxy.example'),('proxy_list','proxy_ip','192.0.2.12\n2001:db8::12\n','192.0.2.12'),('block_list','block_host','ui-block.example\n','ui-block.example'),('block_list','block_ip','192.0.2.13\n2001:db8::13\n','192.0.2.13')]
 for pane,key,value,expected in cases:
  tab(pane);textarea(key).fill(value)
 submit()
 for pane,key,value,expected in cases:
  text=ssh('cat /usr/share/passwall/rules/'+key)
  assert expected in text,(key,text)
 assert ssh('grep -c ui-direct.example /usr/share/passwall/rules/direct_host')=='1'
 go('settings');tab('Proxy')
 for k in ['use_direct_list','use_proxy_list','use_block_list','use_gfw_list']:flag(k,True)
 submit()
 assert '192.0.2.11' in ssh('nft list set inet passwall passwall_whitelist')
 assert '192.0.2.12' in ssh('nft list set inet passwall passwall_blacklist')
 assert '192.0.2.13' in ssh('nft list set inet passwall passwall_blocklist')
check('GUI edit all direct/proxy/block domain+IP lists and apply NFT sets',rule_files)
def host_file():
 go('rule');tab('route_hosts');old='\n'.join(l for l in textarea('hosts').input_value().splitlines() if 'ui-host.example' not in l)+'\n';textarea('hosts').fill(old+'\n192.0.2.77 ui-host.example\n');submit()
 assert '192.0.2.77 ui-host.example' in ssh('cat /etc/hosts')
 out=ssh('nslookup ui-host.example 127.0.0.1 2>&1 || true')
 assert '192.0.2.77' in out,out
 # Remove the entry through GUI and ensure the running resolver stops using it.
 go('rule');tab('route_hosts');textarea('hosts').fill(old);submit()
 assert '192.0.2.77 ui-host.example' not in ssh('cat /etc/hosts')
 assert '192.0.2.77' not in ssh('nslookup ui-host.example 127.0.0.1 2>&1 || true')
check('GUI Hosts addition/removal takes effect in running dnsmasq',host_file)
def lan_lists():
 go('rule');tab('lan_ip_list')
 for k,entry in [('lanlist_ipv4','192.0.2.0/24'),('lanlist_ipv6','2001:db8:aaaa::/48')]:
  t=textarea(k);t.fill(t.input_value()+'\n'+entry+'\n')
 submit()
 assert '192.0.2.0/24' in ssh('nft list set inet passwall passwall_lanlist')
 assert '2001:db8::/32' in ssh('nft list set inet passwall passwall_lanlist6')
 assert '2001:db8:aaaa::/48' in ssh('cat /usr/share/passwall/rules/lanlist_ipv6')
 go('rule')
 for pane in ['gfw_list','chnroute_list','chnroute6_list']:
  tab(pane);root=page.locator(f'.passwall-rule-lazy-list[data-rule-tab="{pane}"]')
  wait(lambda:root.locator('textarea').input_value()!='')
  assert root.locator('textarea').get_attribute('name') is None
check('GUI IPv4/IPv6 LAN additions and three lazy rule lists',lan_lists)
