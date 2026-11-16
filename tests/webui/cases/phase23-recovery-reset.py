ids=json.loads((ROOT/'ids.json').read_text())
def state():return json.loads(ssh('lua /usr/share/passwall/process.lua status'))
def off_on():
 go('settings');flag('enabled',False);submit();wait(lambda:state()['service_status']=='disabled')
 assert ssh('uci get dhcp.@dnsmasq[0].dns_redirect')=='1' and ssh('uci get firewall.@defaults[0].flow_offloading_hw')=='1'
 assert ssh('nft list tables | grep -c "inet passwall" || true')=='0'
 go('settings');flag('enabled',True);submit();wait(lambda:state()['service_status']=='running')
check('GUI enable switch off/on restores native settings then healthy runtime',off_on)
def reset_unsaved():
 go('node_config/'+ids['socks']);old=field('remarks').input_value();fill('remarks','UNSAVED UI VALUE');page.locator('.cbi-page-actions .cbi-button-reset').last.click();page.wait_for_load_state('networkidle')
 wait(lambda:field('remarks').input_value()==old)
 go('rule');tab('direct_list');old=field('direct_host','textarea').input_value();field('direct_host','textarea').fill('unsaved.example\n');page.locator('.cbi-page-actions .cbi-button-reset').last.click();page.wait_for_load_state('networkidle');tab('direct_list');assert field('direct_host','textarea').input_value()==old
check('GUI Reset discards unsaved node and file edits',reset_unsaved)
def error_banner():
 gateway=ssh("ip -6 route show default | head -1 | sed -n 's/.* via \\([^ ]*\\).*/\\1/p'")
 go('other');flag('iproute_shunt',True);fill('iproute_shunt_gw_v4','192.0.2.1');fill('iproute_shunt_gw_v6',gateway);fill('iproute_shunt_interface','eth0');submit()
 wait(lambda:state()['last_error']!='')
 go('settings');wait(lambda:page.locator('#passwall-apply-error').is_visible(),15)
 assert '未应用配置' in page.locator('#passwall-apply-error').inner_text()
 go('other');flag('iproute_shunt',False);submit();wait(lambda:state()['last_error']=='')
 go('settings');wait(lambda:not page.locator('#passwall-apply-error').is_visible(),15)
check('failed GUI apply shows native warning, GUI correction clears warning',error_banner)
