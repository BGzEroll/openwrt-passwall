def raw_submit_error():
 targets=page.locator('.cbi-page-actions .cbi-button-apply')
 if not targets.count():targets=page.locator('.cbi-page-actions .cbi-button-save')
 with page.expect_response(lambda r:r.request.method=='POST' and '/cgi-bin/luci/' in r.url):targets.last.click()
 page.wait_for_load_state('networkidle')
 wait(lambda:page.locator('.cbi-value-error,.cbi-section-error,.cbi-input-invalid').count()>0,10)
def ports_reject():
 old=config()[section('global_forwarding')]['tcp_redir_ports']
 go('other');fill('tcp_redir_ports','not-a-port');raw_submit_error();assert config()[section('global_forwarding')]['tcp_redir_ports']==old
 go('other');fill('tcp_redir_ports','80-90,85:100,443,80');submit()
 assert config()[section('global_forwarding')]['tcp_redir_ports']=='80:100,443'
 assert json.loads(ssh('lua /usr/share/passwall/process.lua status'))['last_error']==''
 go('other');fill('tcp_redir_ports',old);submit()
check('GUI rejects bad ports; overlaps and hyphens normalize without NFT failure',ports_reject)
def dns_reject():
 old=config()[section('global')]
 go('settings');tab('DNS');select('dns_mode','tcp');fill('remote_dns','not-an-ip');raw_submit_error()
 c=config()[section('global')];assert c['remote_dns']==old['remote_dns'] and c['dns_mode']==old['dns_mode']
 go('settings');tab('DNS');select('dns_mode','xray');select('xray_dns_mode','tcp+doh');fill('remote_dns_doh','http://example.com/dns-query');raw_submit_error()
 c=config()[section('global')];assert c['dns_mode']==old['dns_mode']
check('GUI invalid DNS IP and non-HTTPS DoH rejected without partial UCI save',dns_reject)
def exclude_preserve():
 go('other');flag('sniffing_override_dest',True);field('excluded_domains','textarea').fill('ui-preserved.example\n');submit()
 go('other');flag('sniffing_override_dest',False);submit();assert ssh('cat /usr/share/passwall/rules/domains_excluded')=='ui-preserved.example'
 go('other');flag('sniffing_override_dest',True);submit();assert 'ui-preserved.example' in field('excluded_domains','textarea').input_value()
 field('excluded_domains','textarea').fill('');submit();assert ssh('cat /usr/share/passwall/rules/domains_excluded')==''
check('hide/re-enable preserves excluded file; explicit empty clears it',exclude_preserve)
def clear_file_lists():
 saved={key:ssh('cat /usr/share/passwall/rules/'+key)+'\n' for key in ['direct_host','direct_ip','proxy_host','proxy_ip','block_host','block_ip']}
 go('rule')
 for pane,keys in [('direct_list',['direct_host','direct_ip']),('proxy_list',['proxy_host','proxy_ip']),('block_list',['block_host','block_ip'])]:
  tab(pane)
  for key in keys:field(key,'textarea').fill('')
 submit()
 assert all(ssh('cat /usr/share/passwall/rules/'+k)=='' for k in saved)
 go('rule')
 for pane,keys in [('direct_list',['direct_host','direct_ip']),('proxy_list',['proxy_host','proxy_ip']),('block_list',['block_host','block_ip'])]:
  tab(pane)
  for key in keys:field(key,'textarea').fill(saved[key])
 submit()
check('GUI can clear and restore all six editable rule lists',clear_file_lists)
