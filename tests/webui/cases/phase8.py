ids=json.loads((ROOT/'ids.json').read_text())
def rule_update():
 go('rule');tab('update')
 for key,name in [('gfwlist_url','gfw'),('chnroute_url','cn4'),('chnroute6_url','cn6')]:dyn_set(key,[f'http://{HTTP_HOST}:20181/{name}.txt'])
 flag('auto_update',True);select('week_update','7');select('time_update','6');submit()
 update(['gfwlist','chnroute','chnroute6'])
 assert ssh('cat /usr/share/passwall/rules/gfwlist')=='ui-two.example\nui-update.example'
 assert '2001:db8:1111::/48' in ssh('cat /usr/share/passwall/rules/chnroute6')
 c=config()[section('global_rules')]
 assert all(c[k+'_update']=='1' for k in ['gfwlist','chnroute','chnroute6'])
 assert 'rule_update' in ssh('cat /etc/crontabs/root')
 go('rule');tab('gfw_list');wait(lambda:'ui-update.example' in page.locator('.passwall-rule-lazy-list[data-rule-tab="gfw_list"] textarea').input_value())
 tab('update');update(['gfwlist']);c=config()[section('global_rules')]
 assert c['gfwlist_update']=='1' and c['chnroute_update']=='0' and c['chnroute6_update']=='0'
 # Update with unchanged data must preserve the core processes.
 before=ssh("ubus call service list '{\"name\":\"passwall\"}'")
 update(['gfwlist']);assert before==ssh("ubus call service list '{\"name\":\"passwall\"}'")
 choose([]);page.locator('[data-rule-update-start]').click();assert '请先选择' in page.locator('[data-rule-update-status]').inner_text()
check('GUI rule URLs/schedule, all/single/unchanged/no selection and lazy refresh',rule_update)
def failure_urls():
 original=ssh('sha256sum /usr/share/passwall/rules/gfwlist')
 for filename in ['empty.txt','missing-404.txt']:
  go('rule');tab('update');dyn_set('gfwlist_url',[f'http://{HTTP_HOST}:20181/{filename}']);submit()
  update(['gfwlist'],'failed');assert original==ssh('sha256sum /usr/share/passwall/rules/gfwlist')
 go('rule');tab('update');dyn_set('gfwlist_url',[f'http://{HTTP_HOST}:20181/gfw.txt']);flag('auto_update',False);submit()
 assert not any('rule_update' in l for l in ssh('cat /etc/crontabs/root').splitlines())
check('GUI update empty/HTTP404 preserves files, shows failure; disable cron',failure_urls)
