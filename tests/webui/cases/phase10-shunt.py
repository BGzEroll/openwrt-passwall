ids=json.loads((ROOT/'ids.json').read_text())
def rule_create(name,remarks):
 go('rule');table=page.locator('#cbi-passwall-shunt_rules');table.locator('input[type=text]').fill(name);table.locator('input[type=text]').press('End');table.locator('input[type=submit].cbi-button-add').click()
 page.wait_for_url('**/shunt_rules/*',wait_until='networkidle');fill('remarks',remarks)
 field('domain_list','textarea').fill('domain:example.com\nfull:example.net\n# UI rule\n')
 field('ip_list','textarea').fill('192.0.2.55\n2001:db8::55\n')
 field('protocol','input[type=checkbox]').first.check()
 field('inbound','input[type=checkbox]').first.check()
 select('network','tcp');fill('port','80,443');dyn_add('source','192.168.100.2');submit()
 assert config()[name]['remarks']==remarks
check('GUI create core shunt rule with domain/IP/protocol/inbound/source/port',lambda:rule_create('ui_rule_one','UI rule one'))
def shunt_node():
 nid=node_create('UI shunt','_shunt',{'select:xray_default_node':'_direct','select:xray_ui_rule_one':ids['socks']})
 ids['shunt']=nid;(ROOT/'ids.json').write_text(json.dumps(ids));data=generate(nid)
 assert any('domain:example.com' in r.get('domains',[]) for r in data['routing']['rules'])
 go('node_config/'+nid);flag('xray_preproxy_enabled',True);select('xray_main_node',ids['http']);select('xray_ui_rule_one',ids['socks']);select('xray_ui_rule_one_proxy_tag','main');submit()
 assert config()[nid]['ui_rule_one_proxy_tag']=='main';generate(nid)
check('GUI shunt node rule mapping and preproxy persistence/generation',shunt_node)
def global_shunt():
 go('settings');select('tcp_node',ids['shunt'])
 select(ids['shunt']+'-default_node',ids['socks']);submit()
 wait(lambda:config()[ids['shunt']]['default_node']==ids['socks'])
 assert json.loads(ssh('lua /usr/share/passwall/process.lua status'))['service_status']=='running'
 # Put default path through the known-good node and disable preproxy before traffic check.
 go('settings');flag(ids['shunt']+'-preproxy_enabled',False);submit()
 go('settings');select('tcp_node',ids['socks']);submit()
check('GUI global shunt controls map to shunt node; return to normal node',global_shunt)
def rule_sort_delete():
 rule_create('ui_rule_two','UI rule two')
 go('rule');table=page.locator('#cbi-passwall-shunt_rules');table.locator('.cbi-button-up').last.click();submit()
 assert ordered('shunt_rules')[0]=='ui_rule_two'
 go('rule');page.locator('#cbi-passwall-shunt_rules .cbi-button-down').first.click();submit()
 assert ordered('shunt_rules')[0]=='ui_rule_one'
 go('rule');page.locator('input[name="cbi.rts.passwall.ui_rule_one"]').click();page.wait_for_load_state('networkidle');submit()
 c=config();assert 'ui_rule_one' not in c and 'ui_rule_one' not in c[ids['shunt']]
 assert 'ui_rule_one_proxy_tag' not in c[ids['shunt']],c[ids['shunt']]
check('GUI shunt rule sort/delete clears node mapping and proxy tag',rule_sort_delete)
