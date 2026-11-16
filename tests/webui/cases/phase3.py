ids=json.loads((ROOT/'ids.json').read_text())
def acl_create(name,mac,direct):
 go('acl');page.locator('input.cbi-button-add').click();page.wait_for_url('**/acl_config/*',wait_until='networkidle')
 aid=page.url.rsplit('/',1)[1];fill('remarks',name);dyn_add('sources',mac);flag('direct',direct)
 if not direct:
  for k,v in [('tcp_no_redir_ports','22'),('udp_no_redir_ports','53'),('tcp_proxy_drop_ports','443'),('udp_proxy_drop_ports','443'),('tcp_redir_ports','80,443'),('udp_redir_ports','53,123')]:fill(k,v)
 submit();wait(lambda:config().get(aid,{}).get('sources')==mac.upper())
 return aid
aclids=[]
check('ACL create direct MAC from empty list',lambda:aclids.append(acl_create('UI direct','02:00:00:00:01:01',True)))
check('ACL create ordinary port policy',lambda:aclids.append(acl_create('UI ports','02:00:00:00:01:02',False)))
def acl_edit():
 a,b=aclids;go('acl_config/'+a);flag('direct',False);fill('tcp_redir_ports','80-443');submit()
 wait(lambda:config()[a].get('tcp_redir_ports')=='80:443')
 go('acl_config/'+b);dyn_add('sources','02:00:00:00:01:03');submit()
 wait(lambda:'02:00:00:00:01:03' in config()[b]['sources'])
 def acl_id(remark):
  return next(k for k,v in config().items() if v.get('.type')=='acl_rule' and v.get('remarks')==remark)
 go('acl');page.locator('.cbi-button-up').last.click();submit()
 assert config()[ordered('acl_rule')[0]]['remarks']=='UI ports'
 go('acl');page.locator('.cbi-button-down').first.click();submit()
 assert config()[ordered('acl_rule')[0]]['remarks']=='UI direct'
 current_b=acl_id('UI ports')
 go('acl');box=page.locator(f'input[name$=".{current_b}.enabled"][type=checkbox]');box.uncheck();submit()
 current_b=acl_id('UI ports');assert config()[current_b]['enabled']=='0'
 for remark in ['UI direct','UI ports']:
  aid=acl_id(remark)
  go('acl');page.locator(f'input[name="cbi.rts.passwall.{aid}"]').click();page.wait_for_load_state('networkidle');submit()
  assert not any(v.get('.type')=='acl_rule' and v.get('remarks')==remark for v in config().values())
check('ACL edit multi-MAC, range normalization, sort, disable, delete',acl_edit)
