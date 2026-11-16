def repeat_updates():
 go('rule');tab('update')
 for i in range(20):
  update(['gfwlist'])
  r=context.request.get(BASE+'index_status');assert r.status==200 and r.json()['service_status']=='running',(i,r.text())
 print('20 real GUI update jobs completed without HTTP500',flush=True)
check('20 consecutive GUI updates + status polling under child exits',repeat_updates)
def concurrent_tabs():
 go('rule');tab('update');dyn_set('gfwlist_url',[f'http://{HTTP_HOST}:20183/slow-gfw.txt']);submit()
 go('rule');tab('update');choose(['gfwlist'])
 second=context.new_page();second.goto(BASE+'rule',wait_until='networkidle');second.locator('li[data-tab="update"] a').click()
 for name in ['gfwlist','chnroute','chnroute6']:second.locator(f'#rule_update_actions input[type=checkbox][value="{name}"]').set_checked(name=='chnroute')
 with page.expect_response(lambda r:'/passwall/update_rules?' in r.url) as first:page.locator('[data-rule-update-start]').click()
 assert first.value.status==200
 with second.expect_response(lambda r:'/passwall/update_rules?' in r.url) as busy:second.locator('[data-rule-update-start]').click()
 assert busy.value.status==409,busy.value.text()
 assert config()[section('global_rules')]['gfwlist_update']=='1'
 assert config()[section('global_rules')]['chnroute_update']=='0'
 wait(lambda:job()['state']=='done',30);second.close()
 go('rule');tab('update');dyn_set('gfwlist_url',[f'http://{HTTP_HOST}:20181/gfw.txt']);submit()
check('two legitimate GUI tabs race: second job busy, selection unchanged',concurrent_tabs)
