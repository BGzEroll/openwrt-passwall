def large_lists():
 go('rule');tab('update')
 for key,name in [('gfwlist_url','gfwlist'),('chnroute_url','chnroute'),('chnroute6_url','chnroute6')]:dyn_set(key,[f'http://{HTTP_HOST}:20181/large-{name}.txt'])
 submit();update(['gfwlist','chnroute','chnroute6'])
 go('rule')
 for pane,name in [('gfw_list','gfwlist'),('chnroute_list','chnroute'),('chnroute6_list','chnroute6')]:
  tab(pane);root=page.locator(f'.passwall-rule-lazy-list[data-rule-tab="{pane}"]');wait(lambda:root.locator('textarea').input_value()!='')
  text=root.locator('textarea').input_value();assert len(text.splitlines())>100,(name,len(text))
  assert root.locator('textarea').bounding_box()['width']>800
check('GUI full-size real rule publication and wide lazy editors',large_lists)
