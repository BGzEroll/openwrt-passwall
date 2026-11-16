def empty_pages():
 for n in ['settings','node_list','acl','rule','other','log']:
  go(n)
  assert not errors,(n,errors)
  assert page.evaluate('document.body.scrollWidth<=innerWidth'),n
ids={}
check('default empty configuration: six pages and JS',empty_pages)
check('create SOCKS by GUI Save & Apply',lambda:ids.update(socks=node_create('UI SOCKS live')))
(ROOT/'ids.json').write_text(json.dumps(ids))
def edit_node():
 go('node_config/'+ids['socks']);fill('remarks','UI SOCKS renamed');submit(False)
 page.reload(wait_until='networkidle');assert field('remarks').input_value()=='UI SOCKS renamed'
 submit();wait(lambda:config()[ids['socks']]['remarks']=='UI SOCKS renamed')
check('node Save -> reopen -> Save & Apply persistence',edit_node)
def copy_sort_delete():
 go('node_list');page.locator('[data-node-action="copy"]').first.click();page.wait_for_url('**/node_config/*',wait_until='networkidle')
 clone=page.url.rsplit('/',1)[1];assert clone!=ids['socks'];fill('remarks','UI clone');submit()
 wait(lambda:config().get(clone,{}).get('remarks')=='UI clone')
 go('node_list')
 print('SORT CONTROLS',page.locator('.cbi-button-up,.cbi-button-down').evaluate_all('(xs)=>xs.map(x=>({name:x.name,value:x.value}))'),flush=True)
 up=page.locator('.cbi-button-up').last
 up.click();page.wait_for_load_state('networkidle');submit()
 wait(lambda:ordered('nodes')[0]==clone)
 go('node_list');page.locator('.cbi-button-down').first.click();page.wait_for_load_state('networkidle');submit()
 wait(lambda:ordered('nodes')[0]==ids['socks'])
 go('node_list');row=page.locator('tr').filter(has=page.locator(f'[data-node-section="{clone}"]'))
 row.locator('.cbi-button-remove').click();page.wait_for_load_state('networkidle');submit()
 wait(lambda:clone not in config())
check('copy, sort up/down, single delete GUI',copy_sort_delete)
