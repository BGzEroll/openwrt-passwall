ids=json.loads((ROOT/'ids.json').read_text())
def set_members(nid,member):
 go('node_config/'+nid);root=page.locator('.cbi-value[id$="-xray_balancing_node"]')
 while root.locator('.cbi-dynlist > .item').count():
  item=root.locator('.cbi-dynlist > .item').first;item.focus();item.press('Delete')
 root.locator('.cbi-dropdown .open').click();root.locator(f'li[data-value="{member}"]').filter(visible=True).first.click();page.mouse.click(5,5);submit()
def selections(names):
 for b in page.locator('[data-node-select]').all():b.set_checked(b.get_attribute('data-section') in names)
def auth_and_guard():
 auth=node_create('UI auth SOCKS','socks',{'xray_port':'20193','xray_username':'demo','xray_password':'ui-test-password'})
 ids['auth']=auth;(ROOT/'ids.json').write_text(json.dumps(ids))
 go('node_list');b=page.locator(f'[data-test="url"][data-section="{auth}"]');b.click();wait(lambda:'ms' in b.inner_text() or b.inner_text()=='超时',25);assert 'ms' in b.inner_text()
 set_members(ids['_balancing'],auth)
 go('node_list');row=page.locator('tr.cbi-section-table-row').filter(has=page.locator(f'[data-node-section="{auth}"]'))
 row.locator('.cbi-button-remove').click();page.wait_for_load_state('networkidle')
 wait(lambda:'仍在引用' in page.locator('body').inner_text());assert auth in config()
 selections([auth])
 dialog_start=len(dialogs)
 with page.expect_response(lambda r:'/delete_select_nodes?' in r.url) as response:page.locator('[data-node-action="delete-selected"]').click()
 assert response.value.status==409;assert auth in config()
 wait(lambda:any('仍在引用' in d for d in dialogs[dialog_start:]),10)
 go('node_list');selections([auth,ids['_balancing']])
 with page.expect_response(lambda r:'/delete_select_nodes?' in r.url) as response:page.locator('[data-node-action="delete-selected"]').click()
 assert response.value.status==200
 wait(lambda:auth not in config() and ids['_balancing'] not in config())
 wait(lambda:json.loads(ssh('lua /usr/share/passwall/process.lua status'))['service_status']=='running')
check('GUI auth SOCKS live flow; single/bulk reference rejection and internal-group deletion',auth_and_guard)
def chain():
 nid=node_create('UI chained SOCKS','socks',{'select:xray_to_node':ids['http']})
 ids['chain']=nid;(ROOT/'ids.json').write_text(json.dumps(ids))
 go('node_list');b=page.locator(f'[data-test="url"][data-section="{nid}"]');b.click();wait(lambda:'ms' in b.inner_text() or b.inner_text()=='超时',25);assert 'ms' in b.inner_text(),b.inner_text()
 selections([ids['http']])
 dialog_start=len(dialogs)
 with page.expect_response(lambda r:'/delete_select_nodes?' in r.url) as response:page.locator('[data-node-action="delete-selected"]').click()
 assert response.value.status==409;assert 'to_node' in response.value.json()['message']
 wait(lambda:any('to_node' in d for d in dialogs[dialog_start:]),10)
 go('node_list');selections([nid]);page.locator('[data-node-action="delete-selected"]').click();wait(lambda:nid not in config())
check('GUI one-hop chain real URL flow and to_node delete protection',chain)
def selection_cancel():
 global dialog_accept
 go('node_list');page.locator('[data-node-action="toggle-all"]').click();assert all(b.is_checked() for b in page.locator('[data-node-select]').all())
 page.locator('[data-node-action="toggle-all"]').click();assert not any(b.is_checked() for b in page.locator('[data-node-select]').all())
 page.locator('[data-node-action="delete-selected"]').click();assert dialogs[-1]=='请先选择节点'
 before=ordered('nodes');dialog_accept=False;page.locator('[data-node-action="clear-all"]').click();dialog_accept=True
 assert ordered('nodes')==before
check('GUI select all/none, no-selection hint, cancel clear leaves config untouched',selection_cancel)
