ids=json.loads((ROOT/'ids.json').read_text())
def balancing_create(label):
 go('node_list');page.locator('input[value="添加"]').click();page.wait_for_url('**/node_config/*',wait_until='networkidle');nid=page.url.rsplit('/',1)[1]
 fill('remarks',label);select('xray_protocol','_balancing');root=page.locator('.cbi-value[id$="-xray_balancing_node"]');root.locator('.cbi-dropdown .open').click();root.locator(f'li[data-value="{ids["socks"]}"]').filter(visible=True).first.click();page.mouse.click(5,5);select('xray_balancingStrategy','random')
 assert field('xray_fallback_node','select').input_value()=='','new balancer unexpectedly defaults to a fallback dependency'
 submit();assert not config()[nid].get('fallback_node'),config()[nid];return nid
def stale_fallback():
 a=balancing_create('UI fallback A');b=balancing_create('UI fallback B');ids.update(bal_a=a,bal_b=b);(ROOT/'ids.json').write_text(json.dumps(ids))
 go('node_config/'+a);second=context.new_page();second.goto(BASE+'node_config/'+b,wait_until='networkidle')
 select('xray_fallback_node',b);submit()
 second.locator('select[name$=".xray_fallback_node"]').select_option(a)
 with second.expect_response(lambda r:r.request.method=='POST' and '/node_config/' in r.url):second.locator('.cbi-page-actions .cbi-button-apply').last.click()
 second.wait_for_load_state('networkidle');second.wait_for_timeout(500)
 assert second.locator('.cbi-value-error,.cbi-section-error').count()>0
 assert config()[b].get('fallback_node')!=a
 second.close();go('node_config/'+b)
 assert a not in field('xray_fallback_node','select').locator('option').evaluate_all('(xs)=>xs.map(x=>x.value)')
check('two stale GUI fallback forms cannot commit a balancer cycle',stale_fallback)
