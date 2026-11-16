ids=json.loads((ROOT/'ids.json').read_text())
def parallel_url_tests():
 go('node_list')
 valid=ids['socks'];bad=ids['wireguard']
 url_responses=[]
 def capture_response(response):
  if 'urltest_node' in response.url:url_responses.append(response.status)
 page.on('response',capture_response)
 page.evaluate('ids=>ids.forEach(id=>document.querySelector(`[data-test="url"][data-section="${id}"]`).click())',[valid,bad])
 wait(lambda:429 in url_responses,15)
 wait(lambda:any(page.locator(f'[data-test="url"][data-section="{nid}"]').inner_text()=='稍后重试' for nid in [valid,bad]),10)
 retry_nodes=[nid for nid in [valid,bad] if page.locator(f'[data-test="url"][data-section="{nid}"]').inner_text()=='稍后重试']
 assert len(retry_nodes)==1,[(nid,page.locator(f'[data-test="url"][data-section="{nid}"]').inner_text()) for nid in [valid,bad]]
 wait(lambda:all(page.locator(f'[data-test="url"][data-section="{nid}"]').get_attribute('aria-disabled')=='false' for nid in [valid,bad]),25)
 retry_button=page.locator(f'[data-test="url"][data-section="{retry_nodes[0]}"]')
 assert '稍后重试' in retry_button.get_attribute('title')
 retry_response_start=len(url_responses);retry_button.click()
 wait(lambda:retry_button.get_attribute('aria-disabled')=='false' and retry_button.inner_text()!='检测中…',25)
 wait(lambda:200 in url_responses[retry_response_start:],10)
 assert retry_button.inner_text()!='稍后重试'
 page.wait_for_timeout(1000)
 ports=json.loads(ssh("lua -e 'local f=require(\"nixio.fs\");local j=require(\"luci.jsonc\");local r={};for p in f.glob(\"/tmp/passwall-urltest.*/test.json\") do local d=j.parse(f.readfile(p));r[#r+1]=d.inbounds[1].port end;print(j.stringify(r))'"))
 assert len(ports)==len(set(ports)),('concurrent URL tests allocated the same local SOCKS port',ports)
 for nid in [valid,bad]:
  b=page.locator(f'[data-test="url"][data-section="{nid}"]')
  wait(lambda b=b:b.get_attribute('aria-disabled')=='false',25)
 assert 'ms' not in page.locator(f'[data-test="url"][data-section="{bad}"]').inner_text()
 page.remove_listener('response',capture_response)
check('simultaneous legitimate URL tests must not share ports or misreport a bad node',parallel_url_tests)
