ids=json.loads((ROOT/'ids.json').read_text())
def status():return json.loads(ssh('lua /usr/share/passwall/process.lua status'))
def running():return status().get('service_status')=='running'
def pids():return json.loads(ssh("ubus call service list '{\"name\":\"passwall\"}'"))
def enable():
 go('settings');select('tcp_node',ids['socks']);select('udp_node','tcp');flag('enabled',True)
 tab('DNS');select('direct_dns_mode','udp');fill('direct_dns_udp','192.168.114.1');select('dns_mode','udp');fill('remote_dns','192.168.114.1');submit()
 wait(running);assert ssh("curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}'")=='204'
 go('settings');wait(lambda:page.locator('#status_tcp').get_attribute('data-state')=='running',15)
check('enable TCP+UDP from GUI and actual 1070 HTTPS',enable)
def latency():
 go('node_list');assert page.locator('tr.passwall-node-active').count()==1
 for mode in ['icmp','tcping','url']:
  b=page.locator(f'[data-test="{mode}"]').first;b.click()
  wait(lambda:'ms' in b.inner_text() or b.inner_text() in ['超时','错误'],40)
  assert 'ms' in b.inner_text(),(mode,b.inner_text())
  assert b.evaluate('(e)=>e.style.color')=='green'
check('active node background and real Ping/TCP/URL green ms',latency)
def log_options():
 before=pids()
 go('log');flag('log_tcp',True);flag('log_udp',True);select('loglevel','debug');flag('log_debug',True);submit()
 wait(lambda:config()[section('global')]['log_tcp']=='1')
 wait(lambda:ssh('test -e /tmp/etc/passwall/acl/default/TCP.log && echo yes')=='yes',20)
 runtime=json.loads(ssh('cat /tmp/etc/passwall/acl/default/TCP.json'))
 assert runtime['log']['loglevel']=='debug',runtime.get('log')
 go('log');page.locator('#log_source').select_option('TCP');wait(lambda:len(page.locator('#log_textarea').input_value())>0,20)
 assert page.locator('#log_clear').is_disabled()
 page.locator('#log_pause').click();assert '继续' in page.locator('#log_pause').inner_text()
 page.locator('#log_pause').click();page.locator('#log_source').select_option('UDP')
 page.locator('#log_source').select_option('runtime');page.locator('#log_pause').click();page.locator('#log_clear').click()
 wait(lambda:'已清空' in page.locator('#log_feedback').inner_text())
 assert page.locator('#log_textarea').input_value()==''
 flag('log_tcp',False);flag('log_udp',False);select('loglevel','warning');flag('log_debug',False);submit();wait(running)
check('log settings apply to actual core; sources/pause/resume/clear',log_options)
