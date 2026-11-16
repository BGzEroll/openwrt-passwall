# Requires Playwright/Chromium and a dedicated OpenWrt router with no nodes.
# Writes test nodes and applies settings. Caller must back up/restore config.
from playwright.sync_api import sync_playwright
import subprocess, time, os
router=os.environ.get("PASSWALL_TEST_ROUTER")
assert router, "Set PASSWALL_TEST_ROUTER to a dedicated passwordless test router with default empty config"
base='http://'+router+'/cgi-bin/luci/admin/services/passwall/'
def ssh(cmd):return subprocess.check_output(['ssh','-o','BatchMode=yes','root@'+router,cmd],text=True).strip()
with sync_playwright() as p:
 browser=p.chromium.launch()
 context=browser.new_context()
 assert context.request.post(base+'node_list',form={'luci_username':'root','luci_password':''}).ok
 page=context.new_page()
 page.goto(base+'node_list',wait_until='networkidle')
 assert not ssh("uci -q show passwall | sed -n '/=nodes$/p'")
 page.locator('input[value="添加"]').click()
 page.wait_for_url('**/node_config/*',wait_until='networkidle')
 node=page.url.rsplit('/',1)[1]
 print('Created node',node,flush=True)
 page.locator('select[name$=".xray_protocol"]').select_option('socks')
 page.locator('input[name$=".remarks"]').fill('Fresh install UI audit')
 page.locator('input[name$=".xray_address"]').fill('192.0.2.1')
 page.locator('input[name$=".xray_port"]').fill('1080')
 page.get_by_role('button',name='Save',exact=True).last.click()
 page.wait_for_load_state('networkidle')
 time.sleep(2)
 assert not page.locator('.cbi-value-error').count(),page.locator('.cbi-value-error').all_text_contents()
 page.goto(base+'settings',wait_until='networkidle')
 page.locator('.cbi-button-apply').last.click()
 time.sleep(3)
 assert ssh('uci -q get passwall.'+node+'.type')=='Xray'
 assert ssh('uci -q get passwall.'+node+'.protocol')=='socks'
 page.goto(base+'node_config/'+node,wait_until='networkidle')
 assert page.locator('input[name$=".xray_address"]').input_value()=='192.0.2.1'
 assert page.locator('input[name$=".xray_port"]').input_value()=='1080'
 # Recreate the missing field on a previously saved node and repair it through UI Save.
 ssh('uci -q delete passwall.'+node+'.type; uci commit passwall')
 page.reload(wait_until='networkidle')
 page.get_by_role('button',name='Save',exact=True).last.click()
 page.wait_for_load_state('networkidle')
 time.sleep(2)
 page.goto(base+'settings',wait_until='networkidle')
 page.locator('.cbi-button-apply').last.click()
 time.sleep(3)
 assert ssh('uci -q get passwall.'+node+'.type')=='Xray'
 print('PASS empty defaults -> browser Add -> SOCKS Save -> reopen; existing missing type -> Save repaired',flush=True)
 result=ssh('lua /usr/lib/lua/luci/passwall/util_xray.lua gen_config -node '+node+' -local_socks_port 1077 > /tmp/passwall-node-creation-ui.json && xray run -test -c /tmp/passwall-node-creation-ui.json')
 ssh('rm -f /tmp/passwall-node-creation-ui.json')
 assert 'Configuration OK' in result,result
 print('PASS: UI-created node generates valid Xray configuration',flush=True)
 browser.close()
