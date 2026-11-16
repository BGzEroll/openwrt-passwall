ids=json.loads((ROOT/'ids.json').read_text())
def domain_semantics():
 try:
  go('rule');table=page.locator('#cbi-passwall-shunt_rules');box=table.locator('input[type=text]');box.fill('ui_semantic');box.press('End');table.locator('input[type=submit].cbi-button-add').click();page.wait_for_url('**/shunt_rules/*',wait_until='networkidle')
  fill('remarks','UI domain semantics');field('domain_list','textarea').fill('full:www.google.com\n');field('inbound','input[type=checkbox]').nth(1).check();submit()
  go('node_config/'+ids['shunt']);flag('xray_preproxy_enabled',False);select('xray_default_node',ids['socks']);select('xray_ui_semantic','_blackhole');submit()
  go('settings');select('tcp_node',ids['shunt']);tab('DNS');select('dns_mode','udp');submit()
  allowed=ssh("curl -s --max-time 12 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}' || true")
  assert allowed=='204',('unmatched domain was wrongly blocked',allowed)
  blocked=ssh("curl -s --max-time 5 --socks5-hostname 127.0.0.1:1070 https://www.google.com/generate_204 -o /dev/null -w '%{http_code}' || true")
  assert blocked=='000',('matched domain was not blocked',blocked)
 finally:
  go('settings');select('tcp_node',ids['socks']);submit()
check('GUI core shunt full:domain matches only that domain in real SOCKS traffic',domain_semantics)
