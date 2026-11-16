ids=json.loads((ROOT/'ids.json').read_text())
def save_copy():
 old=config()[section('global')].get('dns_redirect','1')
 try:
  go('settings');tab('DNS');flag('dns_redirect',old!='1');submit(False)
  assert config()[section('global')].get('dns_redirect','1')==old
  go('node_list');page.locator(f'[data-node-action="copy"][data-section="{ids["socks"]}"]').click();page.wait_for_url('**/node_config/*',wait_until='networkidle')
  clone=page.url.rsplit('/',1)[1]
  assert config()[section('global')].get('dns_redirect','1')==old,'Copy unexpectedly committed pending settings from another page'
  submit();wait(lambda:clone in config())
 finally:
  go('settings');tab('DNS');flag('dns_redirect',old=='1');submit()
check('Save-only settings stay pending while copying a node; explicit Apply commits both',save_copy)
