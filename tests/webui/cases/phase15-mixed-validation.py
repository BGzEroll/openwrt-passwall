def mixed_validation():
 old_host=ssh('cat /usr/share/passwall/rules/direct_host')+'\n';old_ip=ssh('cat /usr/share/passwall/rules/direct_ip')+'\n'
 try:
  go('rule');tab('direct_list');field('direct_host','textarea').fill('ui-valid-before-invalid.example\n');field('direct_ip','textarea').fill('not-an-IP\n')
  with page.expect_response(lambda r:r.request.method=='POST' and '/passwall/rule' in r.url):page.locator('.cbi-page-actions .cbi-button-apply').last.click()
  page.wait_for_load_state('networkidle');page.wait_for_timeout(700)
  assert page.locator('.cbi-value-error,.cbi-section-error').count()>0
  assert ssh('cat /usr/share/passwall/rules/direct_host').strip()==old_host.strip(),'Rejected GUI form still wrote an earlier valid rule file'
 finally:
  go('rule');tab('direct_list');field('direct_host','textarea').fill(old_host);field('direct_ip','textarea').fill(old_ip);submit()
check('rejected GUI form must not partially write valid rule fields',mixed_validation)
