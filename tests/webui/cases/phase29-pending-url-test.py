def pending_url_test():
    nid = node_create('Committed endpoint for snapshot test', fields={'xray_port': '20179'})
    before = ssh('sha256sum /etc/config/passwall')
    go('node_config/' + nid)
    fill('xray_port', '20180')
    submit(False)
    assert config()[nid]['port'] == '20179'
    go('node_list')
    button = page.locator(f'[data-test="url"][data-section="{nid}"]')
    button.click()
    wait(lambda: button.get_attribute('aria-disabled') == 'false', 25)
    assert 'ms' in button.inner_text(), button.inner_text()
    assert before == ssh('sha256sum /etc/config/passwall')

    # The new node exists only in this browser's saved session.
    page.locator('input[value="添加"]').click()
    page.wait_for_url('**/node_config/*', wait_until='networkidle')
    fresh = page.url.rsplit('/', 1)[1]
    fill('remarks', 'Save-only URL test')
    select('xray_protocol', 'socks')
    fill('xray_address', '127.0.0.1')
    fill('xray_port', '20180')
    submit(False)
    assert fresh not in config()
    go('node_list')
    button = page.locator(f'[data-test="url"][data-section="{fresh}"]')
    button.click()
    wait(lambda: button.get_attribute('aria-disabled') == 'false', 25)
    assert 'ms' in button.inner_text(), button.inner_text()
    assert before == ssh('sha256sum /etc/config/passwall')

    # A pending balancer also needs its list values and pending dependencies.
    page.locator('input[value="添加"]').click()
    page.wait_for_url('**/node_config/*', wait_until='networkidle')
    group = page.url.rsplit('/', 1)[1]
    fill('remarks', 'Save-only balancing test')
    select('xray_protocol', '_balancing')
    dyn_add('xray_balancing_node', fresh)
    select('xray_balancingStrategy', 'random')
    submit(False)
    go('node_list')
    button = page.locator(f'[data-test="url"][data-section="{group}"]')
    button.click()
    wait(lambda: button.get_attribute('aria-disabled') == 'false', 25)
    assert 'ms' in button.inner_text(), button.inner_text()
    codes = page.evaluate('''async url => Promise.all([0, 1].map(async index => {
        const response = await fetch(url + '&request=' + index, {cache: 'no-store'});
        await response.text();
        return response.status;
    }))''', BASE + 'urltest_node?id=' + group)
    assert sorted(codes) == [200, 429], codes
    assert before == ssh('sha256sum /etc/config/passwall')
    assert ssh('find /tmp -maxdepth 1 -name "passwall-url-config.*" -type d') == ''


check('Save-only edits and new nodes test current session without committing', pending_url_test)
