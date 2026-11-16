def runtime_state():
    return json.loads(ssh('lua /usr/share/passwall/process.lua status'))


def live_pids():
    data = json.loads(ssh('ubus call service list \'{"name":"passwall"}\''))
    return {name: instance['pid'] for name, instance in data['passwall']['instances'].items()}


def deferred_node_actions():
    nid = node_create('Pending delete regression')
    (ROOT / 'node-id').write_text(nid)
    output = ssh('PASSWALL_TEST_ROUTER=1 sh /tmp/passwall-test-url-lock.sh ' + nid)
    assert 'PASS:' in output, output
    go('settings')
    select('tcp_node', nid)
    select('udp_node', 'tcp')
    flag('enabled', True)
    tab('DNS')
    flag('dns_redirect', True)
    submit()
    wait(lambda: runtime_state()['service_status'] == 'running')
    assert ssh('test -s /var/run/passwall/hosts.sha256 && echo exists') == 'exists'
    previous = live_pids()

    go('settings')
    tab('DNS')
    flag('dns_redirect', False)
    submit(False)
    # The rule worker uses a separate UCI session; it must preserve this Save.
    ssh('lua /usr/share/passwall/rule_update.lua prepare gfwlist')
    assert config()[section('global')].get('dns_redirect', '1') == '1'
    go('node_list')
    page.locator(f'[data-node-select][data-section="{nid}"]').check()
    page.locator('[data-node-action="delete-selected"]').click()
    wait(lambda: page.locator(f'[data-node-select][data-section="{nid}"]').count() == 0)
    page.wait_for_load_state('networkidle')
    assert nid in config()
    assert config()[section('global')].get('dns_redirect', '1') == '1'
    assert live_pids() == previous
    submit()
    wait(lambda: nid not in config())
    assert config()[section('global')].get('dns_redirect', '1') == '0'
    wait(lambda: runtime_state()['service_status'] == 'running')

    nid = node_create('Pending clear regression')
    previous = live_pids()
    go('settings')
    tab('DNS')
    flag('dns_redirect', True)
    submit(False)
    go('node_list')
    page.locator('[data-node-action="clear-all"]').click()
    wait(lambda: page.locator('[data-node-select]').count() == 0)
    page.wait_for_load_state('networkidle')
    assert nid in config()
    assert config()[section('global')]['enabled'] == '1'
    assert config()[section('global')].get('dns_redirect', '1') == '0'
    assert runtime_state()['service_status'] == 'running'
    assert live_pids() == previous
    submit()
    wait(lambda: not ordered('nodes'))
    assert config()[section('global')].get('dns_redirect', '1') == '1'
    assert runtime_state()['service_status'] == 'disabled'
    assert ssh('test ! -e /var/run/passwall/hosts.sha256 && echo removed') == 'removed'


check('test lock ownership, deferred bulk delete/clear, explicit Apply and Hosts cleanup', deferred_node_actions)
