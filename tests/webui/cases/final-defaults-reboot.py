# Run on a freshly initialized, empty default profile with upstream fixture20180.
def state():
    return json.loads(ssh('lua /usr/share/passwall/process.lua status'))


def new_defaults():
    go('settings')
    tab('Proxy')
    assert field('localhost_proxy', 'input[type=checkbox]').is_checked()
    go('other')
    assert field('start_delay').input_value() == '0'
    go('settings')
    flag('enabled', True)
    submit()
    wait(lambda: state()['service_status'] == 'running')
    assert 'Name:' in ssh('nslookup example.com 127.0.0.1 2>&1 || true')


check('fresh defaults: local proxy on, delay0, zero-node DNS usable', new_defaults)


def clear_create_enable():
    go('node_list')
    page.locator('[data-node-action="clear-all"]').click()
    wait(lambda: state()['service_status'] == 'disabled')
    assert not ordered('nodes')
    nid = node_create('Final WebUI SOCKS')
    go('settings')
    select('tcp_node', nid)
    select('udp_node', 'tcp')
    flag('enabled', True)
    tab('DNS')
    select('dns_shunt', 'dnsmasq')
    select('dns_mode', 'udp')
    select('direct_dns_mode', 'udp')
    fill('direct_dns_udp', '192.168.114.1')
    fill('remote_dns', '192.168.114.1')
    submit()
    wait(lambda: state()['service_status'] == 'running')
    assert ssh("curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}'") == '204'


check('GUI clear all, fresh Add, Save/Apply and enable real proxy flow', clear_create_enable)


def zero_delay_reboot():
    gateway = ssh("ip -6 route show default | head -1 | sed -n 's/.* via \\([^ ]*\\).*/\\1/p'")
    go('other')
    flag('iproute_shunt', True)
    fill('iproute_shunt_gw_v4', '192.168.114.1')
    fill('iproute_shunt_gw_v6', gateway)
    fill('iproute_shunt_interface', 'eth0')
    submit()
    wait(lambda: state()['forwarding_mode'] == 'PBR' and state()['service_status'] == 'running')
    boot = ssh('cat /proc/sys/kernel/random/boot_id')
    page.goto(BASE.split('/admin/')[0] + '/admin/system/reboot', wait_until='networkidle')
    page.locator('button.cbi-button-action').click()
    wait(lambda: ssh('cat /proc/sys/kernel/random/boot_id') != boot, 120)
    wait(lambda: state()['service_status'] == 'running', 90)
    assert state()['forwarding_mode'] == 'PBR'
    assert config()[section('global_delay')]['start_delay'] == '0'
    assert config()[section('global')]['localhost_proxy'] == '1'
    assert ssh("curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:1070 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}'") == '204'
    assert 'Name:' in ssh('nslookup example.com 127.0.0.1 2>&1 || true')
    assert context.request.post(BASE + 'settings', form={'luci_username': 'root', 'luci_password': ''}).ok
    go('settings')
    wait(lambda: page.locator('#status_tcp').get_attribute('data-state') == 'running', 15)


check('native GUI reboot with delay0 and local proxy1 restores PBR, DNS and HTTPS', zero_delay_reboot)
