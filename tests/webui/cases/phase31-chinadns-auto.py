# Requires isolated DNS fixtures on 127.0.0.2:53 and 127.0.0.3:53; see README.
def set_wan_dns(address):
    ssh('printf "# Interface wan\\nnameserver ' + address + '\\n" > /tmp/resolv.conf.d/resolv.conf.auto')


def instances():
    return json.loads(ssh('ubus call service list \'{"name":"passwall"}\''))['passwall']['instances']


def china_config():
    item = next(i for i in instances().values() if '/usr/bin/chinadns-ng' in i['command'])
    return ssh('cat ' + item['command'][item['command'].index('-C') + 1])


def upstreams():
    result, group = {}, None
    for line in china_config().splitlines():
        key, _, value = line.strip().partition(' ')
        if key == 'group':
            group = value
        elif key == 'china-dns':
            result['default'] = value
        elif key == 'group-upstream':
            result[group] = value
    return result


def query(group=''):
    suffix = (group + '.' if group else '') + 'pw-auto-dns.example.org'
    return ssh('nslookup pw' + str(time.time_ns()) + '.' + suffix + ' 127.0.0.1 2>&1')


def check_upstream(address, answer):
    values = upstreams()
    for group in ['default', 'directlist', 'vpslist']:
        assert values[group] == address + '#53', values
    assert values['proxylist'] == 'udp://127.0.0.3#53', values
    for group in ['', 'direct', 'vps']:
        assert answer in query(group)
    assert '9.9.9.9' in query('proxy')


def automatic_dns_reload():
    assert not ssh('uci -q get dhcp.@dnsmasq[0].server || true'), 'fixture requires automatic system DNS'
    set_wan_dns('127.0.0.2')
    node_create('Auto DNS hostname fixture', fields={'xray_address': 'vps.pw-auto-dns.example.org'})
    nid = node_create('Auto DNS selected node')
    go('rule')
    tab('direct_list'); field('direct_host', 'textarea').fill('direct.pw-auto-dns.example.org\n')
    tab('proxy_list'); field('proxy_host', 'textarea').fill('proxy.pw-auto-dns.example.org\n')
    submit()
    go('settings')
    select('tcp_node', nid); select('udp_node', 'tcp'); flag('enabled', True)
    tab('Proxy'); flag('localhost_proxy', False); flag('use_direct_list', True); flag('use_proxy_list', True)
    tab('DNS'); select('dns_shunt', 'chinadns-ng'); select('dns_mode', 'udp')
    select('direct_dns_mode', ''); fill('remote_dns', '127.0.0.3'); select('chinadns_ng_default_tag', 'chn')
    submit()
    check_upstream('127.0.0.2', '8.8.8.8')
    for address, answer in [('127.0.0.3', '9.9.9.9'), ('127.0.0.2', '8.8.8.8')]:
        before = instances()
        set_wan_dns(address)
        # Invoke the actual hotplug entry; do not change link or WAN connectivity.
        ssh('ACTION=ifupdate INTERFACE=wan sh /etc/hotplug.d/iface/98-passwall')
        wait(lambda: upstreams()['default'] == address + '#53', 15)
        check_upstream(address, answer)
        after = instances()
        for name, old in before.items():
            if '/usr/bin/xray' in old['command']:
                assert after[name]['pid'] == old['pid']
            elif '/usr/bin/chinadns-ng' in old['command']:
                assert after[name]['pid'] != old['pid']
        for reason in ['network', 'rules', 'config']:
            ssh('/etc/init.d/passwall reload ' + reason)
            assert {k: v['pid'] for k, v in instances().items()} == {k: v['pid'] for k, v in after.items()}
        check_upstream(address, answer)

    # A rejected replacement must preserve the previous immutable DNS snapshot.
    current = instances()
    china_name = next(k for k, i in current.items() if '/usr/bin/chinadns-ng' in i['command'])
    definition = json.loads(ssh('cat /var/run/passwall/processes/' + china_name + '.json'))
    source = definition['data']['source_config']
    ssh('cp ' + source + ' ' + source + '.test-backup; printf "invalid-auto-dns-test-option\\n" >> ' + source)
    try:
        set_wan_dns('127.0.0.3')
        result = ssh('/etc/init.d/passwall reload network >/dev/null 2>&1; printf "%s" "$?"')
        assert result != '0', 'invalid DNS candidate was accepted'
        wait(lambda: '8.8.8.8' in query(), 15)
        assert ssh('cat /var/run/passwall/runtime/LOCAL_DNS') == '127.0.0.2#53'
        for name, old in current.items():
            if '/usr/bin/xray' in old['command']:
                assert instances()[name]['pid'] == old['pid']
    finally:
        ssh('mv ' + source + '.test-backup ' + source)
        set_wan_dns('127.0.0.2')
        ssh('/etc/init.d/passwall reload network')
    check_upstream('127.0.0.2', '8.8.8.8')

    # Explicit UDP/TCP upstreams must remain fixed across WAN DNS updates.
    for mode in ['udp', 'tcp']:
        go('settings'); tab('DNS'); select('direct_dns_mode', mode)
        fill('direct_dns_' + mode, '127.0.0.2'); submit()
        before = {k: v['pid'] for k, v in instances().items()}
        set_wan_dns('127.0.0.3')
        ssh('/etc/init.d/passwall reload network')
        assert {k: v['pid'] for k, v in instances().items()} == before
        assert '8.8.8.8' in query()
        assert '9.9.9.9' in query('proxy')


check('ChinaDNS automatic upstream follows WAN DNS; fixed upstreams and proxy groups stay fixed', automatic_dns_reload)
