def dns_response():
    name = 'pw-dns-choice-' + str(time.time_ns()) + '.example.org'
    return ssh('nslookup ' + name + ' 127.0.0.1 2>&1')


def pids():
    live = json.loads(ssh('ubus call service list \'{"name":"passwall"}\''))
    return {name: item['pid'] for name, item in live['passwall']['instances'].items()}


def default_dns_reload():
    nid = node_create('Default DNS reload regression')
    go('settings')
    select('tcp_node', nid)
    select('udp_node', 'tcp')
    flag('enabled', True)
    tab('Proxy')
    flag('localhost_proxy', False)
    tab('DNS')
    select('dns_shunt', 'dnsmasq')
    select('dns_mode', 'udp')
    select('direct_dns_mode', 'udp')
    fill('direct_dns_udp', HTTP_HOST + '#20531')
    fill('remote_dns', HTTP_HOST + '#20532')
    select('use_default_dns', 'direct')
    submit()
    assert '8.8.8.8' in dns_response()
    before = pids()
    # Repeat remote -> direct to catch accidentally persisting a stale choice.
    for choice, answer, port in [('remote', '9.9.9.9', '20532'), ('direct', '8.8.8.8', '20531'), ('remote', '9.9.9.9', '20532')]:
        go('settings')
        tab('DNS')
        select('use_default_dns', choice)
        submit()
        assert config()[section('global')]['use_default_dns'] == choice
        entry = ssh('cat /tmp/dnsmasq.d/dnsmasq-passwall.conf')
        assert 'server=' + HTTP_HOST + '#' + port in entry, entry
        assert answer in dns_response()
        assert pids() == before
    for reason in ['config', 'network', 'rules']:
        ssh('/etc/init.d/passwall reload ' + reason)
        assert '9.9.9.9' in dns_response()
        assert pids() == before
    assert ssh('test ! -e /var/run/passwall/runtime/USE_DEFAULT_DNS && echo removed') == 'removed'

    go('settings')
    tab('DNS')
    select('dns_shunt', 'chinadns-ng')
    submit()
    china = ssh('cat /var/run/passwall/runtime/CHINADNS_DNS')
    assert china.startswith('127.0.0.1#')
    before = pids()
    for reason in ['config', 'rules']:
        ssh('/etc/init.d/passwall reload ' + reason)
        assert 'server=' + china in ssh('cat /tmp/dnsmasq.d/dnsmasq-passwall.conf')
        response = dns_response()
        assert '8.8.8.8' in response or '9.9.9.9' in response, response
        assert pids() == before


check('default DNS switches immediately without core restart; ChinaDNS delegation survives reload', default_dns_reload)
