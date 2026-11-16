ids=json.loads((ROOT/'ids.json').read_text())
def url_live(nid):
 go('node_list');b=page.locator(f'[data-test="url"][data-section="{nid}"]');b.click();wait(lambda:b.get_attribute('aria-disabled')=='false',25);assert 'ms' in b.inner_text(),b.inner_text()
def mux_vision():
 nid=ids['vless'];go('node_config/'+nid);select('xray_transport','tcp');flag('xray_tls',True);flag('xray_reality',False);fill('xray_tls_serverName','example.com');flag('xray_tls_allowInsecure',True);fill('xray_port','20198');select('xray_flow','');flag('xray_mux',True);fill('xray_mux_concurrency','3');flag('xray_utls',True);select('xray_fingerprint','chrome');flag('xray_tcpNoDelay',True);submit()
 data=generate(nid);out=next(o for o in data['outbounds'] if o['protocol']=='vless');assert out['mux']['concurrency']==3 and out['streamSettings']['tlsSettings']['fingerprint']=='chrome';url_live(nid)
 go('node_config/'+nid);select('xray_flow','xtls-rprx-vision');fill('xray_port','20199');flag('xray_xmux',True);fill('xray_xudp_concurrency','4');submit()
 data=generate(nid);out=next(o for o in data['outbounds'] if o['protocol']=='vless');assert out['mux']['concurrency']==-1 and out['mux']['xudpConcurrency']==4;url_live(nid)
check('GUI TLS/uTLS/TCPNoDelay/Mux and Vision/XUDP values plus actual HTTPS',mux_vision)
def reality_values():
 nid=ids['vless'];go('node_config/'+nid);flag('xray_reality',True);fill('xray_reality_publicKey','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');fill('xray_reality_shortId','0123456789abcdef');fill('xray_reality_spiderX','/ui');select('xray_fingerprint','firefox');submit()
 out=next(o for o in generate(nid)['outbounds'] if o['protocol']=='vless');assert out['streamSettings']['security']=='reality';assert out['streamSettings']['realitySettings']['shortId']=='0123456789abcdef'
 go('node_config/'+nid);flag('xray_reality',False);submit()
 go('node_config/'+ids['wireguard']);assert not field('xray_tcpNoDelay','input[type=checkbox]').count();assert not field('xray_tcpMptcp','input[type=checkbox]').count()
check('GUI REALITY field mapping/run-test; inapplicable WG TCP controls hidden',reality_values)
def balancers():
 nid=ids['bal_b']
 for strategy in ['random','roundRobin','leastPing']:
  go('node_config/'+nid);select('xray_balancingStrategy',strategy);select('xray_fallback_node',ids['socks'])
  if strategy=='leastPing':flag('xray_useCustomProbeUrl',True);fill('xray_probeUrl','https://www.gstatic.com/generate_204');fill('xray_probeInterval','10s')
  submit();data=generate(nid);assert data['routing']['balancers'][0]['strategy']['type']==strategy;url_live(nid)
 go('node_config/'+nid);select('xray_fallback_node','');submit();assert 'fallback_node' not in config()[nid]
check('GUI balancing random/roundRobin/leastPing, custom probe and optional fallback',balancers)
