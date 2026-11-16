ids=json.loads((ROOT/'ids.json').read_text())
def traffic(name,port,tls=False,auth=False):
 nid=ids[name];go('node_config/'+nid);fill('xray_port',str(port))
 if name not in ['http']:select('xray_transport','tcp')
 if name=='vless':select('xray_transport','tcp')
 flag('xray_tls',tls)
 if tls:fill('xray_tls_serverName','example.com');flag('xray_tls_allowInsecure',True)
 if auth:fill('xray_username','demo');fill('xray_password','ui-test-password')
 submit()
 go('node_list');b=page.locator(f'[data-test="url"][data-section="{nid}"]');b.click()
 wait(lambda:'ms' in b.inner_text() or b.inner_text() in ['超时','错误'],25)
 assert 'ms' in b.inner_text(),(name,tls,b.inner_text())
 assert b.evaluate('(e)=>e.style.color')=='green'
for n,port,tls in [('http',20191,False),('http',20192,True),('vmess',20194,False),('vless',20195,False),('vless',20198,True),('trojan',20196,True),('shadowsocks',20197,False)]:
 check(f'GUI {n} TLS={tls}: real local protocol handshake+HTTPS URL test',lambda n=n,p=port,t=tls:traffic(n,p,t))
