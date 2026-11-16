ids=json.loads((ROOT/'ids.json').read_text())
def http_tls():
 nid=node_create('UI HTTP TLS','http',{'flag:xray_tls':True,'xray_tls_serverName':'example.com'})
 ids['http']=nid;(ROOT/'ids.json').write_text(json.dumps(ids))
 data=generate(nid);out=next(o for o in data['outbounds'] if o['protocol']=='http')
 assert out.get('streamSettings',{}).get('security')=='tls',out
check('HTTP TLS UI settings appear in actual Xray outbound',http_tls)
