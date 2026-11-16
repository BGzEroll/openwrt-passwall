ids=json.loads((ROOT/'ids.json').read_text())
def proto(name,fields):
 if name in ids:
  nid=ids[name];go('node_config/'+nid)
 else:
  go('node_list');page.locator('input[value="添加"]').click();page.wait_for_url('**/node_config/*',wait_until='networkidle')
  nid=page.url.rsplit('/',1)[1]
 fill('remarks','UI '+name);select('xray_protocol',name)
 if not name.startswith('_'):fill('xray_address','127.0.0.1');fill('xray_port','20180')
 for key,val in fields:
  if key.startswith('select:'):select(key[7:],val)
  elif key.startswith('flag:'):flag(key[5:],val)
  elif key.startswith('dyn:'):dyn_add(key[4:],val)
  else:fill(key,val)
 submit();wait(lambda:config().get(nid,{}).get('protocol')==name)
 ids[name]=nid;(ROOT/'ids.json').write_text(json.dumps(ids))
 data=generate(nid)
 assert config()[nid]['type']=='Xray'
 return data
uuid='00000000-0000-4000-8000-000000000001'
cases=[('vmess',[('xray_uuid',uuid),('select:xray_security','auto')]),('vless',[('xray_uuid',uuid),('flag:xray_tls',True),('xray_tls_serverName','example.com')]),('shadowsocks',[('select:xray_ss_method','aes-128-gcm'),('xray_password','ui-test-password')]),('trojan',[('xray_password','ui-test-password'),('flag:xray_tls',True),('xray_tls_serverName','example.com')]),('wireguard',[('xray_wireguard_secret_key','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),('xray_wireguard_public_key','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),('dyn:xray_wireguard_local_address','10.0.0.2/32'),('xray_wireguard_reserved','1,2,3')]),('_iface',[('xray_iface','lo')]),('_balancing',[('dyn:xray_balancing_node',ids['socks']),('select:xray_balancingStrategy','random')])]
for name,fields in cases:check('GUI create+persist+Xray test '+name,lambda n=name,f=fields:proto(n,f))
# Every transport is selected through the real UI on the existing VLESS node.
transports=[('tcp',[]),('mkcp',[]),('ws',[('xray_ws_host','example.com'),('xray_ws_path','/ui')]),('h2',[('xray_h2_host','example.com'),('xray_h2_path','/ui')]),('ds',[('xray_ds_path','/tmp/passwall-ui.sock')]),('quic',[('select:xray_quic_security','none')]),('grpc',[('xray_grpc_serviceName','ui'),('flag:xray_grpc_health_check',True)]),('httpupgrade',[('xray_httpupgrade_host','example.com'),('xray_httpupgrade_path','/ui')]),('splithttp',[('xray_splithttp_host','example.com'),('xray_splithttp_path','/ui')])]
for transport,extra in transports:
 def transport_case(t=transport,extra=extra):
  fields=[('xray_uuid',uuid),('select:xray_transport',t),('flag:xray_tls',False)]+extra
  data=proto('vless',fields)
  out=next(o for o in data['outbounds'] if o['protocol']=='vless')
  assert out['streamSettings']['network']==t
 check('GUI VLESS transport '+transport+' write/reopen/generate',transport_case)
