# nftables 与 ACL 透明代理重构说明

## 1. 目标与兼容基线

本次重构把客户端透明代理从上游 Passwall 的多后端、多模式实现，收敛为本 Fork 的专用数据面：

- 固定目标源码：`BGzEroll/immortalwrt` 的 `openwrt-23.05` 分支；
- 固定防火墙：firewall4 + nftables；
- TCP/UDP 透明代理：仅 TPROXY；
- PBR 关闭：PROXY 流量交给 OpenWrt 本机代理核心；
- PBR 开启：PROXY 流量通过策略路由交给外置透明代理网关；
- ACL：只描述设备 MAC 与端口，不再承担节点、DNS 和目的地址策略；
- DNS：只保留全局 DNS 生命周期；
- Ping hijack：只处理 IPv4/IPv6 Echo Request。

已对本机的目标源码树做只读核对：分支为 `openwrt-23.05`，`network.sh` 提供 `network_get_subnets`、`network_get_subnets6`、`network_get_device`，dnsmasq Makefile 为 2.90、`PKG_RELEASE=2`。

## 2. Before / After

### Before：TCP 双路径与每 ACL 完整策略

```text
Client
  │
  ├─ ACL source parser
  │    ├─ MAC / IPv4 / CIDR / range / ipset
  │    ├─ per-ACL node / proxy mode
  │    ├─ per-ACL five lists / China decision
  │    └─ per-ACL DNS process and temp files
  │
  ├─ TCP REDIRECT ──> PSW_NAT / PSW_OUTPUT_NAT ──> local core
  │
  └─ TCP/UDP TPROXY ──> mangle + mark/table 100 ──> local core or PBR
```

### After：MAC + ports + 唯一 Global Policy

```text
LAN packet
  │
  ├─ ether saddr @passwall_direct_macs ──> complete bypass
  │
  └─ MAC ACL dispatch
       │
       ├─ TCP/UDP Bypass Ports ──> DIRECT
       ├─ TCP/UDP Proxy Drop Ports
       └─ TCP/UDP Proxy Ports
                    │
                    ▼
           PSW_POLICY_V4 / V6
             ├─ DIRECT
             ├─ BLOCK
             └─ PROXY
                    │
                    ▼
              Proxy Action
             ┌──────┴──────┐
             │             │
         PBR OFF         PBR ON
             │             │
      local TPROXY    external route
```

TCP 不再进入 NAT REDIRECT 透明代理链。NAT `redirect` 动作仍由全局 DNS hijack 和 Ping hijack 使用。

## 3. 修改文件

### 数据面和生命周期

- `root/usr/share/passwall/nftables.sh`：重写 nftables 集合、链、ACL、目的策略、Proxy Action、DNS、Ping、本机流量、路由和 flowtable。
- `root/usr/share/passwall/app.sh`：删除 per-ACL 代理/DNS实例，强制代理核心使用 TPROXY，固定 nftables 启停路径。
- `root/usr/share/passwall/iptables.sh`：客户端入口缩减为不支持提示；仅保留独立 `passwall_server` 仍调用的 iptables 二进制查询函数。
- `root/usr/share/passwall/0_default_config`：新安装默认 nftables + TPROXY。

### LuCI 与配置关联

- `luasrc/model/cbi/passwall/client/acl.lua`
- `luasrc/model/cbi/passwall/client/acl_config.lua`
- `luasrc/model/cbi/passwall/client/global.lua`
- `luasrc/model/cbi/passwall/client/other.lua`
- `luasrc/model/cbi/passwall/client/rule_list.lua`
- `luasrc/model/cbi/passwall/client/node_list.lua`
- `luasrc/controller/passwall.lua`
- `root/usr/share/passwall/subscribe.lua`

以上文件删除了 ACL 节点关联和旧防火墙/代理方式选择，ACL 编辑页只保留 `enabled`、`remarks`、MAC、`direct` 和六项端口策略。

### 代理核心配置生成

- `luasrc/passwall/util_sing-box.lua`
- `luasrc/passwall/util_xray.lua`
- `luasrc/passwall/util_hysteria2.lua`

删除 TCP redirect inbound/config 分支，TCP inbound 固定生成 TPROXY。

### 规则维护、依赖和文档

- `root/usr/share/passwall/rule_update.lua`
- `Makefile`
- `README.md`
- `tests/test_nftables_architecture.sh`
- `tests/fixtures/nftables_rules/*`

## 4. TCP REDIRECT 清理结果

已经删除客户端透明代理中的：

- `PSW_NAT`、`PSW_OUTPUT_NAT`；
- TCP REDIRECT 的 prerouting、ACL、default、localhost 分支；
- `REDIRECT_LIST` 和基于 `is_tproxy` 的二选一；
- sing-box redirect inbound 与 Hysteria2 `tcpRedirect`；
- LuCI 的 REDIRECT/TPROXY 选择器；
- 客户端 iptables/ipset 后端选择和实现。

旧 UCI `tcp_proxy_way=redirect` 不会阻止启动。运行时打印废弃提示并强制按 TPROXY 处理。`tcp_redir_ports`/`udp_redir_ports` 仍作为第一阶段兼容 key，UI 已显示为 Proxy Ports。

## 5. 新 TCP/UDP 数据路径

### LAN ingress

```text
mangle_prerouting
  -> socket divert for established transparent TCP sockets
  -> PSW_MANGLE / PSW_MANGLE_V6
  -> Direct MAC early return
  -> global DNS port 53 early return when DNS hijack enabled
  -> first matching MAC ACL port chain, or default port chain
  -> shared PSW_POLICY_V4 / PSW_POLICY_V6
  -> protocol/family Proxy Action
```

六类端口的优先级为：

```text
Bypass Ports > Proxy Drop Ports > Proxy Ports > return
```

Proxy Drop 不会无条件丢弃端口。它先调用共享目的策略，只在目的被判定为 PROXY，或目的未命中且全局默认模式为 proxy 时 DROP；DIRECT 目的返回。

## 6. PBR OFF

```text
PROXY
  -> meta mark 0x1 + ct mark 0x1
  -> TCP/UDP TPROXY
  -> ip rule fwmark 0x1 lookup 100
  -> table 100 local 0.0.0.0/0 dev lo
  -> IPv6 对应 local ::/0 dev lo
  -> OpenWrt 本机 TCP/UDP 代理监听端口
```

PBR OFF 不创建自定义 flowtable；启动时会先删除同表旧 `ft`，路由表 100 也会重建为 local lo。

## 7. PBR ON

```text
PROXY
  -> meta mark 0x1 + ct mark 0x1
  -> ip rule / ip -6 rule
  -> table 100
  -> configured IPv4/IPv6 gateway and interface
  -> External Transparent Proxy Gateway
```

PBR ON 的四个 protocol/family Proxy Action 链只打 mark，不包含 `tproxy` 表达式。本地返回 lo 的 TPROXY 入口也不生成。

## 8. localhost

路由器本机 TCP/UDP 使用独立 `PSW_OUTPUT_MANGLE`，但调用同一端口 helper 与同一 `PSW_POLICY_V4/V6`：

- PBR OFF：output 中标记，table 100 送回 lo，prerouting 的 mark 入口执行本地 TPROXY；
- PBR ON：output 中标记，table 100 直接选择外置网关，不执行本地 TPROXY；
- `oif lo`、已有 `0x1`/`0xff` mark、上游直连 DNS、代理节点地址和代理核心专用 outbound interface 均提前返回，避免回环。

该结构覆盖需要由规则决定的本机 `curl`、`wget`、`opkg` 和 DNS 上游连接；其实际行为仍需在目标路由器上验证。

## 9. ACL 新数据模型

ACL section 现在只消费：

```text
enabled
remarks
sources             # MAC list only
direct
tcp_no_redir_ports
udp_no_redir_ports
tcp_proxy_drop_ports
udp_proxy_drop_ports
tcp_redir_ports
udp_redir_ports
```

每条 ACL 可保存多个 MAC。LuCI 使用 MAC validator，写入时转大写并去重。backend 再次过滤非法值，因此旧 IP、CIDR、range、ipset/nftset source 只会被忽略和记录，不会拼进 nft 规则。

MAC matcher 只生成：

```nft
ether saddr { AA:BB:CC:DD:EE:01, AA:BB:CC:DD:EE:02 }
```

同一 matcher 同时挂到 IPv4 与 IPv6 的 LAN prerouting 分支。output hook 不匹配客户端 MAC。

MAC-only 的支持边界是 OpenWrt 能在二层入口看到终端 MAC 的 LAN、Wi-Fi、Bridge AP、Ethernet、VLAN LAN。NAT router 后、纯三层 tunnel 或 routed subnet 中不可见的单个终端不重新使用 IP ACL 区分。

## 10. Direct ACL

所有 enabled `direct=1` ACL 的有效 MAC 先聚合到：

```nft
set passwall_direct_macs { type ether_addr; }
```

该集合在以下入口最早返回：

- `PSW_MANGLE`；
- `PSW_MANGLE_V6`；
- `dstnat`，且位置早于 Ping 和 DNS jump。

因此 Direct 同时绕过 IPv4/IPv6 TCP、UDP、DNS redirect 和 Echo Request hijack。backend 不生成 Direct ACL 的端口 chain，所以 section 中遗留的六项端口 key 全部无效。集合在普通 ACL dispatch 前完成，保证同一 MAC 同时位于 Direct 与普通 ACL 时 Direct wins。

## 11. 普通 ACL 与共享 Global Policy

普通 ACL 仅生成端口 chain。MAC dispatch 使用 `goto`，形成 first-match semantics；端口 chain 不包含任何 GFW/China/Direct/Proxy/Block/Shunt 目的规则。

全局目的分类只生成一次：

```text
PSW_POLICY_V4 / PSW_POLICY_V6
  LANLIST       -> DIRECT
  VPSLIST       -> DIRECT
  Direct List   -> DIRECT
  Block List    -> DROP
  Fake-IP(v4)   -> PROXY
  Shunt List    -> PROXY
  Proxy List    -> PROXY
  GFW List      -> PROXY
  China List    -> global direct/proxy decision
  unmatched     -> global TCP/UDP default mode
```

custom ACL、default ports、localhost、Proxy Drop 和 Ping 都调用该共享 chain，不复制五大列表。

## 12. DNS

普通 ACL 完全复用现有 Global DNS。启用全局 DNS redirect 时，TCP/UDP 53 先从 mangle 返回，再在 `dstnat` 进入 `PSW_DNS_REDIRECT`，避免 DNS 被更早的 TPROXY 捕获。Direct MAC 在两个入口都更早返回。

已删除：

- ACL 专用 dnsmasq/ChinaDNS/Xray/sing-box DNS；
- ACL DNS 端口、进程、pid、配置和临时目录生成；
- ACL-specific node/core instance 及订阅节点更新逻辑。

全局 `helper_dnsmasq.sh`、`helper_dnsmasq_add.lua` 与其注入目录语义未改。

## 13. 为什么未升级 dnsmasq 集成

兼容目标明确固定为 dnsmasq 2.90-2。此次没有引入 `get_dnsmasq_conf_dir()`，没有扫描 `/tmp/etc/dnsmasq.conf.*` 的 `conf-dir=`，没有迁移全局 Passwall dnsmasq 注入目录，也没有移植上游提交 `87051ecf1ac3acfe53a5a63e6d59a3fdc18d6453`。

这是固定 `openwrt-23.05` 的设计选择，不是本次遗漏。

## 14. Ping hijack 与 IPv6 安全

Ping 入口严格为：

```nft
ip protocol icmp icmp type echo-request
meta l4proto icmpv6 icmpv6 type echo-request
```

Echo Request 先复用共享 Global Policy：DIRECT 目标真实转发，PROXY 目标 NAT redirect；Direct MAC 在进入 Ping chain 前已返回。

规则中不再存在 `meta l4proto {icmp,icmpv6}` Ping 入口，也没有用 `ip6 nexthdr 58` 泛匹配。因此 Destination Unreachable、Packet Too Big、Time Exceeded、Parameter Problem、RS、RA、NS、NA、Redirect、MLD 等不会进入 Ping hijack，NDP/SLAAC/PMTUD 的控制平面不被此链改变。

尚未硬编码 `br-lan` 作为 Ping 入口。当前 `dstnat` 是 prerouting hook；在没有能覆盖 guest/multi-LAN/DSA/VLAN 且不会误判 WAN 的可靠设备集合前，LAN-only Ping 限制保留为明确 TODO。Echo Request-only 已完成。

## 15. 节点防回环

以下机制保留：

- `VPSLIST` / `VPSLIST6`；
- `filter_vpsip` 和 `filter_vps_addr`；
- `filter_node` 对 normal、balancing、shunt、socks 节点的 active 分支；
- sing-box/Xray 生成的 outbound interface 提前从 `PSW_OUTPUT_MANGLE` 返回。

已删除的只是 TCP REDIRECT 特有的 node output action。节点地址仍被共享目的策略判为 DIRECT，防止代理核心 outbound 再次进入 Passwall。

## 16. mark、路由与 Flow Offload

魔数集中为：

```sh
PROXY_MARK=0x1
BYPASS_MARK=0xff
PROXY_ROUTE_TABLE=100
```

PROXY action 同时设置 packet mark 和 conntrack mark。PBR flowtable 只允许：

```nft
meta mark != 0x1 ct mark != 0x1 flow add @ft
```

Direct ACL 在 mangle 入口直接返回，不获得代理 mark，可自然进入系统 normal routing/offload path。PBR OFF 会删除 PBR 专用 flowtable；stop 会删除整个 `inet passwall` 表并清空 IPv4/IPv6 table 100 与 fwmark rule。

## 17. network.sh 与 LAN 地址

LAN 地址不再依赖旧 `/tmp/state network.lan.ifname`。实现从 firewall 中名为 `lan` 的 zone 读取其 logical network，调用目标分支已有的：

- `network_get_subnets`；
- `network_get_subnets6`，包括 IPv6 prefix assignment；
- `network_get_device`，仅在 netifd 未给出 subnet 时配合 `ip address` 兜底。

另外保留 logical network `lan` fallback，避免极简 firewall 配置漏掉本机 LAN 地址。此实现支持一个 lan zone 中的多 logical network、多地址、bridge/DSA/VLAN 与动态 IPv6 前缀。

## 18. 删除的 dead code

- 约千行客户端 iptables/ipset 透明代理实现；
- nftables 万能 `REDIRECT()` action 与 TCP 双链选择；
- 数百行 `load_acl()` 完整目的策略复制；
- `acl_app()` 的 per-ACL core、SOCKS、DNS、dnsmasq、ChinaDNS 和临时文件生命周期；
- LuCI ACL 的 IP/range/ipset parser、节点、mode、list、DNS 选项；
- 清空/删除节点与订阅更新时维护 ACL node 引用的代码；
- 规则更新时的 iptables/nftables 分支；
- 代理配置生成器中的 TCP redirect 参数和 inbound。

## 19. 旧 UCI key 处理

继续消费但改名展示：

- `tcp_no_redir_ports`、`udp_no_redir_ports`；
- `tcp_redir_ports`、`udp_redir_ports`；
- `tcp_proxy_drop_ports`、`udp_proxy_drop_ports`。

兼容读取：

- `tcp_proxy_way`：非 `tproxy` 时仅提示，运行时仍强制 TPROXY；
- `use_nft`：不再用于选择客户端后端，固定 nftables。

普通 ACL 中以下历史字段被 backend 忽略，不自动迁移，也不影响启动：

```text
tcp_node / udp_node / use_global_config
use_direct_list / use_proxy_list / use_block_list / use_gfw_list / chn_list
tcp_proxy_mode / udp_proxy_mode
dns_shunt / filter_proxy_ipv6 / dns_mode / xray_dns_mode / singbox_dns_mode
remote_dns / remote_dns_doh 等 ACL DNS 字段
非 MAC sources
```

## 20. 测试与当前证据

### 已执行

```sh
sh -n luci-app-passwall/root/usr/share/passwall/app.sh
sh -n luci-app-passwall/root/usr/share/passwall/iptables.sh
sh -n luci-app-passwall/root/usr/share/passwall/nftables.sh
bash -n tests/test_nftables_architecture.sh
tests/test_nftables_architecture.sh
git diff --check
```

Lua 文件使用 `luaparser` 做了解析验证。

host-side nftables 架构测试用 mock UCI/network/nft/ip 生成 PBR OFF 和 PBR ON 两套规则，并断言：

- PBR OFF 同时生成 IPv4/IPv6 TCP/UDP TPROXY 和 local lo route；
- PBR ON 不含本地 TPROXY，生成外部 gateway route；
- 三个普通 MAC ACL 分别拥有 TCP 80/443、TCP all、UDP 53/443 端口行为；
- 同一个普通 ACL 的两个 MAC 同时 dispatch；
- Direct MAC 聚合且不生成自己的端口 chain；
- V4/V6 GFW destination rule 各只出现在一份 Global Policy 中；
- Direct、DNS、Ping、node interface bypass、flowtable mark exclusion 规则存在；
- Ping 只有明确 Echo Request 入口；
- 不存在 `PSW_NAT`、`PSW_OUTPUT_NAT`。

测试还在非特权 user/network namespace 中把 PBR OFF、PBR ON 两套规则实际装入宿主机 nftables 1.1.3 内核接口。由于 namespace 的虚拟网卡不支持硬件 offload，PBR ON 的同一 flowtable 在该子测试中仅去掉 `flags offload` 后装入；原始硬件 offload 表达式仍由 mock 输出断言覆盖，目标硬件能力需实机确认。

### 尚未形成的证据

当前环境没有目标 OpenWrt `.config`，仓库也未挂入目标 feed，因此未执行 ipk/full firmware build。目标源码打包的 nftables 是 1.0.8，而 namespace 解析/装载使用宿主机 1.1.3，仍需在目标版本复核。也未在路由器上完成 start/stop/reload/firewall reload、真实 LAN/WAN hook、IPv4/IPv6 连通、DNS、NDP/SLAAC/PMTUD、proxy core outbound 和硬件 flow offload 测试。

## 21. 风险与 TODO

1. 在目标路由器上用 `nft -c -f`/实际 start 检查目标 nft 版本的完整规则解析，再检查 `nft list table inet passwall`。
2. 验证 PBR OFF 的四类 LAN 流量和四类 localhost 流量实际进入对应本机 TPROXY socket。
3. 验证 PBR ON 的 IPv4/IPv6 下一跳、回程路由、外置网关透明代理和无本地 TPROXY。
4. 验证 Direct ACL 的 TCP、UDP、DNS、IPv4 Ping、IPv6 Ping 均真实直连，并覆盖 Direct/normal 重叠 MAC。
5. 用 RA、RS、NS、NA、Packet Too Big 和大包流量验证 IPv6 control plane/PMTUD 未进入 Ping chain。
6. 验证 normal、balancing、shunt、socks、preproxy/outbound interface 的实际节点防回环。
7. 在目标硬件验证 PBR flowtable/offload；确认 PROXY 不 offload、DIRECT 可 offload。
8. 评估 firewall zone/device 动态集合后，再实现不硬编码接口的 LAN-only Ping ingress 限制。
9. 执行重复 start/stop/reload/firewall reload，检查无 duplicate rule、stale table 100、stale flowtable 或 Resource busy。
10. 将本仓库作为 package feed 接入已配置的目标源码树后执行正式 package build。

## 22. 验收时建议采集

```sh
nft list table inet passwall
ip rule show
ip route show table 100
ip -6 rule show
ip -6 route show table 100
logread -e passwall
pgrep -af 'xray|sing-box|hysteria|ss-redir|ipt2socks'
```

需要把“源码/静态规则证据”“目标系统 build 证据”“路由器运行证据”“真实流量证据”分开记录；本文件当前只确认前一类。

## 23. 提示词交付项对照

| # | 交付项 | 结果/位置 |
| --- | --- | --- |
| 1 | 修改文件 | 第 3 节 |
| 2 | 删除 TCP REDIRECT | 第 4、18 节 |
| 3 | 新 TCP/UDP 路径 | 第 5 节 |
| 4 | PBR OFF | 第 6 节 |
| 5 | PBR ON | 第 7 节 |
| 6 | localhost | 第 8 节 |
| 7 | ACL 数据模型 | 第 9 节 |
| 8 | MAC-only | 第 9 节 |
| 9 | Direct ACL | 第 10 节 |
| 10 | ACL port policy | 第 5、11 节 |
| 11 | Global Policy 共享 | 第 11 节 |
| 12 | Proxy Drop | 第 5、11 节 |
| 13 | DNS 变化 | 第 12 节 |
| 14 | 不升级 dnsmasq 的原因 | 第 13 节 |
| 15 | Ping Hijack | 第 14 节 |
| 16 | IPv6 ICMP 安全 | 第 14 节 |
| 17 | flow offload | 第 16 节 |
| 18 | 节点防回环 | 第 15 节 |
| 19 | dead code | 第 18 节 |
| 20 | 旧 UCI key | 第 19 节 |
| 21 | 语法测试 | 第 20 节 |
| 22 | nftables 逻辑测试 | 第 20 节 |
| 23 | 风险/TODO | 第 21 节 |
