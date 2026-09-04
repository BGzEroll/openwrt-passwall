# 当前配置下 nftables 规则链验证报告

## 1. 快照信息

- 采集时间：2026-09-04
- 设备：Qihoo 360T7（ImmortalWrt 23.05-SNAPSHOT，Linux 5.15.164）
- Passwall：已启用，本次后台重启返回 `0`
- 代理进程：Xray 1.8.23，重启后 PID 为 `21127`
- 数据面：firewall4 + nftables，未发现 Passwall iptables/ip6tables 链

本报告基于主路由当前 UCI 配置、重启后生成配置、策略路由和 `table inet passwall` 实时计数器。未记录节点密码、订阅地址等敏感值。

## 2. 当前行为配置

| 项目 | 当前值 | 实际行为 |
|---|---:|---|
| TCP / UDP 模式 | `proxy` / `proxy` | 默认设备的 TCP、UDP 都进入全局端口策略 |
| UDP 节点 | `tcp` | TCP/UDP 复用同一主节点和生成的 Xray 进程 |
| 全局代理端口 | `1:65535` | TCP/UDP 全端口纳入策略 |
| 全局不转发/丢弃端口 | `disable` | 没有额外端口级放行或丢弃 |
| `localhost_proxy` | `0` | 路由器自身普通输出不进入代理策略 |
| 中国地址策略 | `chn_list=direct` | chnroute/chnroute6 命中后设置 `0xff` 并直连 |
| 直连/代理/屏蔽/GFW 列表 | UCI 未设置，fallback 均为 `0` | 没有向策略链加入这四类可选列表分支 |
| IPv6 透明策略 | 固定开启 | IPv6 TCP/UDP 与 IPv4 同时进入策略链 |
| DNS 分流 | Dnsmasq + UDP 上游 | Dnsmasq 监听 53，上游为 `192.168.113.59#1053` |
| DNS 重定向 | UCI 未设置，runtime fallback `1` | LAN 客户端 TCP/UDP 53 重定向到路由器 53 |
| ICMP / ICMPv6 | `1` / `1` | 按目标策略处理 ping |
| 策略路由转发 | `iproute_shunt=1` | `mark 0x1` 交由 table 100 转发到外部网关 |
| IPv4 PBR 网关 | `192.168.113.59` / `br-lan.114` | table 100 默认路由可达 |
| IPv6 PBR 网关 | `fdb2:5cc2:2555:1::1919` / `br-lan.114` | table 100 IPv6 默认路由可达 |
| Passwall flowtable | `lan1,lan2,lan3,wan,pppoe-wan` | 仅未标记为代理的直连流量可进入硬件 offload |

## 3. 总体数据路径

```text
LAN 数据包
├─ dstnat（priority -101）
│  ├─ Direct MAC：立即 return，不做 DNS/PING 劫持
│  ├─ ICMP/ICMPv6：PSW_PING
│  └─ TCP/UDP 53：PSW_DNS_REDIRECT → 本机 53
└─ mangle_prerouting（priority -151）
   ├─ TCP：PSW_DIVERT
   ├─ IPv4：PSW_MANGLE
   └─ IPv6：PSW_MANGLE_V6
      ├─ Direct MAC / DNS / lo：return
      ├─ 指定 MAC：PSW_ACL_acl_rule1
      └─ 其余设备：PSW_DEFAULT_PORTS
         ├─ 目标策略：PSW_POLICY_V4 / PSW_POLICY_V6
         ├─ 直连：mark 0xff 后 return
         └─ 代理：PSW_PROXY_* → PSW_MARK → mark 0x1
            └─ ip rule → table 100 → 外部 IPv4/IPv6 网关
```

当前启用 PBR，因此 `PSW_PROXY_TCP4/UDP4/TCP6/UDP6` 的动作是设置 mark，而不是在路由器本机执行 TPROXY redirect。

## 4. 基链与职责

| 链 | hook / priority | 当前规则数 | 职责 |
|---|---|---:|---|
| `dstnat` | prerouting / `-101` | 4 | Direct MAC 早退、PING 和 DNS 重定向入口 |
| `mangle_prerouting` | prerouting / `-151` | 3 | TCP DIVERT，然后分流到 IPv4/IPv6 客户端链 |
| `mangle_output` | output / `-151` | 3 | 本机 lo/已标记流量早退，主节点地址防回环 |
| `nat_output` | output / `-1` | 2 | 路由器本机 ICMP/ICMPv6 策略入口 |
| `hwnat_pass` | forward / `-1` | 1 | 将转发流量交给 `PSW_HWNAT_PASS` 判断 |

Passwall 的 mangle/dstnat hook 优先级早于 fw4 对应的默认 hook；表内对 LAN、节点地址和已标记数据包都有显式防回环路径。

## 5. 策略链

### `PSW_POLICY_V4` / `PSW_POLICY_V6`

当前顺序为：

1. LAN 地址集合：`mark 0xff` 并直接返回。
2. 节点地址集合：`mark 0xff` 并直接返回，防止代理回环。
3. IPv4 FakeDNS 段 `198.18.0.0/16`：直接进入 `PSW_MARK`。
4. shunt 动态集合：进入 `PSW_MARK`。
5. chnroute/chnroute6：`mark 0xff` 并直连。
6. 其余目标返回端口策略，按全局模式进入代理。

### `PSW_DEFAULT_PORTS`

全局 TCP/UDP 都是 `1:65535`，因此 IPv4/IPv6 先执行目标策略；目标未被标记为直连时，进入对应 `PSW_PROXY_*` 链。快照中已观察到：

- IPv4 TCP 进入代理：2,779 包 / 618,703 字节。
- IPv4 UDP 进入代理：4 包 / 240 字节。
- IPv4 TCP 直连返回：757 包 / 64,044 字节。
- IPv4 UDP 直连返回：57 包 / 13,562 字节。
- IPv6 默认链已有流量；快照时主要是 17 包 / 3,992 字节的直连 UDP。

### `PSW_MARK` 与 PBR

`PSW_MARK` 同时设置 packet mark 和 conntrack mark 为 `0x1`，然后返回。快照时已命中 2,818 包 / 621,051 字节。

IPv4/IPv6 都存在优先级 32765 的 `fwmark 0x1 lookup 100` 规则。实测：

- `8.8.8.8 mark 1` 选择 table 100，经 `192.168.113.59 dev br-lan.114`。
- `2606:4700:4700::1111 mark 1` 选择 table 100，经 `fdb2:5cc2:2555:1::1919 dev br-lan.114`。
- 两个网关均连续 ping 2/2 成功，平均延迟约 0.72 ms 和 0.78 ms。

## 6. ACL 行为

### Direct ACL

`localproxy` 规则的 1 个 MAC 被加入 `passwall_direct_macs`。该集合在 `dstnat`、`PSW_MANGLE`、`PSW_MANGLE_V6` 的最前面返回，因此对该设备的结果是：

- TCP/UDP 不进入 Passwall 代理。
- DNS 不被 Passwall 重定向。
- ICMP/ICMPv6 不被 Passwall 劫持。

快照时 Direct MAC 已在 `dstnat` 命中 49 包，在 IPv4 mangle 命中 3,172 包，在 IPv6 mangle 命中 14 包。

### 普通 ACL `server-noproxy`

该规则包含 4 个 MAC，并生成 `PSW_ACL_acl_rule1`：

- UDP 策略为 `1:65535` 不转发，IPv4/IPv6 UDP 直接返回。
- TCP 仅 `80,443` 进入目标策略和代理分支，其余 TCP 返回。
- 节点、DNS 和目标策略复用全局配置。

快照时规则已有实际命中：IPv4 TCP 80/443 代理 23 包，IPv6 TCP 80/443 代理 12 包，UDP 直连分支也已有命中。

## 7. DNS 与 PING

### DNS

- `PSW_DNS_REDIRECT` 对 UDP/TCP 53 都执行 `redirect to :53`。
- 快照时 UDP DNS 重定向已命中 33 包 / 2,094 字节；TCP DNS 当时为 0。
- Dnsmasq 已在所有必要的 IPv4/IPv6 本地地址监听 53。
- `nslookup openai.com 127.0.0.1` 成功返回 A 记录。
- `nslookup -type=AAAA cloudflare.com 127.0.0.1` 成功返回 AAAA 记录。
- 当前 `dns_shunt=dnsmasq`，没有 ChinaDNS-NG 进程和 15353 监听；状态页 DNS 卡片因专门表示 ChinaDNS-NG，显示“未运行”符合当前设计。

### PING

`dstnat` 和 `nat_output` 分别将 ICMP/ICMPv6 echo-request 交给 `PSW_PING`。该链先执行 IPv4/IPv6 目标策略，再对 `0x1` 或未分类流量执行 redirect，对 `0xff` 直连流量返回。

## 8. 集合快照

`nft -j list table inet passwall` 在采集时返回以下 element 记录数。对 interval set，这是 nft JSON 中的区间记录数，不等于逐 IP 展开数。

| 集合 | IPv4 | IPv6 | 说明 |
|---|---:|---:|---|
| VPS | 1 | 0 | 主节点防回环 |
| LAN | 14 | 15 | 本地/保留地址直连 |
| chnroute | 2,977 | 1,253 | 中国地址直连 |
| whitelist | 2 | 0 | 集合存在，但当前 `use_direct_list=0` 未接入策略链 |
| gfwlist / blacklist / blocklist / shuntlist | 0 | 0 | 当前未使用或未有动态元素 |
| Direct MAC | 1 | — | Direct ACL 设备 |

## 9. flowtable

Passwall 创建了 `flowtable ft`，hook 为 ingress，priority 为 `filter - 1`，设备集合为 `lan1, lan2, lan3, wan, pppoe-wan`，并带 `flags offload`。

`PSW_HWNAT_PASS` 仅对 packet mark 和 conntrack mark 都不是 `0x1` 的 TCP/UDP 流执行 `flow add @ft`，因此代理/PBR 流量被排除，直连流量可加速。快照时 `hwnat_pass` 基链已观察到 6,411 包 / 2,353,724 字节。

这能证明 flowtable 规则已成功建立并接收流量；仅凭 nftables 规则快照不能证明每一条流都已被具体硬件驱动实际 offload。

## 10. 验证结果

| 验证项 | 结果 | 证据 |
|---|---|---|
| Passwall 重启 | 通过 | 后台 restart 返回 0，日志以“运行完成”结束 |
| Xray 生成配置 | 通过 | `xray run -test` 返回 `Configuration OK` |
| nftables 规则 | 通过 | `nft -c list table inet passwall` 返回 0 |
| IPv4/IPv6 PBR | 通过 | mark 1 均命中 table 100，两个网关均可达 |
| 实际 LAN 流量 | 通过 | IPv4/IPv6、Direct MAC、ACL、默认代理和 DNS 链均已有命中计数 |
| DNS A/AAAA | 通过 | 本机 Dnsmasq 查询均成功 |
| 本机 SOCKS 1070 | 通过 | Xray 同时监听 TCP/UDP `127.0.0.1:1070` |
| SOCKS 外网连通 | 通过 | Google generate_204 返回 204，GitHub 返回 200 |
| 路由器直连 | 通过 | Baidu HTTPS 返回 200，符合 `localhost_proxy=0` |
| DNS 重定向 | 通过 | UDP 53 redirect 已有实际命中 |
| ACL | 通过 | Direct 早退及普通 ACL TCP/UDP/IPv4/IPv6 分支均已有命中 |
| flowtable | 通过（规则层） | flowtable 创建成功，forward 入口已有命中 |
| 监控与 cron | 通过 | `monitor.sh` 正在运行；规则更新为每周四 06:00 |
| LuCI / ubus | 通过 | ubus 调用正常；LuCI 未登录请求返回正常的 403 |
| 旧 iptables 数据面 | 无残留 | `iptables-save` 和 `ip6tables-save` 中 `PSW` 数量均为 0 |

## 11. 结论与边界

当前配置下，TCP、UDP、DNS、IPv4/IPv6、MAC Direct ACL、普通 ACL、PBR table 100、PING 策略和直连 flowtable 的代码路径一致，且重启后规则已有实际命中。未发现启动失败、无效 MAC、规则加载错误或旧 iptables 链残留。

远程验证无法从路由器伪造每一台实际 LAN 客户端的完整应用会话；因此逐设备的应用层感受仍以客户端实测为最终依据。本次通过该 MAC 分支的实时命中计数、主路由上的 DNS/SOCKS 实测和 PBR 网关可达性，已覆盖可远程验证的关键路径。
