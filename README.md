# openwrt-passwall

基于 OpenWrt Passwall 的个人定制版本。

本 Fork 已收敛为面向 `BGzEroll/immortalwrt` `openwrt-23.05` 的 nftables 专用实现。透明代理只支持 TCP/UDP TPROXY，并支持两种 Proxy Action：

> **PBR 关闭时交给 OpenWrt 本机透明代理核心；PBR 开启时通过 Policy Routing 转发至独立透明代理机。**

无论 Proxy Action 选用哪条路径，VLAN、路由、防火墙、DNS、ACL、分流规则、nftables 和 Policy Routing 都由 OpenWrt 统一管理。PBR 开启时，mihomo、sing-box、Xray 等实际代理核心可以运行在独立 Linux / VM / LXC / 物理机上。

可以简单理解为：

> **Passwall 负责 WHO / WHICH PORTS / WHERE；Proxy Action 只负责把 PROXY 流量送到本机 TPROXY 或外置代理机。**

## 专用架构约束

- 客户端透明代理仅使用 nftables，不再提供 iptables 后端选择。
- TCP 不再支持 NAT REDIRECT 透明代理；DNS 和 Ping 仍保留 nftables NAT `redirect` 动作。
- `iproute_shunt=0`：`fwmark 0x1 → table 100 → local lo → TPROXY → 本机代理核心`。
- `iproute_shunt=1`：`fwmark 0x1 → table 100 → 外置透明代理网关`，不执行本地 TPROXY。
- ACL Source 仅接受 MAC 地址；一条 ACL 可以包含多个 MAC。
- 普通 ACL 只覆盖 TCP/UDP 的 Bypass、Proxy 和 Proxy Drop 端口，节点、DNS 和目的地址列表全部使用 Global Config。
- Direct ACL 完整绕过 TCP、UDP、DNS hijack 和 Ping hijack；同一 MAC 同时命中多条 ACL 时 Direct 优先。
- Ping hijack 只接收 IPv4/IPv6 Echo Request，不处理 NDP、RA、SLAAC、PMTUD 或其它 ICMPv6 控制报文。

实现细节、Before/After、23 项交付对照和实机待验证项见 [nftables 与 ACL 透明代理重构说明](docs/nftables与ACL透明代理重构说明.md)。

---

# 网络拓扑

当前实际网络使用两个独立 VLAN / 子网：

| 网络 | VLAN | IPv4 网段 | 用途 |
| --- | --- | --- | --- |
| 主网 | VLAN 0 | `192.168.114.0/24` | PC、手机、NAS、服务器等普通终端 |
| 代理网 | VLAN 114 | `192.168.113.0/24` | 外置透明代理机 |

当前代理机地址：

```text
192.168.113.59
```

OpenWrt 上代理网对应接口：

```text
br-lan.114
```

因此需要代理的流量会通过：

```text
br-lan.114
        │
        ▼
192.168.113.59
```

转发至外置代理机。

## 重要

> **主网与代理机必须位于相互隔离的 VLAN / 子网中。**

即类似：

```text
主网：
VLAN 0
192.168.114.0/24

代理网：
VLAN 114
192.168.113.0/24
```

不要将普通客户端与代理机放置在同一个二层网络中。

另外，VLAN ID 与 IPv4 网段编号没有要求必须对应。

例如本网络中：

```text
VLAN 114
```

承载：

```text
192.168.113.0/24
```

属于正常配置。

---

# 整体架构

```text
                            Internet
                               ▲
                               │
                  ┌────────────┴────────────┐
                  │                         │
               DIRECT                  Proxy Node
                  ▲                         ▲
                  │                         │
                  │                  ┌──────┴──────┐
                  │                  │ Proxy Host  │
                  │                  │             │
                  │                  │ mihomo      │
                  │                  │ sing-box    │
                  │                  │ Xray        │
                  │                  └──────▲──────┘
                  │                         │
                  │                  192.168.113.59
                  │                     VLAN 114
                  │                         ▲
                  │                         │
            ┌─────┴─────────────────────────┴─────┐
            │              OpenWrt                │
            │                                     │
            │ Passwall                            │
            │ DNS / ACL / Rules                   │
            │ nftables                            │
            │ fwmark                              │
            │ Policy Routing                      │
            └─────────────────▲───────────────────┘
                              │
                            VLAN 0
                              │
                     192.168.114.0/24
                              │
                ┌─────────────┼─────────────┐
                │             │             │
               PC           Phone          NAS
```

整个网络中：

```text
OpenWrt
=
主路由
```

而：

```text
192.168.113.59
=
代理流量专用下一跳
```

代理机不是普通客户端的默认网关。

---

# 工作原理

标准 Passwall TProxy 模式通常为：

```text
Client
   │
   ▼
OpenWrt
   │
   ▼
Passwall
   │
   ▼
TPROXY
   │
   ▼
OpenWrt 本机代理核心
   │
   ▼
Internet
```

本 Fork 开启：

```text
通过策略路由转发代理流量
```

后，Passwall 仍然负责判断流量应该：

```text
DIRECT
PROXY
BLOCK
```

但对于需要代理的流量，不再交给 OpenWrt 本机透明代理核心，而是通过 `fwmark + Policy Routing` 转发至外置代理机。

整体逻辑为：

```text
Client
   │
   ▼
OpenWrt
   │
   ▼
Passwall / nftables
   │
   ├── DIRECT ─────────────► WAN
   │
   ├── BLOCK ──────────────► DROP
   │
   └── PROXY
          │
          ▼
       fwmark 1
          │
          ▼
      Route Table 100
          │
          ▼
      外置代理机
          │
          ▼
       Proxy Node
```

---

# 数据流

## 直连流量

当 Passwall 判定连接应当直连时：

```text
Client
192.168.114.x
      │
      ▼
OpenWrt
      │
      ▼
Passwall
      │
      │ DIRECT
      ▼
WAN
      │
      ▼
Internet
```

这部分流量不会经过代理机。

---

## 代理流量

当 Passwall 判定连接需要代理时：

```text
Client
192.168.114.x
      │
      ▼
OpenWrt
      │
      ▼
Passwall / nftables
      │
      │ PROXY
      ▼
   fwmark 1
      │
      ▼
Policy Routing
Table 100
      │
      ▼
br-lan.114
      │
      ▼
192.168.113.59
      │
      ▼
Transparent Proxy
      │
      ▼
Proxy Node
      │
      ▼
Internet
```

可以概括为：

```text
DIRECT
   │
   └── OpenWrt → WAN


PROXY
   │
   └── OpenWrt
          │
          ▼
       VLAN 114
          │
          ▼
     192.168.113.59
          │
          ▼
        Proxy
```

---

# Policy Routing

开启：

```text
通过策略路由转发代理流量
```

之后，需要代理的连接会由 Passwall 标记。

IPv4 核心逻辑类似：

```sh
ip rule add fwmark 1 lookup 100

ip route replace 0.0.0.0/0 \
    via 192.168.113.59 \
    dev br-lan.114 \
    table 100
```

因此：

```text
PROXY
   │
   ▼
mark 1
   │
   ▼
ip rule
   │
   ▼
table 100
   │
   ▼
192.168.113.59
```

而普通直连流量不会进入该策略路由表，继续按照 OpenWrt 正常路由表转发。

---

# IPv6

IPv6 使用相同的策略路由思路。

例如：

```sh
ip -6 rule add fwmark 1 table 100

ip -6 route replace ::/0 \
    via <代理机 IPv6 地址> \
    dev br-lan.114 \
    table 100
```

对应：

```text
IPv6 PROXY
     │
     ▼
  fwmark 1
     │
     ▼
table 100
     │
     ▼
代理机 IPv6
     │
     ▼
Transparent Proxy
```

使用 IPv6 时需要确保：

- 代理机具有正确的 IPv6 地址；
- OpenWrt 能直接访问代理机 IPv6；
- 代理机 IPv6 Forwarding 正常；
- 透明代理核心支持 IPv6；
- 回程路由正确。

---

# 当前实际配置

当前网络配置：

| 配置项 | 当前值 |
| --- | --- |
| TCP 代理方式 | `TPROXY` |
| IPv6 透明代理 | 开启 |
| 策略路由转发代理流量 | 开启 |
| 主网 VLAN | VLAN 0 |
| 主网 IPv4 | `192.168.114.0/24` |
| 代理网 VLAN | VLAN 114 |
| 代理网 IPv4 | `192.168.113.0/24` |
| 代理机 IPv4 | `192.168.113.59` |
| 代理网接口 | `br-lan.114` |

Passwall 中类似配置：

```text
TCP 代理方式：
TPROXY

IPv6 透明代理：
开启

通过策略路由转发代理流量：
开启

转发至 IPv4 网关：
192.168.113.59

转发至 IPv6 网关：
<代理机 IPv6 地址>

通过接口：
br-lan.114
```

---

# VLAN 设计

普通客户端位于：

```text
VLAN 0
192.168.114.0/24
```

例如：

```text
192.168.114.10    PC
192.168.114.20    Phone
192.168.114.30    NAS
```

客户端的默认网关始终是 OpenWrt。

客户端：

- 不需要将代理机设置为默认网关；
- 不需要配置 HTTP / SOCKS 代理；
- 不需要安装额外代理客户端；
- 不需要感知代理机的存在。

代理机位于独立网络：

```text
VLAN 114
192.168.113.0/24
```

当前：

```text
192.168.113.59
```

OpenWrt 通过：

```text
br-lan.114
```

与代理机通信。

因此代理机可以理解为：

> **专门用于 PROXY 流量的三层下一跳网关。**

---

# 与传统旁路由的区别

传统所谓旁路由经常采用：

```text
Client
   │
   ▼
旁路由
   │
   ▼
主路由
   │
   ▼
Internet
```

或者通过 DHCP 将客户端默认网关下发为旁路由。

本方案不是这种结构。

普通客户端始终：

```text
Client
   │
   ▼
OpenWrt
```

只有被 Passwall 判定为需要代理的连接才会进入：

```text
OpenWrt
   │
   ▼
Policy Routing
   │
   ▼
192.168.113.59
```

因此严格来说：

> **代理机并不是传统旁路由，而是由 Policy Routing 调用的 External Transparent Proxy Gateway。**

---

# 为什么采用这种架构

该方案主要目的是将：

```text
网络控制 / 分流
```

和：

```text
实际代理处理
```

进行解耦。

OpenWrt 负责：

```text
DHCP
VLAN
Routing
Firewall
DNS
Passwall
ACL
Rule Set
nftables
Policy Routing
```

外置代理机负责：

```text
mihomo
sing-box
Xray
节点管理
Transparent Proxy
实际代理连接
```

这样可以避免将越来越复杂、资源占用越来越高、更新频繁的代理核心直接运行在 OpenWrt 上。

比较适合：

```text
OpenWrt
   +
PVE / Linux
   +
VM / LXC / Docker
```

或者：

```text
OpenWrt
   +
独立 Linux 主机
```

等部署环境。

---

# 故障影响

该架构下代理机主要影响：

```text
PROXY 流量
```

而不是整个 LAN 的正常三层网络。

正常情况下：

```text
代理机正常

DIRECT → 正常
PROXY  → 正常
```

代理机异常时：

```text
代理机异常

DIRECT → 仍可直接通过 OpenWrt / WAN
PROXY  → 无法正常代理
```

因此相对于将全部客户端默认网关直接指向代理机，代理机故障对普通直连网络的影响更小。

---

# Hardware Flow Offloading

本 Fork 对 Policy Routing 与 nftables Flow Offload 的兼容进行了额外处理。

需要代理的连接使用：

```text
mark 1
ct mark 1
```

进行标记。

普通可 Offload 流量则要求类似：

```text
mark != 1
ct mark != 1
```

因此：

```text
DIRECT
   │
   ▼
Normal Routing
   │
   ▼
Flow Offload
```

而：

```text
PROXY
   │
   ▼
mark 1
   │
   ▼
Policy Routing
   │
   ▼
192.168.113.59
```

不会因为 Flow Offload 而绕过代理分流。

---

# 软件 / 硬件流量分载注意事项

开启：

```text
通过策略路由转发代理流量
```

时，应按照界面提示关闭 OpenWrt 防火墙原生的：

```text
软件流量分载
硬件流量分载
```

本 Fork 会建立与 Policy Routing 兼容的 Flowtable。

如果之后关闭：

```text
通过策略路由转发代理流量
```

需要重新开启 OpenWrt 原生的：

```text
软件流量分载
硬件流量分载
```

---

# 外置代理机要求

外置代理机至少需要满足：

1. 与普通客户端位于不同 VLAN / 子网；
2. OpenWrt 可以直接访问代理机；
3. 可以作为 OpenWrt 的三层下一跳；
4. IPv4 Forwarding 正常；
5. 如使用 IPv6，则 IPv6 Forwarding 正常；
6. 已正确配置透明代理；
7. TCP / UDP 转发规则正确；
8. 回程路由正确；
9. 不得形成代理流量路由环路。

错误配置可能形成类似：

```text
OpenWrt
   │
   ▼
Proxy
   │
   ▼
OpenWrt
   │
   ▼
Proxy
   │
   ▼
...
```

因此配置代理机默认路由、策略路由以及透明代理规则时需要特别注意。

---

# DNS 与规则分流

PBR 模式主要改变的是：

> **被 Passwall 判定为 PROXY 的流量最终被发送到哪里。**

全局分流体系仍然保留在 OpenWrt 上，例如：

- DNS
- MAC ACL 端口策略
- Direct List
- Proxy List
- Block List
- GFW List
- China List
- Shunt List
- IPv4 / IPv6 规则

整体逻辑仍为：

```text
DNS / Rules
     │
     ▼
Passwall
     │
     ▼
DIRECT / PROXY / BLOCK
     │
     ├── DIRECT → WAN
     │
     ├── BLOCK  → DROP
     │
     └── PROXY
            │
            ▼
      Policy Routing
            │
            ▼
      External Proxy
```

因此外置代理机原则上只负责处理已经被 OpenWrt 判定为需要代理的透明代理流量。

---

# 数据路径总结

```text
                             ┌──── DIRECT ─────► WAN
                             │
Client                       │
VLAN 0                       │
192.168.114.0/24             │
      │                      │
      ▼                      │
   OpenWrt ─── Passwall ─────┤
                             │
                             └──── PROXY
                                    │
                                    ▼
                                 fwmark 1
                                    │
                                    ▼
                                table 100
                                    │
                                    ▼
                                br-lan.114
                                    │
                                    ▼
                                 VLAN 114
                                    │
                                    ▼
                              192.168.113.59
                                    │
                                    ▼
                             Transparent Proxy
                                    │
                                    ▼
                                Proxy Node
```

一句话概括：

> **OpenWrt 始终作为主路由，Passwall 负责分流；仅将需要代理的连接通过 Policy Routing 和独立代理 VLAN 转交给外置透明代理机。**

---

# 当前实现范围

该定制版本固定针对：

```text
fw4
+
nftables
```

环境实现。

兼容基线为：

```text
BGzEroll/immortalwrt openwrt-23.05
firewall4 / nftables
dnsmasq 2.90-2（启用 nftset）
```

旧配置中的 `use_nft=0` 不再选择 iptables；`tcp_proxy_way=redirect` 会在运行时按 TPROXY 处理并记录废弃提示。

---

# 已知问题

本 Fork 有意固定兼容 `BGzEroll/immortalwrt` 的 `openwrt-23.05` 与 dnsmasq `2.90-2`，未移植新版 dnsmasq `conf-dir` 自动探测改动；现有全局 dnsmasq 配置注入目录和语义保持不变。

相关背景可看此 [issue](https://github.com/xiaorouji/openwrt-passwall/issues/3455)。如果未来改变兼容基线，可参考上游 [commit 87051ecf](https://github.com/Openwrt-Passwall/openwrt-passwall/commit/87051ecf1ac3acfe53a5a63e6d59a3fdc18d6453)，但当前版本明确不移植该提交。

---

# Upstream

本项目 Fork 自：

```text
Openwrt-Passwall/openwrt-passwall
```

主要用于个人网络环境，以及以下架构的实验与维护：

```text
Passwall
    +
Policy Routing
    +
Dedicated Proxy VLAN
    +
External Transparent Proxy Gateway
```
