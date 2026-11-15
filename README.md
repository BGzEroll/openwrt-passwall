# openwrt-passwall

面向个人固定网络环境的 Passwall 裁剪版本。主路由负责 DNS、设备策略、目标分流和策略路由，外置透明代理网关负责处理代理流量。

固定使用 `BGzEroll/immortalwrt` 的 `openwrt-23.05` 分支，基线为 fw4、nftables `1.0.8`、支持 nftset 的 dnsmasq `2.90` 和 Xray `1.8.23`。功能及默认行为围绕自用需求维护。

## 当前部署

以下是当前主路由的部署值，不是初始化脚本写死的默认配置。新安装默认停用，已有配置和节点会保留。

| 项目 | 配置 |
| --- | --- |
| 客户端网络 | VLAN 1，`br-lan.1`，`192.168.114.0/24` |
| 客户端网关 | `192.168.114.1` |
| 代理网络 | VLAN 2，`br-lan.2`，`192.168.113.0/24` |
| 代理网主路由地址 | `192.168.113.1` |
| IPv4 透明代理网关 | `192.168.113.10` |
| IPv6 透明代理网关 | `fd07:a401:7468:1::1919` |
| 直连、远端 DNS | 均为 `192.168.113.11:53`，UDP |
| DNS 分流 | dnsmasq，默认使用直连 DNS |
| 目标策略 | 中国 IPv4/IPv6 地址直连，其余目标默认代理 |
| 转发模式 | PBR 开启，通过 `br-lan.2` 转发 |
| 本机代理 | 开启 |
| 全局节点 | Xray SOCKS，`192.168.113.10:1080`，UDP 与 TCP 相同 |
| 本地 SOCKS | `127.0.0.1:1070` |
| 启动延迟 | `0` 秒 |

```text
LAN 客户端 → 主路由分类
                ├─ 直连 → WAN
                ├─ 屏蔽 → 丢弃
                └─ 代理 → mark 0x1 → table 100 → br-lan.2 → 外置透明代理网关

客户端 DNS → 主路由 dnsmasq → 192.168.113.11:53
```

外置网关接收 IPv4/IPv6 透明流量，回程经主路由返回客户端。代理网关设备配置直连 MAC 策略，避免回程再次进入代理分类。DNS 服务的内部上游由 `192.168.113.11` 自行管理。

## 分流与设备策略

全局策略统一管理节点、DNS 和目标列表；设备策略仅按 MAC 覆盖端口行为，一条策略可填写多个 MAC。

- 普通设备策略分别设置 TCP/UDP 的不代理端口、代理端口、代理目标丢弃端口。按绕过、代理目标丢弃、代理的顺序处理，其余直连；也可选择继承全局设置。
- 代理目标丢弃仅作用于全局策略判定为代理的目标，不阻断同端口的直连目标。
- 直连设备策略优先于普通策略，绕过 TCP/UDP 代理、DNS 劫持及 ICMP 接管。
- ICMP 接管仅处理 IPv4/IPv6 Echo Request，不处理 NDP、RA 等 IPv6 控制报文。

本机代理开启时，主路由普通 TCP/UDP 流量也按全局规则分类；配置为直连 DNS 的上游优先绕过。关闭本机代理后，普通本机 53 端口查询按系统路由发送；Xray DNS 使用核心配置的出口。

## 转发与硬件加速

支持两种转发模式，当前部署使用 PBR：

| 模式 | 代理流量路径 |
| --- | --- |
| PBR 开启 | `mark 0x1 → table 100 → 外置透明代理网关` |
| PBR 关闭 | `mark 0x1 → table 100 → local lo → 本机 Xray TPROXY` |

两种模式均需选择有效的全局 TCP/UDP 节点以启用对应协议。PBR 下仍运行 Xray，并保留 SOCKS 1070，供规则下载和本机显式代理请求使用。

PBR 开启时自动关闭 fw4 原生的软、硬件流量分载，使用 Passwall 自建 flowtable；加速接口通过 fw4 API 获取。原生开关关闭不代表 Passwall 的硬件卸载关闭。当前部署已通过真实连接的 `HW_OFFLOAD` 标记和 PPE 表项计数确认硬件转发。

关闭 Passwall 后，固定开启原生 DNS 重定向及软、硬件流量分载。启用 Passwall DNS 劫持时，会关闭 dnsmasq 的原生 DNS 重定向。

## 启动与热更新

核心和 DNS 辅助进程统一由 procd 守护。启动延迟支持 `0`；接口地址尚未就绪时保留不可达路由，网络就绪后补齐 PBR 路由，不回落到普通出口。

- 每次操作使用固定的配置快照，成功后保存为生效配置；运行状态和后续网络、规则热更新以生效配置为准。
- 核心配置先生成并校验，失败保留原服务。仅备注、未引用节点或普通规则变化时，不重启核心。
- ChinaDNS-NG 域名文件变化时仅替换 DNS 实例，加载失败恢复旧快照；Xray 嗅探排除文件变化时重新生成并加载核心配置。配置与规则更新均检查文件变化。
- NFT 表通过完整事务替换，DNS 配置按需更新并在失败时回滚。DNS 学习集合及 flowtable 在替换后重新积累。
- hotplug 关注 `wan`、`wan6`、`lan`，并从“通过接口”反查对应的 netifd 逻辑接口。重复通知跳过，停止后的通知不会重新启动服务。
- 延迟启动可取消；重复启停和热更新通过同一服务锁串行处理。

常用命令：

```sh
/etc/init.d/passwall start
/etc/init.d/passwall stop
/etc/init.d/passwall restart
/etc/init.d/passwall reload          # 核心变化时重启，否则热更新
/etc/init.d/passwall reload rules    # 更新规则，按需重载依赖规则文件的进程
/etc/init.d/passwall reload network  # 按当前网络状态更新
```

运行状态位于 `/var/run/passwall/`，服务锁为 `/var/lock/passwall.lock`。正常探测和重载保持系统日志安静；操作结果与失败原因写入 Passwall 日志。

## 功能范围

页面使用 OpenWrt 原生 Lua CBI，入口为基础设置、节点、设备策略、规则、高级设置和日志。

- 本机核心固定为 Xray，保留 SOCKS、HTTP、VMess、VLESS、Shadowsocks、Trojan、WireGuard，以及核心分流、均衡、前置代理、落地节点和接口出口。
- 节点通过表单管理，支持手动测试；删除前检查节点引用，避免留下无效配置。
- DNS 支持 UDP、TCP、Xray DoH 和 ChinaDNS-NG，正常处理 IPv4/IPv6。
- 规则更新仅包含 GFW 域名、中国 IPv4、中国 IPv6 三个文本列表。手动与定时更新共用勾选；下载使用独立任务锁，不占用服务锁，发布失败保留原文件。
- 日志页统一管理核心日志及详细运行日志，可查看运行、TCP、UDP 日志。

不包含订阅、URL/二维码导入导出、自动延迟检测、组件更新及其他独立核心；不支持 GeoIP/GeoSite、FakeIP、DoT、dns2socks。程序使用标准路径，Xray 资源目录固定为 `/usr/share/v2ray/`。

## 验证与项目状态

本轮开发已按约定范围完成验收，可以收尾。测试机覆盖初始化、0 秒启动、生命周期、热更新及失败保护；主路由覆盖真实 LAN 客户端的 IPv4/IPv6 TCP/UDP、设备策略、DNS、硬件卸载和下载跨热重载。主路由未断开 WAN，测试后配置恢复，核心 PID 保持一致。

详细结果、硬件证据及测试边界见 [冒烟测试记录](docs/冒烟测试记录.md)。按约定未重新安装主路由，也未逐一验证所有远端节点协议。

## 上游

Fork 自 [Openwrt-Passwall/openwrt-passwall](https://github.com/Openwrt-Passwall/openwrt-passwall)，遵循仓库许可证。
