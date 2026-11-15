# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2023 xiaorouji
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall
PKG_VERSION:=4.78-1
PKG_RELEASE:=

LUCI_TITLE:=LuCI support for PassWall
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +curl \
	+chinadns-ng +dns2tcp +dnsmasq-full +ip-full \
	+libuci-lua +libubus-lua +lua +luci-compat +luci-lib-jsonc \
	+resolveip +tcping +xray-core +nftables \
	+kmod-nft-nat +kmod-nft-socket +kmod-nft-tproxy

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall
/usr/share/passwall/rules/direct_host
/usr/share/passwall/rules/direct_ip
/usr/share/passwall/rules/proxy_host
/usr/share/passwall/rules/proxy_ip
/usr/share/passwall/rules/block_host
/usr/share/passwall/rules/block_ip
/usr/share/passwall/rules/lanlist_ipv4
/usr/share/passwall/rules/lanlist_ipv6
/usr/share/passwall/rules/domains_excluded
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
