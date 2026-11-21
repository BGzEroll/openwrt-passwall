#!/bin/bash
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT_DIR/luci-app-passwall/root/usr/share/passwall/nftables.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT

run_case() {
	local pbr="$1" case_dir="$TEST_TMP/pbr_$1"
	mkdir -p "$case_dir/work" "$case_dir/work2" "$case_dir/interfaces"
	(
		export TEST_PBR="$pbr"
		export TEST_RULES_FILE="$case_dir/rules.nft"
		export TMP_PATH="$case_dir/work"
		export TMP_PATH2="$case_dir/work2"
		export TMP_IFACE_PATH="$case_dir/interfaces"
		export RULES_PATH="$ROOT_DIR/tests/fixtures/nftables_rules"
		export CONFIG=passwall
		export ENABLED=1 ENABLED_DEFAULT_ACL=1 LOCALHOST_PROXY=1
		export TCP_NODE=node1 UDP_NODE=node1 TCP_UDP=0
		export TCP_REDIR_PORT=1041 UDP_REDIR_PORT=1051 PROXY_IPV6=1
		export TCP_REDIR_PORTS=1:65535 UDP_REDIR_PORTS=1:65535
		export TCP_NO_REDIR_PORTS=disable UDP_NO_REDIR_PORTS=disable
		export TCP_PROXY_DROP_PORTS=disable UDP_PROXY_DROP_PORTS=443
		export USE_DIRECT_LIST=1 USE_PROXY_LIST=1 USE_BLOCK_LIST=1 USE_GFW_LIST=1
		export CHN_LIST=direct TCP_PROXY_MODE=proxy UDP_PROXY_MODE=proxy
		export ISP_DNS= ISP_DNS6= IPT_APPEND_DNS=

		sysctl() { [ "${1:-}" = "-e" ] && echo 1 || true; }
		echo_log() { :; }
		echolog() { echo_log "$@"; }
		debuglog() { :; }
		get_host_ip() {
			case "$1:$2" in
				ipv4:*.*) echo "$2" ;;
				ipv6:*:*) echo "$2" ;;
			esac
		}
		config_load() { :; }
		config_foreach() { :; }
		config_ids() {
			case "$1" in
				acl_rule) printf '%s\n' acl_web acl_all acl_udp acl_direct ;;
				nodes) echo node1 ;;
			esac
		}
		network_flush_cache() { :; }
		network_find_wan() { printf -v "$1" wan; }
		network_find_wan6() { printf -v "$1" wan6; }
		network_get_ipaddr() { printf -v "$1" 203.0.113.1; }
		network_get_ipaddr6() { printf -v "$1" 2001:db8::1; }
		network_get_subnets() { printf -v "$1" 192.168.1.1/24; }
		network_get_subnets6() {
			case "$2" in
				lan) printf -v "$1" '%s' '2001:db8:1::1/64 fd00::1/64' ;;
				proxy) printf -v "$1" '%s' '2001:db8:1::114/64 2001:db8:2::114/64 fd00:0:0:1::114/64' ;;
			esac
		}
		network_get_device() { printf -v "$1" br-lan; }
		uci() {
			if [ "$1" = "show" ]; then
				cat <<-'EOF'
				passwall.acl_web=acl_rule
				passwall.acl_all=acl_rule
				passwall.acl_udp=acl_rule
				passwall.acl_direct=acl_rule
				EOF
			fi
			return 0
		}
		config_t_get() {
			case "$1.$2" in
				global_forwarding.iproute_shunt) echo "$TEST_PBR" ;;
				global_forwarding.iproute_shunt_gw_v4) echo 192.0.2.2 ;;
				global_forwarding.iproute_shunt_gw_v6) echo 2001:db8::2 ;;
				global_forwarding.iproute_shunt_interface) echo eth9 ;;
				global_forwarding.accept_icmp|global_forwarding.accept_icmpv6) echo 1 ;;
				global.dns_redirect) echo 1 ;;
				*) echo "${3:-}" ;;
			esac
		}
		config_n_get() {
			case "$1.$2" in
				acl_web.enabled|acl_all.enabled|acl_udp.enabled|acl_direct.enabled) echo 1 ;;
				acl_web.direct|acl_all.direct|acl_udp.direct) echo 0 ;;
				acl_direct.direct) echo 1 ;;
				acl_web.sources) echo 'AA:BB:CC:DD:EE:01 AA:BB:CC:DD:EE:02 192.168.1.9' ;;
				acl_all.sources) echo 'AA:BB:CC:DD:EE:03' ;;
				acl_udp.sources) echo 'AA:BB:CC:DD:EE:04' ;;
				acl_direct.sources) echo 'AA:BB:CC:DD:EE:02' ;;
				acl_web.tcp_redir_ports) echo '80,443' ;;
				acl_all.tcp_redir_ports) echo '1:65535' ;;
				acl_udp.udp_redir_ports) echo '53,443' ;;
				acl_web.udp_proxy_drop_ports) echo 443 ;;
				acl_direct.tcp_redir_ports|acl_direct.udp_redir_ports) echo '1:65535' ;;
				acl_web.remarks) echo web ;;
				acl_all.remarks) echo all-tcp ;;
				acl_udp.remarks) echo dns-quic ;;
				node1.type) echo Xray ;;
				node1.address) echo 198.51.100.10 ;;
				node1.port) echo 443 ;;
				*) echo "${3:-}" ;;
			esac
		}
		config_get_type() { config_n_get "$1" type "${2:-}"; }
		touch "$TMP_IFACE_PATH/proxy0"

		# Replace only the unavailable OpenWrt network helper, then exercise the
		# function-library API that emits the complete candidate table.
		source <(sed 's#^\. /usr/share/passwall/network.sh$#:#' "$SCRIPT")
		nft_offload_devices() { echo eth0,eth1; }
		passwall_proxy_interfaces() { echo proxy; }
		nft_read_config
		nft_generate > "$TEST_RULES_FILE"
	)
}

if [ "${1:-}" = "--netns" ]; then
	run_case 0
	/usr/sbin/nft -f "$TEST_TMP/pbr_0/rules.nft"
	/usr/sbin/nft list table inet passwall >/dev/null
	/usr/sbin/ip link add eth0 type veth peer name eth1
	/usr/sbin/ip link set eth0 up
	/usr/sbin/ip link set eth1 up
	run_case 1
	sed 's/flags offload;[[:space:]]*/ /' "$TEST_TMP/pbr_1/rules.nft" > "$TEST_TMP/pbr_1/rules-soft.nft"
	{
		printf 'delete table inet passwall\n'
		cat "$TEST_TMP/pbr_1/rules-soft.nft"
		printf 'add rule inet passwall missing_chain counter\n'
	} > "$TEST_TMP/pbr_1/invalid-batch.nft"
	if /usr/sbin/nft -f "$TEST_TMP/pbr_1/invalid-batch.nft" >/dev/null 2>&1; then
		echo "invalid nftables replacement unexpectedly loaded" >&2
		exit 1
	fi
	/usr/sbin/nft list table inet passwall >/dev/null
	/usr/sbin/nft list chain inet passwall PSW_PROXY_TCP4 | grep -q 'tproxy ip to :1041'
	{
		printf 'delete table inet passwall\n'
		cat "$TEST_TMP/pbr_1/rules-soft.nft"
	} | /usr/sbin/nft -f -
	/usr/sbin/nft list flowtable inet passwall ft >/dev/null
	echo "nftables namespace load checks passed"
	exit 0
fi

run_case 0
run_case 1

OFF="$TEST_TMP/pbr_0/rules.nft"
ON="$TEST_TMP/pbr_1/rules.nft"

# During renumbering, both interfaces can report the same prefix with distinct
# host bits. Reserved ranges, interface prefixes and the WAN host must merge
# together instead of being inserted into the same interval set in stages.
[ "$(grep -c '^add element inet passwall passwall_lanlist6 ' "$ON")" -eq 1 ]
lan6=$(grep '^add element inet passwall passwall_lanlist6 ' "$ON")
for address in fc00::/7 2001:db8:1::1/64 2001:db8:1::114/64 2001:db8:2::114/64 2001:db8::1; do
	[[ "$lan6" == *"$address"* ]]
done

grep -q 'tproxy ip to :1041' "$OFF"
grep -q 'tproxy ip6 to :1041' "$OFF"
! grep -q 'tproxy .* to :' "$ON"
grep -q 'PSW_MANGLE iif lo meta mark 0x1 meta l4proto tcp.*PSW_PROXY_TCP4' "$OFF"
grep -q 'PSW_MANGLE iif lo meta mark 0x1 meta l4proto udp.*PSW_PROXY_UDP4' "$OFF"
grep -q 'PSW_MANGLE_V6 iif lo meta mark 0x1 meta l4proto tcp.*PSW_PROXY_TCP6' "$OFF"
grep -q 'PSW_MANGLE_V6 iif lo meta mark 0x1 meta l4proto udp.*PSW_PROXY_UDP6' "$OFF"
grep -q 'PSW_OUTPUT_MANGLE.*goto PSW_ROUTE_PROXY' "$OFF"
! grep -q 'iif lo meta mark 0x1.*PSW_PROXY_' "$ON"
grep -q 'add element inet passwall passwall_direct_macs { AA:BB:CC:DD:EE:02 }' "$OFF"
grep -q 'PSW_MANGLE ether saddr @passwall_direct_macs counter return' "$OFF"
grep -q 'PSW_MANGLE_V6 ether saddr @passwall_direct_macs counter return' "$OFF"
grep -q 'dstnat ether saddr @passwall_direct_macs counter return' "$OFF"
grep -q 'ether saddr { AA:BB:CC:DD:EE:01, AA:BB:CC:DD:EE:02 }.*goto PSW_ACL_acl_web' "$OFF"
grep -q 'PSW_ACL_acl_web meta nfproto ipv4 meta l4proto tcp tcp dport {80, 443}.*jump PSW_POLICY_V4' "$OFF"
grep -q 'PSW_ACL_acl_all meta nfproto ipv4 meta l4proto tcp .*jump PSW_POLICY_V4' "$OFF"
grep -q 'PSW_ACL_acl_udp meta nfproto ipv4 meta l4proto udp udp dport {53, 443}.*jump PSW_POLICY_V4' "$OFF"
! grep -q 'PSW_ACL_acl_direct' "$OFF"
[ "$(grep -c 'PSW_POLICY_V4 ip daddr @passwall_gfwlist' "$OFF")" -eq 1 ]
[ "$(grep -c 'PSW_POLICY_V6 ip6 daddr @passwall_gfwlist6' "$OFF")" -eq 1 ]
grep -q 'icmp type echo-request.*jump PSW_PING' "$OFF"
grep -q 'icmpv6 type echo-request.*jump PSW_PING' "$OFF"
! grep -q 'meta l4proto {icmp,icmpv6}' "$OFF"
! grep -q 'PSW_NAT\|PSW_OUTPUT_NAT' "$OFF"
grep -q 'PSW_DNS_REDIRECT.*redirect to :53' "$OFF"
grep -q 'PSW_MANGLE iifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return' "$OFF"
grep -q 'PSW_MANGLE_V6 iifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return' "$OFF"
grep -q 'ct mark != 0x1 flow add @ft' "$ON"
grep -q 'PSW_HWNAT_PASS meta l4proto { tcp, udp } ct direction original meta mark 0x1 counter flow add @ft' "$ON"
! grep -q 'ct direction original meta mark 0x1 counter flow add @ft' "$OFF"
! grep -q ' comment ' "$ON" "$OFF"
grep -q 'PSW_OUTPUT_MANGLE oifname "proxy0" counter return' "$OFF"
grep -q 'PSW_ACL_acl_web meta nfproto ipv4 meta l4proto udp udp dport {443} jump PSW_POLICY_V4' "$OFF"
grep -q 'PSW_ACL_acl_web meta nfproto ipv4 meta l4proto udp udp dport {443} meta mark 0x1 counter drop' "$OFF"
grep -q 'PSW_ACL_acl_web meta nfproto ipv4 meta l4proto udp udp dport {443} meta mark 0xff counter return' "$OFF"

direct_dstnat_line=$(grep -n -m1 'dstnat ether saddr @passwall_direct_macs' "$OFF" | cut -d: -f1)
ping_dstnat_line=$(grep -n -m1 'dstnat ip protocol icmp icmp type echo-request' "$OFF" | cut -d: -f1)
dns_dstnat_line=$(grep -n -m1 'dstnat iifname != "lo" counter jump PSW_DNS_REDIRECT' "$OFF" | cut -d: -f1)
[ "$direct_dstnat_line" -lt "$ping_dstnat_line" ]
[ "$direct_dstnat_line" -lt "$dns_dstnat_line" ]

if [ -x /usr/sbin/nft ] && unshare -Urn true 2>/dev/null; then
	unshare -Urn "$0" --netns
else
	echo "nftables namespace load checks skipped"
fi

echo "nftables architecture checks passed"
