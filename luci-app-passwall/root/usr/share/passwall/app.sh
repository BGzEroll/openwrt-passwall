#!/bin/sh
# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2023 xiaorouji

. $IPKG_INSTROOT/lib/functions.sh

CONFIG=passwall
STATE_PATH=/var/run/passwall
TMP_PATH=${PASSWALL_TMP_PATH:-/tmp/etc/$CONFIG}
PROCESS_DIR=$STATE_PATH/processes
TMP_ACL_PATH=$TMP_PATH/acl
TMP_IFACE_PATH=$TMP_PATH/iface
DNSMASQ_CONF=/tmp/dnsmasq.d/dnsmasq-passwall.conf
LOG_FILE=/tmp/log/$CONFIG.log
APP_PATH=/usr/share/$CONFIG
RULES_PATH=/usr/share/${CONFIG}/rules
DNS_PORT=15353
TUN_DNS="127.0.0.1#${DNS_PORT}"
LOCAL_DNS=119.29.29.29,223.5.5.5
IPT_APPEND_DNS=
ENABLED_DEFAULT_ACL=0
resolve_dns=0
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua

echolog() {
	local component="$1"
	shift
	local message
	message=$(printf '%s' "$*" | tr '\r\n' '  ')
	mkdir -p /tmp/log
	printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$component" "$message" >> "$LOG_FILE"
}

debuglog() {
	[ "$(config_t_get global log_debug 0)" != 1 ] || echolog "$@"
}

# Passwall is loaded once per operation by OpenWrt's native config reader.
config_get_type() {
	config_n_get "$1" TYPE "$2"
}

config_n_get() {
	local value
	config_get value "$1" "$2" "$3"
	printf '%s\n' "$value"
}

config_ids() {
	local section kind
	for section in $CONFIG_SECTIONS; do
		config_get kind "$section" TYPE
		[ "$kind" != "$1" ] || printf '%s\n' "$section"
	done
}

config_t_get() {
	local section kind count=0 index="${4:-0}"
	for section in $CONFIG_SECTIONS; do
		config_get kind "$section" TYPE
		[ "$kind" = "$1" ] || continue
		if [ "$count" = "$index" ]; then
			config_n_get "$section" "$2" "$3"
			return
		fi
		count=$((count + 1))
	done
	printf '%s\n' "$3"
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=$host
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			isip=$(echo $host | cut -d '[' -f2 | cut -d ']' -f1)
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	echo $ip
}

dns_endpoints() {
 lua - "$1" <<'LUA'
local endpoint = require 'luci.passwall.endpoint'
print(endpoint.list(arg[1]))
LUA
}

first_dns() {
 printf '%s\n' "${1%%,*}"
}

system_dns_upstreams() {
	awk '{ for (i = 1; i <= NF; i++) {
		if ($i ~ /\//) continue
		printf "%s%s", n++ ? "," : "", $i
		if (n == 2) exit
	} }'
}

chinadns_local_servers() {
	case "$1" in
		127.0.0.1\#*) first_dns "$1" ;;
		*) printf '%s\n' "$1" ;;
	esac
}

get_new_port() {
	local port="$1" flags
	[ "$port" != auto ] || port=2082
	case "$port" in ''|*[!0-9]*) return 1 ;; esac
	case "${2:-tcp,udp}" in
		tcp|TCP) flags=-tln ;;
		udp|UDP) flags=-uln ;;
		tcp,udp) flags=-tuln ;;
		*) return 1 ;;
	esac
	netstat "$flags" | awk -v port="$port" '
		$4 ~ /:[0-9]+$/ { addr = $4; sub(/^.*:/, "", addr); used[addr] = 1 }
		END {
			if (port < 1) exit 1
			while (port <= 65535 && used[port]) port++
			if (port > 65535) exit 1
			print port
		}'
}

ln_run() {
	local binary="$1" name="$2" output="$3"
	shift 3
	if [ -z "$binary" ] || [ ! -x "$binary" ]; then
		echolog 服务 "找不到可执行程序：$name"
		return 1
	fi
	if [ -n "${PASSWALL_TEST_DIR:-}" ]; then
		"$binary" "$@" 9>&- >>"$output" 2>&1 &
		echo $! >> "$PASSWALL_TEST_DIR/pids"
	else
		lua "$APP_PATH/process.lua" plan "$PROCESS_DIR" "$output" "$binary" "$@"
	fi
}

run_xray() {
	local node tcp_redir_port udp_redir_port socks_address socks_port
	local dns_listen_port remote_dns_tcp_server remote_dns_doh dns_client_ip dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file
	export "$@" || return 1
	[ -n "$log_file" ] || log_file=/dev/null
	[ -n "$loglevel" ] || loglevel=$(config_t_get global loglevel warning)
	set -- -node "$node" -tcp_redir_port "$tcp_redir_port" -udp_redir_port "$udp_redir_port" \
	 -local_socks_address "$socks_address" -local_socks_port "$socks_port" \
	 -dns_listen_port "$dns_listen_port" -dns_client_ip "$dns_client_ip" -dns_cache "$dns_cache" \
	 -dns_socks_address "$dns_socks_address" -dns_socks_port "$dns_socks_port" \
	 -remote_dns_tcp_server "$remote_dns_tcp_server" -remote_dns_doh "$remote_dns_doh" -loglevel "$loglevel"
	lua "$UTIL_XRAY" gen_config "$@" > "$config_file" || return 1
	ln_run /usr/bin/xray xray "$log_file" run -c "$config_file"
}

run_chinadns_ng() {
	local _flag _listen_port _dns_local _dns_trust _use_direct_list _use_proxy_list _gfwlist _chnroute _default_mode _default_tag
	export "$@" || return 1

	local _CONF_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.conf
	local _LOG_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.log
	_LOG_FILE="/dev/null"

	cat <<-EOF > ${_CONF_FILE}
		bind-addr 127.0.0.1
		bind-port ${_listen_port}
		china-dns ${_dns_local}
		trust-dns ${_dns_trust}
		ipset-name4 inet@passwall@passwall_chnroute
		ipset-name6 inet@passwall@passwall_chnroute6
	EOF

	node_addresses | grep -v -Fx "engage.cloudflareclient.com" | grep '[a-zA-Z]$' | sort -u > "${TMP_PATH}/vpslist"
	[ -s "${TMP_PATH}/vpslist" ] && {
		local vpslist4_set="inet@passwall@passwall_vpslist"
		local vpslist6_set="inet@passwall@passwall_vpslist6"
		cat <<-EOF >> ${_CONF_FILE}
			group vpslist
			group-dnl ${TMP_PATH}/vpslist
			group-upstream ${_dns_local}
			group-ipset ${vpslist4_set},${vpslist6_set}
		EOF
	}

	[ "${_use_direct_list}" = "1" ] && {
		local whitelist4_set="inet@passwall@passwall_whitelist"
		local whitelist6_set="inet@passwall@passwall_whitelist6"
		cat <<-EOF >> ${_CONF_FILE}
			group directlist
			group-dnl ${RULES_PATH}/direct_host
			group-upstream ${_dns_local}
			group-ipset ${whitelist4_set},${whitelist6_set}
		EOF
	}

	[ "${_use_proxy_list}" = "1" ] && {
		local blacklist4_set="inet@passwall@passwall_blacklist"
		local blacklist6_set="inet@passwall@passwall_blacklist6"
		cat <<-EOF >> ${_CONF_FILE}
			group proxylist
			group-dnl ${RULES_PATH}/proxy_host
			group-upstream ${_dns_trust}
			group-ipset ${blacklist4_set},${blacklist6_set}
		EOF
	}

	[ "${_gfwlist}" = "1" ] && {
		local gfwlist4_set="inet@passwall@passwall_gfwlist"
		local gfwlist6_set="inet@passwall@passwall_gfwlist6"
		cat <<-EOF >> ${_CONF_FILE}
			gfwlist-file ${RULES_PATH}/gfwlist
			add-taggfw-ip ${gfwlist4_set},${gfwlist6_set}
		EOF
	}

	#只使用gfwlist模式，GFW列表以外的域名及默认使用本地DNS
	[ "${_gfwlist}" = "1" ] && [ "${_chnroute}" = "0" ] && _default_tag="chn"
	#回中国模式，中国列表以外的域名及默认使用本地DNS
	[ "${_chnroute}" = "proxy" ] && _default_tag="chn"
	#全局模式，默认使用远程DNS
	[ "${_default_mode}" = "proxy" ] && [ "${_chnroute}" = "0" ] && [ "${_gfwlist}" = "0" ] && {
		_default_tag="gfw"
	}

	# 是否接受直连 DNS 空响应
	[ "${_default_tag}" = "none_noip" ] && echo "noip-as-chnip" >> ${_CONF_FILE}
	
	([ -z "${_default_tag}" ] || [ "${_default_tag}" = "smart" ] || [ "${_default_tag}" = "none_noip" ]) && _default_tag="none"
	echo "default-tag ${_default_tag}" >> ${_CONF_FILE}

	ln_run /usr/bin/chinadns-ng chinadns-ng "${_LOG_FILE}" -C ${_CONF_FILE}
}

run_socks() {
	local node="$1" port="$2"
	[ "$(config_n_get "$node" type)" = Xray ] || { echolog 核心 "节点 $node 不是 Xray 节点"; return 1; }
	run_xray "node=$node" socks_address=127.0.0.1 \
		"socks_port=$port" "config_file=$TMP_PATH/test.json"
}

run_redir() {
	local node proto local_port config_file log_file
	export "$@" || return 1
	[ "$(config_n_get "$node" type)" = Xray ] || { echolog 核心 "节点 $node 不是 Xray 节点"; return 1; }
	config_file="$TMP_ACL_PATH/default/$config_file"
	proto=$(printf '%s' "$proto" | tr 'A-Z' 'a-z')
	if [ "$(config_t_get global "log_$proto" 0)" = 1 ]; then
		log_file="$TMP_ACL_PATH/default/$log_file"
	else
		log_file=/dev/null
	fi
	if [ "$proto" = udp ]; then
		run_xray "node=$node" "udp_redir_port=$local_port" "config_file=$config_file" "log_file=$log_file"
		return $?
	fi

	tcp_node_socks_port=$(config_t_get global tcp_node_socks_port 1070)
	local socks_bind=127.0.0.1
	[ "$(config_t_get global tcp_node_socks_bind_local 1)" = 1 ] || socks_bind=0.0.0.0
	set --
	if [ "$TCP_UDP" = 1 ]; then
		UDP_REDIR_PORT=$local_port
		UDP_NODE=nil
		set -- "udp_redir_port=$local_port"
	fi
	local protocol=$(config_n_get "$node" protocol)
	local default_node=$(config_n_get "$node" default_node)
	local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
	if [ "$DNS_MODE" != xray ] && [ "$DNS_MODE" != udp ] &&
		[ "$protocol" = _shunt ] && [ "$default_node" = _direct ]; then
		DNS_MODE=xray
		v2ray_dns_mode=tcp
		debuglog DNS "代理 DNS 改用 Xray TCP，避免直连分流产生环回"
	fi
	if [ "$DNS_MODE" = xray ]; then
		resolve_dns=1
		resolve_dns_port=$dns_listen_port
		dns_listen_port=$((dns_listen_port + 1))
		set -- "$@" "dns_listen_port=$resolve_dns_port" dns_cache=0 "remote_dns_tcp_server=$REMOTE_DNS" \
			"dns_client_ip=$(config_t_get global dns_client_ip)"
		if [ "$v2ray_dns_mode" = tcp+doh ]; then
			set -- "$@" "remote_dns_doh=$(config_t_get global remote_dns_doh https://1.1.1.1/dns-query)"
		fi
	fi
	run_xray "node=$node" "tcp_redir_port=$local_port" \
		"socks_address=$socks_bind" "socks_port=$tcp_node_socks_port" \
		"config_file=$config_file" "log_file=$log_file" "$@" || return 1
	printf '%s\n' "127.0.0.1:$tcp_node_socks_port" > "$TMP_ACL_PATH/default/TCP_SOCKS_server"
}

start_redir() {
	local proto=${1}
	eval node=\$${proto}_NODE
	if [ "$node" != "nil" ]; then
		local config_file="${proto}.json"
		local log_file="${proto}.log"
		eval current_port=\$${proto}_REDIR_PORT
		local port protocol="$proto"
		[ "$proto:$TCP_UDP" != TCP:1 ] || protocol=tcp,udp
		port=$(get_new_port "$current_port" "$protocol") || return 1
		eval ${proto}_REDIR_PORT=$port
		run_redir node=$node proto=${proto} local_port=$port config_file=$config_file log_file=$log_file || return 1
	else
		[ "${proto}" = "UDP" ] && [ "$TCP_UDP" = "1" ] && return
		debuglog 核心 "${proto}节点没有选择或为空，不代理${proto}"
	fi
}

app_crontab() {
	local active="$1" file="$STATE_PATH/cron.next" week hour
	mkdir -p /etc/crontabs
	[ -f /etc/crontabs/root ] || touch /etc/crontabs/root
	# Remove only Passwall-owned entries, including obsolete jobs from older builds.
	sed '\|/usr/share/passwall/|d; \|/etc/init.d/passwall|d' /etc/crontabs/root > "$file" || return 1
	if [ "$active" = 1 ] && [ "$(config_t_get global_rules auto_update 0)" = 1 ]; then
		week=$(config_t_get global_rules week_update 7)
		hour=$(config_t_get global_rules time_update 6)
		case "$week" in
			0|1|2|3|4|5|6) ;;
			7) week='*' ;;
			*) week='' ;;
		esac
		case "$hour" in ''|*[!0-9]*) hour='' ;; esac
		if [ -n "$week" ] && [ -n "$hour" ] && [ "$hour" -le 23 ]; then
			printf '0 %s * * %s %s/rule_update.sh run > /dev/null 2>&1\n' "$hour" "$week" "$APP_PATH" >> "$file"
		fi
	fi
	if cmp -s "$file" /etc/crontabs/root; then
		rm -f "$file"
	else
		cat "$file" > /etc/crontabs/root || return 1
		rm -f "$file"
		/etc/init.d/cron restart 9>&- || return 1
	fi
}

start_dns() {
	REMOTE_DNS=$(dns_endpoints "$REMOTE_DNS") || return 1
	LOCAL_DNS=$(dns_endpoints "$LOCAL_DNS") || return 1
	IPT_APPEND_DNS="$LOCAL_DNS"
	debuglog DNS "生成 DNS 配置"

	local china_ng_local_dns=$(chinadns_local_servers "$LOCAL_DNS")
	local direct_dns_mode=$(config_t_get global direct_dns_mode "auto")
	case "$direct_dns_mode" in
		udp)
			LOCAL_DNS=$(dns_endpoints "$(config_t_get global direct_dns_udp 223.5.5.5)") || return 1
			china_ng_local_dns=${LOCAL_DNS}
			IPT_APPEND_DNS=${LOCAL_DNS}
		;;
		tcp)
			LOCAL_DNS="127.0.0.1#${dns_listen_port}"
			dns_listen_port=$(expr $dns_listen_port + 1)
			local DIRECT_DNS
			DIRECT_DNS=$(dns_endpoints "$(config_t_get global direct_dns_tcp 223.5.5.5)") || return 1
			china_ng_local_dns="tcp://${DIRECT_DNS}"
			IPT_APPEND_DNS="${LOCAL_DNS},${DIRECT_DNS}"
			ln_run /usr/bin/dns2tcp dns2tcp "/dev/null" -L "${LOCAL_DNS}" -R "$(first_dns "$DIRECT_DNS")" -v || return 1
			debuglog DNS "dns2tcp(${LOCAL_DNS}) -> tcp://$(first_dns "$DIRECT_DNS")"
		;;
		auto)
			#Automatic logic is already done by default
			:
		;;
	esac

	TUN_DNS="127.0.0.1#${dns_listen_port}"
	[ "${resolve_dns}" == "1" ] && TUN_DNS="127.0.0.1#${resolve_dns_port}"

	case "$DNS_MODE" in
	xray)
		[ "${resolve_dns}" == "0" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=/dev/null
			local remote_dns_doh=""
			if [ "$(config_t_get global v2ray_dns_mode tcp)" = tcp+doh ]; then
				remote_dns_doh=$(config_t_get global remote_dns_doh https://1.1.1.1/dns-query)
			fi
			run_xray "config_file=$config_file" "log_file=$log_file" dns_cache=0 \
				"dns_listen_port=$dns_listen_port" "dns_client_ip=$(config_t_get global dns_client_ip)" \
				"remote_dns_tcp_server=$REMOTE_DNS" "remote_dns_doh=$remote_dns_doh" \
				dns_socks_address=127.0.0.1 "dns_socks_port=$tcp_node_socks_port" || return 1
			debuglog DNS "Xray DNS(${TUN_DNS})：TCP ${REMOTE_DNS}${remote_dns_doh:+，DoH ${remote_dns_doh}}"

		}
	;;
	udp)
		if [ "$DNS_SHUNT" = "chinadns-ng" ]; then
			local china_ng_listen_port=${dns_listen_port}
			local china_ng_trust_dns="udp://$(first_dns "$REMOTE_DNS")"
		else
			TUN_DNS="$(first_dns "$REMOTE_DNS")"
			debuglog DNS "udp://${TUN_DNS}"
		fi
	;;
	*)
		if [ "$DNS_SHUNT" = "chinadns-ng" ]; then
			local china_ng_listen_port=${dns_listen_port}
			local china_ng_trust_dns="tcp://$(first_dns "$REMOTE_DNS")"
		else
			ln_run /usr/bin/dns2tcp dns2tcp "/dev/null" -L "${TUN_DNS}" -R "$(first_dns "$REMOTE_DNS")" -v || return 1
			debuglog DNS "dns2tcp(${TUN_DNS}) -> tcp://$(first_dns "$REMOTE_DNS")"
		fi
	;;
	esac

	[ "$DNS_SHUNT" = "chinadns-ng" ] && {
		[ -z "${china_ng_listen_port}" ] && local china_ng_listen_port=$(expr $dns_listen_port + 1)
		local china_ng_listen="127.0.0.1#${china_ng_listen_port}"
		[ -z "${china_ng_trust_dns}" ] && local china_ng_trust_dns=${TUN_DNS}

		run_chinadns_ng \
			_flag="default" \
			_listen_port=${china_ng_listen_port} \
			_dns_local=${china_ng_local_dns} \
			_dns_trust=${china_ng_trust_dns} \
			_use_direct_list=${USE_DIRECT_LIST} \
			_use_proxy_list=${USE_PROXY_LIST} \
			_gfwlist=${USE_GFW_LIST} \
			_chnroute=${CHN_LIST} \
			_default_mode=${TCP_PROXY_MODE} \
			_default_tag=$(config_t_get global chinadns_ng_default_tag smart) || return 1

		debuglog DNS "ChinaDNS-NG(${china_ng_listen})：直连DNS：${china_ng_local_dns}，可信DNS：${china_ng_trust_dns}"
	}

	CHINADNS_DNS=${china_ng_listen:-0}
}

app_dns_generate() {
	local work="$1"
	lua "$APP_PATH/helper_dnsmasq_add.lua" \
		-DNSMASQ_CONF_FILE "$work/dnsmasq.conf" \
		-LOCAL_DNS "${LOCAL_DNS:-nil}" \
		-TUN_DNS "${TUN_DNS:-nil}" \
		-USE_DEFAULT_DNS "$(config_t_get global use_default_dns direct)" -CHINADNS_DNS "${CHINADNS_DNS:-0}" \
		-USE_DIRECT_LIST "$USE_DIRECT_LIST" -USE_PROXY_LIST "$USE_PROXY_LIST" \
		-USE_BLOCK_LIST "$USE_BLOCK_LIST" -USE_GFW_LIST "$USE_GFW_LIST" -CHN_LIST "$CHN_LIST" \
		-TCP_NODE "$TCP_NODE" -DEFAULT_PROXY_MODE "$TCP_PROXY_MODE" || return 1
	sha256sum /etc/hosts > "$work/hosts.sha256" || return 1
}

app_dns_check() {
	local work="$1"
	dnsmasq --test --conf-file="$work/dnsmasq.conf" > "$work/dns-check.log" 2>&1 || {
		echolog DNS "DNS 候选配置检查失败：$(cat "$work/dns-check.log")"
		return 1
	}
}

app_dns_restart() {
	local work="$1" server removed=0 status=0 had_delta=0
	local delta=/tmp/.uci/dhcp
	# Keep UCI's global upstreams configured, but do not let them race the
	# default upstream selected by Passwall in the running dnsmasq instance.
	if grep -q '^server=[^/]' "$DNSMASQ_CONF" 2>/dev/null; then
		if [ -e "$delta" ]; then
			cp -p "$delta" "$work/dhcp.delta" || return 1
			had_delta=1
		fi
		for server in $(uci -q get 'dhcp.@dnsmasq[0].server'); do
			case "$server" in */*) continue ;; esac
			uci -q del_list "dhcp.@dnsmasq[0].server=$server" || status=1
			removed=1
		done
	fi
	if [ "$status" = 0 ]; then
		/etc/init.d/dnsmasq restart 9>&- >/dev/null 2>&1
		status=$?
	fi
	if [ "$removed" = 1 ]; then
		if [ "$had_delta" = 1 ]; then
			cp -p "$work/dhcp.delta" "$delta" || return 1
		else
			rm -f "$delta" || return 1
		fi
	fi
	return "$status"
}

app_dns_restore() {
	local work="$1"
	if [ -e "$work/old.conf" ]; then
		mv "$work/old.conf" "$DNSMASQ_CONF" || return 1
	else
		rm -f "$DNSMASQ_CONF" || return 1
	fi
	app_dns_restart "$work"
}

app_dns_apply() {
	APP_DNS_APPLIED=0
	local work="$1"
	if [ "${APP_DNS_REDIRECT_CHANGED:-0}" = 0 ] &&
		cmp -s "$work/hosts.sha256" "$STATE_PATH/hosts.sha256" &&
		cmp -s "$work/dnsmasq.conf" "$DNSMASQ_CONF"; then
		return 0
	fi
	[ "${2:-}" = prepared ] || app_dns_check "$work" || return 1
	mkdir -p /tmp/dnsmasq.d || return 1
	if [ -e "$DNSMASQ_CONF" ]; then
		cp "$DNSMASQ_CONF" "$work/old.conf" || return 1
	fi
	mv "$work/dnsmasq.conf" "$DNSMASQ_CONF" || return 1
	if ! app_dns_restart "$work"; then
		app_dns_restore "$work"
		echolog DNS "DNS 配置应用失败，已尝试恢复旧配置"
		return 1
	fi
	APP_DNS_APPLIED=1
	debuglog DNS "DNS 配置已更新"
}

app_core_signature() {
	local config
	config=$(lua "$APP_PATH/core_config.lua") || return 1
	printf '%s\n' "$config" | sha256sum | cut -d ' ' -f 1
}

# Prepare one candidate while the current service keeps running. procd uses
# these same files once the candidate is activated.
app_prepare_start() {
	local TMP_PATH="$1" TMP_ACL_PATH="$1/acl" TMP_IFACE_PATH="$1/iface" PROCESS_DIR="$1/processes"
	local PASSWALL_TMP_PATH="$TMP_PATH"
	export PASSWALL_TMP_PATH
	mkdir -p "$TMP_ACL_PATH/default" "$TMP_IFACE_PATH" "$PROCESS_DIR" "$TMP_PATH/apply" || return 1
	app_core_signature > "$TMP_PATH/core.sha256" || return 1
	if [ "$ENABLED_DEFAULT_ACL" = 1 ]; then
		start_redir TCP && start_redir UDP || return 1
	fi
	start_dns &&
		lua "$APP_PATH/process.lua" validate "$PROCESS_DIR" &&
		nft_read_config && nft_network_snapshot > "$TMP_PATH/apply/network" &&
		nft_prepare "$TMP_PATH/apply" &&
		app_dns_generate "$TMP_PATH/apply" && app_dns_check "$TMP_PATH/apply" || return 1
	[ ! -f "$STATE_PATH/running" ] || nft_check "$TMP_PATH/apply"
}

app_runtime_save() {
	local key
	mkdir -p "$STATE_PATH/runtime/config" && chmod 700 "$STATE_PATH/runtime/config" || return 1
	cp "$CONFIG_INPUT/passwall" "$STATE_PATH/runtime/config/passwall.next" &&
		mv "$STATE_PATH/runtime/config/passwall.next" "$STATE_PATH/runtime/config/passwall" || return 1
	for key in TCP_REDIR_PORT UDP_REDIR_PORT LOCAL_DNS TUN_DNS IPT_APPEND_DNS CHINADNS_DNS; do
		eval 'printf "%s\n" "${'"$key"':-}"' > "$STATE_PATH/runtime/$key"
	done
}

app_runtime_load() {
	local key value
	for key in TCP_REDIR_PORT UDP_REDIR_PORT LOCAL_DNS TUN_DNS IPT_APPEND_DNS CHINADNS_DNS; do
		[ -f "$STATE_PATH/runtime/$key" ] || continue
		value=$(cat "$STATE_PATH/runtime/$key")
		export "$key=$value"
	done
}

app_processes_stop() {
	lua "$APP_PATH/process.lua" stop
}

app_system_desired() {
	SYSTEM_DNS_REDIRECT=1
	SYSTEM_FLOW_OFFLOAD=1
	if [ "$1" = running ]; then
		[ "$(config_t_get global dns_redirect 1)" != 1 ] || SYSTEM_DNS_REDIRECT=0
		[ "$(config_t_get global_forwarding iproute_shunt 0)" != 1 ] || SYSTEM_FLOW_OFFLOAD=0
	fi
}

app_system_matches() {
	app_system_desired running
	[ "$(uci -q get 'dhcp.@dnsmasq[0].dns_redirect')" = "$SYSTEM_DNS_REDIRECT" ] &&
		[ "$(uci -q get 'firewall.@defaults[0].flow_offloading')" = "$SYSTEM_FLOW_OFFLOAD" ] &&
		[ "$(uci -q get 'firewall.@defaults[0].flow_offloading_hw')" = "$SYSTEM_FLOW_OFFLOAD" ]
}

app_system_save() {
	uci -q get 'dhcp.@dnsmasq[0].dns_redirect' > "$1/system-dns" || :
	uci -q get 'firewall.@defaults[0].flow_offloading' > "$1/system-flow" || :
	uci -q get 'firewall.@defaults[0].flow_offloading_hw' > "$1/system-hw" || :
}

app_system_set() {
	local key="$1" value="$2"
	[ "$(uci -q get "$key")" != "$value" ] || return 0
	if [ -n "$value" ]; then uci set "$key=$value"; else uci -q delete "$key"; fi || return 1
	case "$key" in
		dhcp.*) APP_DNS_REDIRECT_CHANGED=1 ;;
		firewall.*) APP_FLOW_OFFLOAD_CHANGED=1 ;;
	esac
}

app_system_commit() {
	local output
	if [ "$APP_DNS_REDIRECT_CHANGED" = 1 ]; then uci commit dhcp || return 1; fi
	if [ "$APP_FLOW_OFFLOAD_CHANGED" = 1 ]; then
		uci commit firewall || return 1
		# fw4's include must not enqueue another update caused by our own change.
		output=$(PASSWALL_FW_RELOAD=1 /etc/init.d/firewall reload 9>&- 2>&1) || {
			echolog 防火墙 "重载失败：$output"
			return 1
		}
		[ -z "$output" ] || debuglog 防火墙 "$output"
	fi
}

app_system_apply() {
	APP_DNS_REDIRECT_CHANGED=0
	APP_FLOW_OFFLOAD_CHANGED=0
	app_system_desired "$1"
	app_system_set 'dhcp.@dnsmasq[0].dns_redirect' "$SYSTEM_DNS_REDIRECT" &&
		app_system_set 'firewall.@defaults[0].flow_offloading' "$SYSTEM_FLOW_OFFLOAD" &&
		app_system_set 'firewall.@defaults[0].flow_offloading_hw' "$SYSTEM_FLOW_OFFLOAD" &&
		app_system_commit
}

app_system_restore() {
	APP_DNS_REDIRECT_CHANGED=0
	APP_FLOW_OFFLOAD_CHANGED=0
	app_system_set 'dhcp.@dnsmasq[0].dns_redirect' "$(cat "$1/system-dns")" &&
		app_system_set 'firewall.@defaults[0].flow_offloading' "$(cat "$1/system-flow")" &&
		app_system_set 'firewall.@defaults[0].flow_offloading_hw' "$(cat "$1/system-hw")" &&
		app_system_commit || return 1
	[ "$APP_DNS_REDIRECT_CHANGED" = 0 ] || app_dns_restart "$1"
}

app_apply_dns() {
	local china_dns=
	app_dns_apply "$1" "${2:-}" || return 1
	# Cold start already loaded the DNS snapshot. dnsmasq mode has no
	# separate ChinaDNS process to replace.
	[ "${2:-}" != prepared ] && [ "${CHINADNS_DNS:-0}" != 0 ] || return 0
	if [ "$(config_t_get global direct_dns_mode auto)" = auto ]; then
		china_dns=$(chinadns_local_servers "$LOCAL_DNS")
	fi
	lua "$APP_PATH/process.lua" reload_files "$PROCESS_DIR" "$china_dns"
}

app_apply() {
	local work="$1" routes_changed=0
	if ! cmp -s "$work/network" "$STATE_PATH/network"; then
		routes_changed=1
		nft_routes_save "$work"
		if ! nft_routes; then
			nft_routes_restore "$work"
			echolog 路由 "策略路由更新失败，已尝试恢复原路由"
			return 1
		fi
	fi
	app_system_save "$work"
	if ! app_system_apply running || ! nft_commit "$work"; then
		app_system_restore "$work"
		[ "$routes_changed" = 0 ] || nft_routes_restore "$work"
		return 1
	fi
	if ! app_apply_dns "$work" "${2:-}"; then
		[ "${APP_DNS_APPLIED:-0}" != 1 ] || app_dns_restore "$work"
		if [ -s "$STATE_PATH/rules.nft" ]; then nft_restore; else nft_stop; fi
		app_system_restore "$work"
		[ "$routes_changed" = 0 ] || nft_routes_restore "$work"
		return 1
	fi
	mv "$work/rules.nft" "$STATE_PATH/rules.nft" || return 1
	mv "$work/network" "$STATE_PATH/network" || return 1
	mv "$work/hosts.sha256" "$STATE_PATH/hosts.sha256" || return 1
}

app_reload() {
	local reason="${1:-config}" work new_local_dns="$LOCAL_DNS"
	if [ "$reason" = config ]; then
		rm -f "$STATE_PATH/last_error"
		[ "$ENABLED" = 1 ] || { app_stop; return $?; }
		[ -f "$STATE_PATH/running" ] || { app_start; return $?; }
	fi
	[ -f "$STATE_PATH/running" ] || return 0
	if [ "$reason" = config ] || [ "$reason" = rules ]; then
		if [ "$(app_core_signature)" != "$(cat "$STATE_PATH/core.sha256")" ]; then
			local saved_error status
			[ "$reason" != rules ] || saved_error=$(cat "$STATE_PATH/last_error" 2>/dev/null)
			app_start restart
			status=$?
			[ -z "$saved_error" ] || printf '%s\n' "$saved_error" > "$STATE_PATH/last_error"
			return "$status"
		fi
	fi
	app_runtime_load
	if [ "$(config_t_get global direct_dns_mode auto)" = auto ]; then
		LOCAL_DNS=$(dns_endpoints "$new_local_dns") || return 1
		IPT_APPEND_DNS="$LOCAL_DNS"
	fi
	nft_read_config || return 1
	work=$(mktemp -d "$STATE_PATH/reload.XXXXXX") || return 1
	nft_network_snapshot > "$work/network"
	if [ "$reason" = network ] &&
		cmp -s "$work/network" "$STATE_PATH/network" && app_system_matches && nft_present; then
		rm -rf "$work"
		return 0
	fi
	if ! nft_prepare "$work" || ! app_dns_generate "$work"; then
		rm -rf "$work"
		return 1
	fi
	if ! app_apply "$work"; then
		rm -rf "$work"
		return 1
	fi
	if ! app_runtime_save || { [ "$reason" = config ] && ! app_crontab 1; }; then
		rm -rf "$work"
		return 1
	fi
	rm -rf "$work"
	[ "$reason" != config ] || rm -f "$STATE_PATH/last_error"
	case "$reason" in config) reason=配置 ;; rules) reason=规则 ;; network) reason=网络 ;; firewall) reason=防火墙 ;; esac
	echolog 服务 "热更新完成：$reason"
}

app_update_rules() {
	local source="$1" backup name count=0 failed=0
	[ -d "$source" ] || return 1
	backup=$(mktemp -d "$RULES_PATH/.update.XXXXXX") || return 1
	for name in gfwlist chnroute chnroute6; do
		[ -f "$source/$name" ] || continue
		[ -s "$source/$name" ] || { rm -rf "$backup"; return 1; }
		cp "$source/$name" "$backup/$name.new" || { rm -rf "$backup"; return 1; }
		[ ! -e "$RULES_PATH/$name" ] || cp -p "$RULES_PATH/$name" "$backup/$name.old" || { rm -rf "$backup"; return 1; }
		count=$((count + 1))
	done
	[ "$count" -gt 0 ] || { rm -rf "$backup"; return 1; }
	for name in gfwlist chnroute chnroute6; do
		[ ! -f "$backup/$name.new" ] || mv "$backup/$name.new" "$RULES_PATH/$name" || { failed=1; break; }
	done
	if [ "$failed" = 1 ] || ! app_reload rules; then
		for name in gfwlist chnroute chnroute6; do
			[ -f "$source/$name" ] || continue
			if [ -f "$backup/$name.old" ]; then
				mv "$backup/$name.old" "$RULES_PATH/$name"
			else
				rm -f "$RULES_PATH/$name"
			fi
		done
		rm -rf "$backup"
		echolog 规则 "规则应用失败，已保留旧规则文件"
		return 1
	fi
	for backup in "$RULES_PATH"/.update.??????; do
		[ -d "$backup" ] || continue
		rm -rf -- "$backup" || echolog 规则 "无法清理旧规则备份：$backup"
	done
	debuglog 规则 "规则文件发布完成"
}

app_remove_instance() {
	local active
	active=$(readlink "$TMP_PATH")
	case "$active" in "$STATE_PATH"/service.??????) rm -rf "$active" ;; esac
	rm -rf "$TMP_PATH" "$PROCESS_DIR"
}

app_start() {
	[ "$ENABLED" = 1 ] || { app_stop; return $?; }
	if [ "${1:-}" != restart ] && [ -f "$STATE_PATH/running" ]; then
		app_reload config
		return $?
	fi
	ulimit -n 65535
	local work
	work=$(mktemp -d "$STATE_PATH/service.XXXXXX") || return 1
	rm -f "$STATE_PATH/last_error"
	if ! app_prepare_start "$work" > "$work/check.log" 2>&1; then
		if [ ! -s "$STATE_PATH/last_error" ] && [ -s "$work/check.log" ]; then
			tail -n 1 "$work/check.log" > "$STATE_PATH/last_error"
			echolog 核心 "$(cat "$STATE_PATH/last_error")"
		fi
		rm -rf "$work"
		return 1
	fi
	rm -f "$work/check.log"
	if [ "${1:-}" = restart ]; then
		if ! app_processes_stop; then
			rm -rf "$work"
			return 1
		fi
		rm -f "$STATE_PATH/running"
	fi
	# Keep the generated paths intact. The stable link is used by LuCI and
	# the rule updater to find the currently active service files.
	app_remove_instance
	if ! ln -s "$work" "$TMP_PATH" || ! mv "$work/processes" "$PROCESS_DIR"; then
		app_stop
		rm -rf "$work"
		return 1
	fi
	if ! lua "$APP_PATH/process.lua" start "$PROCESS_DIR" ||
		! app_apply "$work/apply" prepared ||
		! app_runtime_save || ! mv "$work/core.sha256" "$STATE_PATH/core.sha256" ||
		! app_crontab 1; then
		app_record_error
		app_stop
		return 1
	fi
	nft_include
	touch "$STATE_PATH/running"
	rm -rf "$work/apply"
	echolog 服务 "启动完成：$( [ "$iproute_shunt" = 1 ] && echo PBR || echo TPROXY )"
}

app_stop() {
	local failed=0 dns_removed=0
	rm -f "$STATE_PATH/running"
	nft_stop || failed=1
	if [ -n "$FWI" ]; then printf '#!/bin/sh\n' > "$FWI" || failed=1; fi
	app_processes_stop || failed=1
	app_crontab 0 || failed=1
	if [ -e "$DNSMASQ_CONF" ]; then
		rm -f "$DNSMASQ_CONF" || failed=1
		dns_removed=1
	fi
	app_system_apply stopped || failed=1
	if [ "$dns_removed" = 1 ] || [ "$APP_DNS_REDIRECT_CHANGED" = 1 ]; then
		/etc/init.d/dnsmasq restart 9>&- >/dev/null 2>&1 || failed=1
	fi
	if [ "$failed" = 0 ]; then
		app_remove_instance
		rm -rf "$STATE_PATH/runtime"
		rm -f "$STATE_PATH/core.sha256" "$STATE_PATH/hosts.sha256" "$STATE_PATH/network" "$STATE_PATH/rules.nft"
		echolog 服务 "已停止"
	else
		echolog 服务 "Passwall 停止时有步骤失败，已继续清理并保留运行记录"
	fi
	return "$failed"
}

app_record_error() {
	[ ! -s "$STATE_PATH/last_error" ] || return 0
	tail -n 1 "$LOG_FILE" 2>/dev/null | sed 's/^[^]]*] //' > "$STATE_PATH/last_error"
	[ -s "$STATE_PATH/last_error" ] || printf '%s\n' '应用失败，请查看运行日志' > "$STATE_PATH/last_error"
}

if [ "$1" = get_new_port ]; then
	get_new_port "$2" "$3"
	exit $?
fi

# Network notifications are already serialized by the init script. A
# stopped service needs no configuration loading or probing.
case "$1:$2" in
 reload:network|reload:firewall|reload:rules)
  [ -f "$STATE_PATH/running" ] || exit 0
 ;;
esac

mkdir -p "$STATE_PATH" || exit 1
if [ "$1" = stop ]; then
	. "$APP_PATH/nftables.sh"
	app_stop
	exit $?
fi

export PASSWALL_TMP_PATH="$TMP_PATH"
export XRAY_LOCATION_ASSET=/usr/share/v2ray/
CONFIG_INPUT=$(mktemp -d "$STATE_PATH/config.XXXXXX") || exit 1
trap 'rm -rf "$CONFIG_INPUT"' EXIT
case "$1:$2" in
 run_socks:*)
  [ -z "${PASSWALL_CONFIG_DIR:-}" ] || cp "$PASSWALL_CONFIG_DIR/passwall" "$CONFIG_INPUT/passwall" || exit 1
 ;;
 reload:network|reload:firewall|reload:rules|update_rules:*)
  [ ! -f "$STATE_PATH/running" ] || cp "$STATE_PATH/runtime/config/passwall" "$CONFIG_INPUT/passwall" || exit 1
 ;;
esac
if [ ! -f "$CONFIG_INPUT/passwall" ]; then
 uci -q -S export "$CONFIG" > "$CONFIG_INPUT/passwall" || exit 1
fi
export PASSWALL_CONFIG_DIR="$CONFIG_INPUT"
# Native shell config callbacks, with an isolated delta directory for the snapshot.
config_data=$(/sbin/uci -c "$CONFIG_INPUT" -t "$CONFIG_INPUT" -S -n export "$CONFIG") || exit 1
eval "$config_data"
unset config_data

if [ "$1" = run_socks ]; then
	mkdir -p "$TMP_IFACE_PATH" || exit 1
	run_socks "$2" "$3"
	exit $?
fi

ENABLED=$(config_t_get global enabled 0)
TCP_REDIR_PORT=1041
TCP_NODE=$(config_t_get global tcp_node nil)
UDP_REDIR_PORT=1051
UDP_NODE=$(config_t_get global udp_node nil)
TCP_UDP=0
[ "$UDP_NODE" == "tcp" ] && {
	UDP_NODE=$TCP_NODE
	TCP_UDP=1
}
[ "$ENABLED" == 1 ] && {
	[ "$TCP_NODE" != "nil" ] && [ "$(config_get_type $TCP_NODE nil)" != "nil" ] && ENABLED_DEFAULT_ACL=1
	[ "$UDP_NODE" != "nil" ] && [ "$(config_get_type $UDP_NODE nil)" != "nil" ] && ENABLED_DEFAULT_ACL=1
}
TCP_REDIR_PORTS=$(config_t_get global_forwarding tcp_redir_ports '1:65535')
UDP_REDIR_PORTS=$(config_t_get global_forwarding udp_redir_ports '1:65535')
TCP_NO_REDIR_PORTS=$(config_t_get global_forwarding tcp_no_redir_ports 'disable')
UDP_NO_REDIR_PORTS=$(config_t_get global_forwarding udp_no_redir_ports 'disable')
TCP_PROXY_DROP_PORTS=$(config_t_get global_forwarding tcp_proxy_drop_ports 'disable')
UDP_PROXY_DROP_PORTS=$(config_t_get global_forwarding udp_proxy_drop_ports 'disable')
USE_DIRECT_LIST=$(config_t_get global use_direct_list 0)
USE_PROXY_LIST=$(config_t_get global use_proxy_list 0)
USE_BLOCK_LIST=$(config_t_get global use_block_list 0)
USE_GFW_LIST=$(config_t_get global use_gfw_list 0)
CHN_LIST=$(config_t_get global chn_list direct)
TCP_PROXY_MODE=$(config_t_get global tcp_proxy_mode proxy)
UDP_PROXY_MODE=$(config_t_get global udp_proxy_mode proxy)
[ "${TCP_PROXY_MODE}" != "disable" ] && TCP_PROXY_MODE="proxy"
[ "${UDP_PROXY_MODE}" != "disable" ] && UDP_PROXY_MODE="proxy"
LOCALHOST_PROXY=$(config_t_get global localhost_proxy 1)
DNS_SHUNT=$(config_t_get global dns_shunt dnsmasq)
DNS_MODE=$(config_t_get global dns_mode tcp)
REMOTE_DNS=$(config_t_get global remote_dns 1.1.1.1:53)
dns_listen_port=${DNS_PORT}

RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto

ISP_DNS=$(awk '$1 == "nameserver" && $2 !~ /:/ && $2 != "0.0.0.0" && $2 != "127.0.0.1" {print $2}' "$RESOLVFILE" 2>/dev/null | sort -u)
ISP_DNS6=$(awk '$1 == "nameserver" && $2 ~ /:/ {sub(/%.*/, "", $2); if ($2 != "::" && $2 != "::1") print $2}' "$RESOLVFILE" 2>/dev/null | sort -u)

DEFAULT_DNS=$(uci -q get 'dhcp.@dnsmasq[0].server' | system_dns_upstreams)
[ -n "$DEFAULT_DNS" ] || DEFAULT_DNS=$(printf '%s\n' "$ISP_DNS" | system_dns_upstreams)
LOCAL_DNS="${DEFAULT_DNS:-119.29.29.29,223.5.5.5}"
IPT_APPEND_DNS=${LOCAL_DNS}


mkdir -p /tmp/etc || exit 1

# nftables.sh is a library, never a second command dispatcher.
. "$APP_PATH/nftables.sh"

arg1=$1
shift
case $arg1 in
restart)
	app_start restart
	;;
start)
	app_start
	;;
reload)
	app_reload "${1:-config}"
	;;
update_rules)
	app_update_rules "$1"
	;;
esac

result=$?
case "$arg1:$1" in
	start:*|restart:*|reload:config)
		[ "$result" = 0 ] || app_record_error
	;;
esac
exit "$result"
