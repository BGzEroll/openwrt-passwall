#!/bin/sh
# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2023 xiaorouji

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall
STATE_PATH=/var/run/passwall
TMP_PATH=/tmp/etc/$CONFIG
TMP_BIN_PATH=$TMP_PATH/bin
TMP_SCRIPT_FUNC_PATH=$TMP_PATH/script_func
TMP_ID_PATH=$TMP_PATH/id
TMP_ROUTE_PATH=$TMP_PATH/route
TMP_ACL_PATH=$TMP_PATH/acl
TMP_IFACE_PATH=$TMP_PATH/iface
TMP_PATH2=/tmp/etc/${CONFIG}_tmp
DNSMASQ_PATH=/etc/dnsmasq.d
TMP_DNSMASQ_PATH=/tmp/dnsmasq.d/passwall
LOG_FILE=/tmp/log/$CONFIG.log
APP_PATH=/usr/share/$CONFIG
RULES_PATH=/usr/share/${CONFIG}/rules
DNS_PORT=15353
TUN_DNS="127.0.0.1#${DNS_PORT}"
LOCAL_DNS=119.29.29.29,223.5.5.5
DEFAULT_DNS=
IPT_APPEND_DNS=
ENABLED_DEFAULT_ACL=0
resolve_dns=0
use_tcp_node_resolve_dns=0
use_udp_node_resolve_dns=0
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall
UTIL_SINGBOX=$LUA_UTIL_PATH/util_sing-box.lua
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua
UTIL_TROJAN=$LUA_UTIL_PATH/util_trojan.lua
UTIL_NAIVE=$LUA_UTIL_PATH/util_naiveproxy.lua
UTIL_HYSTERIA2=$LUA_UTIL_PATH/util_hysteria2.lua
UTIL_TUIC=$LUA_UTIL_PATH/util_tuic.lua

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

config_get_type() {
	local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null)
	echo "${ret:=$2}"
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
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

get_ip_port_from() {
	local __host=${1}; shift 1
	local __ipv=${1}; shift 1
	local __portv=${1}; shift 1
	local __ucipriority=${1}; shift 1

	local val1 val2
	if [ -n "${__ucipriority}" ]; then
		val2=$(config_n_get ${__host} port $(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p'))
		val1=$(config_n_get ${__host} address "${__host%%${val2:+[:#]${val2}*}}")
	else
		val2=$(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p')
		val1="${__host%%${val2:+[:#]${val2}*}}"
	fi
	eval "${__ipv}=\"$val1\"; ${__portv}=\"$val2\""
}

host_from_url(){
	local f=${1}

	## Remove protocol part of url  ##
	f="${f##http://}"
	f="${f##https://}"
	f="${f##ftp://}"
	f="${f##sftp://}"

	## Remove username and/or username:password part of URL  ##
	f="${f##*:*@}"
	f="${f##*@}"

	## Remove rest of urls ##
	f="${f%%/*}"
	echo "${f%%:*}"
}

hosts_foreach() {
	local __hosts
	eval "__hosts=\$${1}"; shift 1
	local __func=${1}; shift 1
	local __default_port=${1}; shift 1
	local __ret=1

	[ -z "${__hosts}" ] && return 0
	local __ip __port
	for __host in $(echo $__hosts | sed 's/[ ,]/\n/g'); do
		get_ip_port_from "$__host" "__ip" "__port"
		eval "$__func \"${__host}\" \"\${__ip}\" \"\${__port:-${__default_port}}\" \"$@\""
		__ret=$?
		[ ${__ret} -ge ${ERROR_NO_CATCH:-1} ] && return ${__ret}
	done
}

check_host() {
	local f=${1}
	a=$(echo $f | grep "\/")
	[ -n "$a" ] && return 1
	# 判断是否包含汉字~
	local tmp=$(echo -n $f | awk '{print gensub(/[!-~]/,"","g",$0)}')
	[ -n "$tmp" ] && return 1
	return 0
}

get_first_dns() {
	local __hosts_val=${1}; shift 1
	__first() {
		[ -z "${2}" ] && return 0
		echo "${2}#${3}"
		return 1
	}
	eval "hosts_foreach \"${__hosts_val}\" __first \"$@\""
}

check_port_exists() {
	port=$1
	protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

check_depends() {
	local depends
	for depends in "kmod-nft-socket" "kmod-nft-tproxy" "kmod-nft-nat"; do
		[ -s "/usr/lib/opkg/info/${depends}.control" ] || echolog "nftables透明代理基础依赖 $depends 未安装..."
	done
}

check_ver() {
	local version1="$1"
	local version2="$2"
	local i v1 v1_1 v1_2 v1_3 v2 v2_1 v2_2 v2_3
	IFS='.'; set -- $version1; v1_1=${1:-0}; v1_2=${2:-0}; v1_3=${3:-0}
	IFS='.'; set -- $version2; v2_1=${1:-0}; v2_2=${2:-0}; v2_3=${3:-0}
	IFS=
	for i in 1 2 3; do
		eval v1=\$v1_$i
		eval v2=\$v2_$i
		if [ "$v1" -gt "$v2" ]; then
			# $1 大于 $2
			echo 0
			return
		elif [ "$v1" -lt "$v2" ]; then
			# $1 小于 $2
			echo 1
			return
		fi
	done
	# $1 等于 $2
	echo 255
}

get_new_port() {
	port=$1
	[ "$port" == "auto" ] && port=2082
	protocol=$(echo $2 | tr 'A-Z' 'a-z')
	result=$(check_port_exists $port $protocol)
	if [ "$result" != 0 ]; then
		temp=
		if [ "$port" -lt 65535 ]; then
			temp=$(expr $port + 1)
		elif [ "$port" -gt 1 ]; then
			temp=$(expr $port - 1)
		fi
		get_new_port $temp $protocol
	else
		echo $port
	fi
}

binary_path() {
	local path="/usr/bin/$1"
	[ "$1" != dnsmasq ] || path=/usr/sbin/dnsmasq
	[ -x "$path" ] && printf '%s\n' "$path"
}

eval_set_val() {
	for i in $@; do
		for j in $i; do
			eval $j
		done
	done
}

ln_run() {
	local file_func=${1}
	local ln_name=${2}
	local output=${3}

	shift 3;
	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || echolog "  - $(readlink ${file_func}) 没有执行权限，无法启动：${file_func} $*"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || echolog "  - 找不到 ${ln_name}，无法启动..."
	[ -n "$file_func" ] && [ -x "$file_func" ] || { APP_LAUNCH_FAILED=1; return 1; }
	("$file_func" "$@" 9>&- >"$output" 2>&1) &
	echo $! >> "$STATE_PATH/pids"
	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-echolog "  - ${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo "nil"
		return
	}
	echo $(lua -e "local api = require 'luci.passwall.api' print(api.${func})")
}

run_ipt2socks() {
	local flag proto tcp_tproxy local_port socks_address socks_port socks_username socks_password log_file
	local _extra_param=""
	eval_set_val $@
	[ -n "$log_file" ] || log_file="/dev/null"
	socks_address=$(get_host_ip "ipv4" ${socks_address})
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -a $socks_username -k $socks_password"
	[ -n "$tcp_tproxy" ] || _extra_param="${_extra_param} -R"
	case "$proto" in
	UDP)
		flag="${flag}_UDP"
		_extra_param="${_extra_param} -U"
	;;
	TCP)
		flag="${flag}_TCP"
		_extra_param="${_extra_param} -T"
	;;
	*)
		flag="${flag}_TCP_UDP"
	;;
	esac
	_extra_param="${_extra_param} -v"
	ln_run "$(binary_path ipt2socks)" "ipt2socks_${flag}" $log_file -l $local_port -b 0.0.0.0 -s $socks_address -p $socks_port ${_extra_param}
}

run_singbox() {
	local flag type node tcp_redir_port udp_redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_port direct_dns_udp_server direct_dns_tcp_server direct_dns_dot_server remote_dns_protocol remote_dns_udp_server remote_dns_tcp_server remote_dns_doh remote_fakedns remote_dns_query_strategy dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file server_host server_port
	local _extra_param=""
	eval_set_val $@
	[ -z "$type" ] && {
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		if [ "$type" != "sing-box" ]; then
			bin=$(binary_path sing-box)
			[ -n "$bin" ] && type="sing-box"
		fi
	}
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	if [ "$log_file" = "/dev/null" ]; then
		_extra_param="${_extra_param} -log 0"
	else
		_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	fi
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warn")
	[ "$loglevel" = "warning" ] && loglevel="warn"
	_extra_param="${_extra_param} -loglevel $loglevel"

	_extra_param="${_extra_param} -tags $($(binary_path sing-box) version | grep 'Tags:' | awk '{print $2}')"

	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$node" ] && _extra_param="${_extra_param} -node $node"
	[ -n "$server_host" ] && _extra_param="${_extra_param} -server_host $server_host"
	[ -n "$server_port" ] && _extra_param="${_extra_param} -server_port $server_port"
	[ -n "$tcp_redir_port" ] && _extra_param="${_extra_param} -tcp_redir_port $tcp_redir_port"
	[ -n "$udp_redir_port" ] && _extra_param="${_extra_param} -udp_redir_port $udp_redir_port"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"
	[ -n "$dns_socks_address" ] && [ -n "$dns_socks_port" ] && _extra_param="${_extra_param} -dns_socks_address ${dns_socks_address} -dns_socks_port ${dns_socks_port}"
	[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
	[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"

	if [ -n "$direct_dns_udp_server" ]; then
		direct_dns_port=$(echo ${direct_dns_udp_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_udp_server $(echo ${direct_dns_udp_server} | awk -F '#' '{print $1}')"
	elif [ -n "$direct_dns_tcp_server" ]; then
		direct_dns_port=$(echo ${direct_dns_tcp_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_tcp_server $(echo ${direct_dns_tcp_server} | awk -F '#' '{print $1}')"
	elif [ -n "$direct_dns_dot_server" ]; then
		direct_dns_port=$(echo ${direct_dns_dot_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_dot_server $(echo ${direct_dns_dot_server} | awk -F '#' '{print $1}')"
	else
		local local_dns=$(echo -n $(echo "${LOCAL_DNS}" | sed "s/,/\n/g" | head -n1) | tr " " ",")
		_extra_param="${_extra_param} -direct_dns_udp_server $(echo ${local_dns} | awk -F '#' '{print $1}')"
		direct_dns_port=$(echo ${local_dns} | awk -F '#' '{print $2}')
	fi
	_extra_param="${_extra_param} -direct_dns_port ${direct_dns_port:-53}"
	_extra_param="${_extra_param} -direct_dns_query_strategy UseIP"

	[ -n "$remote_dns_query_strategy" ] && _extra_param="${_extra_param} -remote_dns_query_strategy ${remote_dns_query_strategy}"
	case "$remote_dns_protocol" in
		tcp)
			local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
			local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
			local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
			_extra_param="${_extra_param} -remote_dns_server ${_dns_address} -remote_dns_port ${_dns_port} -remote_dns_tcp_server tcp://${_dns}"
		;;
		doh)
			local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
			local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
			#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
			local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
			local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
			local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
			[ -z "${_doh_port}" ] && _doh_port=443
			local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
			[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
			[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_server ${_doh_bootstrap}"
			_extra_param="${_extra_param} -remote_dns_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
		;;
	esac
	[ "$remote_fakedns" = "1" ] && _extra_param="${_extra_param} -remote_dns_fake 1"
	lua $UTIL_SINGBOX gen_config ${_extra_param} > $config_file
	ln_run "$(binary_path sing-box)" "sing-box" $log_file run -c "$config_file"
}

run_xray() {
	local flag type node tcp_redir_port udp_redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port remote_dns_udp_server remote_dns_tcp_server remote_dns_doh dns_client_ip dns_query_strategy dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file server_host server_port
	local _extra_param=""
	eval_set_val $@
	[ -z "$type" ] && {
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		if [ "$type" != "xray" ]; then
			bin=$(binary_path xray)
			[ -n "$bin" ] && type="xray"
		fi
	}
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warning")
	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$node" ] && _extra_param="${_extra_param} -node $node"
	[ -n "$server_host" ] && _extra_param="${_extra_param} -server_host $server_host"
	[ -n "$server_port" ] && _extra_param="${_extra_param} -server_port $server_port"
	[ -n "$tcp_redir_port" ] && _extra_param="${_extra_param} -tcp_redir_port $tcp_redir_port"
	[ -n "$udp_redir_port" ] && _extra_param="${_extra_param} -udp_redir_port $udp_redir_port"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"
	[ -n "$dns_socks_address" ] && [ -n "$dns_socks_port" ] && _extra_param="${_extra_param} -dns_socks_address ${dns_socks_address} -dns_socks_port ${dns_socks_port}"
	[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
	[ -n "$dns_query_strategy" ] && _extra_param="${_extra_param} -dns_query_strategy ${dns_query_strategy}"
	[ -n "$dns_client_ip" ] && _extra_param="${_extra_param} -dns_client_ip ${dns_client_ip}"
	[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"
	[ -n "${remote_dns_tcp_server}" ] && {
		local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
		local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
		local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
		_extra_param="${_extra_param} -remote_dns_tcp_server ${_dns_address} -remote_dns_tcp_port ${_dns_port}"
	}
	[ -n "${remote_dns_doh}" ] && {
		local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
		local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
		#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
		local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
		local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
		local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
		[ -z "${_doh_port}" ] && _doh_port=443
		local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
		[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
		[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_doh_ip ${_doh_bootstrap}"
		_extra_param="${_extra_param} -remote_dns_doh_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
	}
	_extra_param="${_extra_param} -loglevel $loglevel"
	lua $UTIL_XRAY gen_config ${_extra_param} > $config_file
	ln_run "$(binary_path "$type")" ${type} $log_file run -c "$config_file"
}

run_dns2socks() {
	local flag socks socks_address socks_port socks_username socks_password listen_address listen_port dns cache log_file
	local _extra_param=""
	eval_set_val $@
	[ -n "$flag" ] && flag="_${flag}"
	[ -n "$log_file" ] || log_file="/dev/null"
	dns=$(get_first_dns dns 53 | sed 's/#/:/g')
	[ -n "$socks" ] && {
		socks=$(echo $socks | sed "s/#/:/g")
		socks_address=$(echo $socks | awk -F ':' '{print $1}')
		socks_port=$(echo $socks | awk -F ':' '{print $2}')
	}
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} /u $socks_username /p $socks_password"
	[ -z "$cache" ] && cache=1
	[ "$cache" = "0" ] && _extra_param="${_extra_param} /d"
	ln_run "$(binary_path dns2socks)" "dns2socks${flag}" $log_file ${_extra_param} "${socks_address}:${socks_port}" "${dns}" "${listen_address}:${listen_port}"
}

run_chinadns_ng() {
	local _flag _listen_port _dns_local _dns_trust _no_ipv6_trust _use_direct_list _use_proxy_list _gfwlist _chnroute _default_mode _default_tag
	eval_set_val $@

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

	# This function may be called multiple times, so add a condition here to avoid repeated execution.
	[ ! -f "${TMP_PATH}/vpslist" ] && {
		servers=$(uci show "${CONFIG}" | grep ".address=" | cut -d "'" -f 2 | grep -v "engage.cloudflareclient.com")
		hosts_foreach "servers" host_from_url | grep '[a-zA-Z]$' | sort -u > "${TMP_PATH}/vpslist"
	}
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

	[ "${_use_direct_list}" = "1" ] && [ -s "${RULES_PATH}/direct_host" ] && {
		local whitelist4_set="inet@passwall@passwall_whitelist"
		local whitelist6_set="inet@passwall@passwall_whitelist6"
		cat <<-EOF >> ${_CONF_FILE}
			group directlist
			group-dnl ${RULES_PATH}/direct_host
			group-upstream ${_dns_local}
			group-ipset ${whitelist4_set},${whitelist6_set}
		EOF
	}

	[ "${_use_proxy_list}" = "1" ] && [ -s "${RULES_PATH}/proxy_host" ] && {
		local blacklist4_set="inet@passwall@passwall_blacklist"
		local blacklist6_set="inet@passwall@passwall_blacklist6"
		cat <<-EOF >> ${_CONF_FILE}
			group proxylist
			group-dnl ${RULES_PATH}/proxy_host
			group-upstream ${_dns_trust}
			group-ipset ${blacklist4_set},${blacklist6_set}
		EOF
		[ "${_no_ipv6_trust}" = "1" ] && echo "no-ipv6 tag:proxylist" >> ${_CONF_FILE}
	}

	[ "${_gfwlist}" = "1" ] && [ -s "${RULES_PATH}/gfwlist" ] && {
		local gfwlist4_set="inet@passwall@passwall_gfwlist"
		local gfwlist6_set="inet@passwall@passwall_gfwlist6"
		cat <<-EOF >> ${_CONF_FILE}
			gfwlist-file ${RULES_PATH}/gfwlist
			add-taggfw-ip ${gfwlist4_set},${gfwlist6_set}
		EOF
		[ "${_no_ipv6_trust}" = "1" ] && echo "no-ipv6 tag:gfw" >> ${_CONF_FILE}
	}

	#只使用gfwlist模式，GFW列表以外的域名及默认使用本地DNS
	[ "${_gfwlist}" = "1" ] && [ "${_chnroute}" = "0" ] && _default_tag="chn"
	#回中国模式，中国列表以外的域名及默认使用本地DNS
	[ "${_chnroute}" = "proxy" ] && _default_tag="chn"
	#全局模式，默认使用远程DNS
	[ "${_default_mode}" = "proxy" ] && [ "${_chnroute}" = "0" ] && [ "${_gfwlist}" = "0" ] && {
		_default_tag="gfw"
		[ "${_no_ipv6_trust}" = "1" ] && echo "no-ipv6" >> ${_CONF_FILE}
	}

	# 是否接受直连 DNS 空响应
	[ "${_default_tag}" = "none_noip" ] && echo "noip-as-chnip" >> ${_CONF_FILE}
	
	([ -z "${_default_tag}" ] || [ "${_default_tag}" = "smart" ] || [ "${_default_tag}" = "none_noip" ]) && _default_tag="none"
	echo "default-tag ${_default_tag}" >> ${_CONF_FILE}

	ln_run "$(binary_path chinadns-ng)" chinadns-ng "${_LOG_FILE}" -C ${_CONF_FILE}
}

run_socks() {
	local flag node bind socks_port config_file http_port http_config_file relay_port log_file
	eval_set_val $@
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	[ -n "$http_port" ] || http_port=0
	[ -n "$http_config_file" ] && [ -z "$(echo ${http_config_file} | grep $TMP_PATH)" ] && http_config_file=$TMP_PATH/$http_config_file
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=$TMP_PATH/$log_file
	else
		log_file="/dev/null"
	fi
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local port=$(config_n_get $node port)
	[ -n "$relay_port" ] && {
		server_host="127.0.0.1"
		port=$relay_port
	}
	local error_msg tmp

	if [ -n "$server_host" ] && [ -n "$port" ]; then
		check_host $server_host
		[ $? != 0 ] && {
			echolog "  - Socks节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
		tmp="${server_host}:${port}"
	else
		error_msg="某种原因，此 Socks 服务的相关配置已失联，启动中止！"
	fi

	if [ "$type" == "sing-box" ] || [ "$type" == "xray" ]; then
		local protocol=$(config_n_get $node protocol)
		if [ "$protocol" == "_balancing" ] || [ "$protocol" == "_shunt" ] || [ "$protocol" == "_iface" ]; then
			unset error_msg
		fi
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动中止 ${bind}:${socks_port} ${error_msg}"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动 ${bind}:${socks_port}"

	case "$type" in
	socks)
		local _socks_address=$(config_n_get $node address)
		local _socks_port=$(config_n_get $node port)
		local _socks_username=$(config_n_get $node username)
		local _socks_password=$(config_n_get $node password)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		local bin=$(binary_path sing-box)
		if [ -n "$bin" ]; then
			type="sing-box"
			lua $UTIL_SINGBOX gen_proto_config -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} -server_proto socks -server_address ${_socks_address} -server_port ${_socks_port} -server_username ${_socks_username} -server_password ${_socks_password} > $config_file
			ln_run "$bin" ${type} $log_file run -c "$config_file"
		else
			bin=$(binary_path xray)
			[ -n "$bin" ] && {
				type="xray"
				lua $UTIL_XRAY gen_proto_config -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} -server_proto socks -server_address ${_socks_address} -server_port ${_socks_port} -server_username ${_socks_username} -server_password ${_socks_password} > $config_file
				ln_run "$bin" ${type} $log_file run -c "$config_file"
			}
		fi
	;;
	sing-box)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _args="http_address=$bind http_port=$http_port"
		}
		[ -n "$relay_port" ] && _args="${_args} server_host=$server_host server_port=$port"
		run_singbox flag=$flag node=$node socks_address=$bind socks_port=$socks_port config_file=$config_file log_file=$log_file ${_args}
	;;
	xray)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _args="http_address=$bind http_port=$http_port"
		}
		[ -n "$relay_port" ] && _args="${_args} server_host=$server_host server_port=$port"
		run_xray flag=$flag node=$node socks_address=$bind socks_port=$socks_port config_file=$config_file log_file=$log_file ${_args}
	;;
	trojan*)
		lua $UTIL_TROJAN gen_config -node $node -run_type client -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(binary_path ${type})" "${type}" $log_file -c "$config_file"
	;;
	naiveproxy)
		lua $UTIL_NAIVE gen_config -node $node -run_type socks -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(binary_path naive)" naive $log_file "$config_file"
	;;
	ssr)
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(binary_path ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss)
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port -mode tcp_and_udp > $config_file
		ln_run "$(binary_path ss-local)" "ss-local" $log_file -c "$config_file" -v
	;;
	ss-rust)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		lua $UTIL_SS gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(binary_path sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria2)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		lua $UTIL_HYSTERIA2 gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(binary_path hysteria)" "hysteria" $log_file -c "$config_file" client
	;;
	tuic)
		lua $UTIL_TUIC gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(binary_path tuic-client)" "tuic-client" $log_file -c "$config_file"
	;;
	esac

	eval node_${node}_socks_port=$socks_port

	# http to socks
	[ -z "$http_flag" ] && [ "$http_port" != "0" ] && [ -n "$http_config_file" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && [ "$type" != "socks" ] && {
		local bin=$(binary_path sing-box)
		if [ -n "$bin" ]; then
			type="sing-box"
			lua $UTIL_SINGBOX gen_proto_config -local_http_address $bind -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		else
			bin=$(binary_path xray)
			[ -n "$bin" ] && type="xray"
			[ -z "$type" ] && return 1
			lua $UTIL_XRAY gen_proto_config local_http_address $bind -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		fi
	}
	unset http_flag
}

run_redir() {
	local node proto bind local_port config_file log_file
	eval_set_val $@
	local tcp_node_socks_flag
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=${TMP_ACL_PATH}/default/${config_file}
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=${TMP_ACL_PATH}/default/${log_file}
	else
		log_file="/dev/null"
	fi
	local proto=$(echo $proto | tr 'A-Z' 'a-z')
	local PROTO=$(echo $proto | tr 'a-z' 'A-Z')
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local enable_log=$(config_t_get global log_${proto} 1)
	[ "$enable_log" != "1" ] && log_file="/dev/null"
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local port=$(config_n_get $node port)
	[ -n "$server_host" ] && [ -n "$port" ] && {
		check_host $server_host
		[ $? != 0 ] && {
			echolog "${PROTO}节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
	}
	[ "$bind" != "127.0.0.1" ] && echolog "${PROTO}节点：[$remarks]，监听端口：$local_port"
	eval ${PROTO}_NODE_PORT=$port

	case "$PROTO" in
	UDP)
		case "$type" in
		socks)
			local _socks_address=$(config_n_get $node address)
			local _socks_port=$(config_n_get $node port)
			local _socks_username=$(config_n_get $node username)
			local _socks_password=$(config_n_get $node password)
			run_ipt2socks flag=default proto=UDP local_port=${local_port} socks_address=${_socks_address} socks_port=${_socks_port} socks_username=${_socks_username} socks_password=${_socks_password} log_file=${log_file}
		;;
		sing-box)
			run_singbox flag=UDP node=$node udp_redir_port=$local_port config_file=$config_file log_file=$log_file
		;;
		xray)
			run_xray flag=UDP node=$node udp_redir_port=$local_port config_file=$config_file log_file=$log_file
		;;
		trojan*)
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $UTIL_TROJAN gen_config -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel > $config_file
			ln_run "$(binary_path ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			echolog "Naiveproxy不支持UDP转发！"
		;;
		ssr)
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(binary_path ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v -U
		;;
		ss)
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port -mode udp_only > $config_file
			ln_run "$(binary_path ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			lua $UTIL_SS gen_config -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(binary_path sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria2)
			lua $UTIL_HYSTERIA2 gen_config -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(binary_path hysteria)" "hysteria" $log_file -c "$config_file" client
		;;
		tuic)
			echolog "TUIC不支持UDP转发！"
		;;
		esac
	;;
	TCP)
		tcp_node_socks=1
		tcp_node_socks_bind_local=$(config_t_get global tcp_node_socks_bind_local 1)
		tcp_node_socks_bind="127.0.0.1"
		[ "${tcp_node_socks_bind_local}" != "1" ] && tcp_node_socks_bind="0.0.0.0"
		tcp_node_socks_port=$(get_new_port $(config_t_get global tcp_node_socks_port 1070))

			can_ipt=$(echo "$TPROXY_LIST" | grep "$type")
		[ -z "$can_ipt" ] && type="socks"

		case "$type" in
		socks)
			_socks_flag=1
			_socks_address=$(config_n_get $node address)
			_socks_port=$(config_n_get $node port)
			_socks_username=$(config_n_get $node username)
			_socks_password=$(config_n_get $node password)
			[ -z "$can_ipt" ] && {
				local _config_file=$config_file
				_config_file="TCP_SOCKS_${node}.json"
				local _port=$(get_new_port 2080)
				run_socks flag="TCP" node=$node bind=127.0.0.1 socks_port=${_port} config_file=${_config_file}
				_socks_address=127.0.0.1
				_socks_port=${_port}
				unset _socks_username
				unset _socks_password
			}
		;;
		sing-box)
			local _flag="TCP"
			local _args=""
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				_args="${_args} socks_address=${tcp_node_socks_bind} socks_port=${tcp_node_socks_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
			}
			[ "$TCP_UDP" = "1" ] && {
				UDP_REDIR_PORT=$local_port
				UDP_NODE="nil"
				_flag="TCP_UDP"
				_args="${_args} udp_redir_port=${UDP_REDIR_PORT}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
			}

			local protocol=$(config_n_get $node protocol)
			local default_node=$(config_n_get $node default_node)
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			[ "${DNS_MODE}" != "sing-box" ] && [ "${DNS_MODE}" != "udp" ] && [ "$protocol" = "_shunt" ] && [ "$default_node" = "_direct" ] && {
				DNS_MODE="sing-box"
				v2ray_dns_mode="tcp"
				echolog "* 当前TCP节点采用Sing-Box分流且默认节点为直连，远程DNS过滤模式将默认使用Sing-Box(TCP)，防止环回！"
			}

			[ "${DNS_MODE}" = "sing-box" ] && {
				resolve_dns=1
				config_file=$(echo $config_file | sed "s/.json/_DNS.json/g")
				_args="${_args} remote_dns_query_strategy=${DNS_QUERY_STRATEGY}"
				DNSMASQ_FILTER_PROXY_IPV6=0
				[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
				resolve_dns_port=${dns_listen_port}
				_args="${_args} dns_listen_port=${resolve_dns_port}"

				case "$(config_t_get global direct_dns_mode "auto")" in
					udp)
						_args="${_args} direct_dns_udp_server=$(config_t_get global direct_dns_udp 223.5.5.5 | sed 's/:/#/g')
					;;
					tcp)
						_args="${_args} direct_dns_tcp_server=$(config_t_get global direct_dns_tcp 223.5.5.5 | sed 's/:/#/g')
					;;
					dot)
						local tmp_dot_dns=$(config_t_get global direct_dns_dot "tls://dot.pub@1.12.12.12")
						local tmp_dot_ip=$(echo "$tmp_dot_dns" | sed -n 's/.*:\/\/\([^@#]*@\)*\([^@#]*\).*/\2/p')
						local tmp_dot_port=$(echo "$tmp_dot_dns" | sed -n 's/.*#\([0-9]\+\).*/\1/p')
						_args="${_args} direct_dns_dot_server=$tmp_dot_ip#${tmp_dot_port:-853}"
					;;
				esac

				_args="${_args} remote_dns_protocol=${v2ray_dns_mode}"
				case "$v2ray_dns_mode" in
					tcp)
						_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
						resolve_dns_log="Sing-Box DNS(127.0.0.1#${resolve_dns_port}) -> tcp://${REMOTE_DNS}"
					;;
					doh)
						remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
						_args="${_args} remote_dns_doh=${remote_dns_doh}"
						resolve_dns_log="Sing-Box DNS(127.0.0.1#${resolve_dns_port}) -> ${remote_dns_doh}"
					;;
				esac
				local remote_fakedns=$(config_t_get global remote_fakedns 0)
				[ "${remote_fakedns}" = "1" ] && {
					fakedns=1
					_args="${_args} remote_fakedns=1"
					resolve_dns_log="${resolve_dns_log} + FakeDNS"
				}
				dns_listen_port=$(expr $dns_listen_port + 1)
			}
			run_singbox flag=$_flag node=$node tcp_redir_port=$local_port config_file=$config_file log_file=$log_file ${_args}
		;;
		xray)
			local _flag="TCP"
			local _args=""
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				_args="${_args} socks_address=${tcp_node_socks_bind} socks_port=${tcp_node_socks_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
			}
			[ "$TCP_UDP" = "1" ] && {
				UDP_REDIR_PORT=$local_port
				UDP_NODE="nil"
				_flag="TCP_UDP"
				_args="${_args} udp_redir_port=${UDP_REDIR_PORT}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
			}

			local protocol=$(config_n_get $node protocol)
			local default_node=$(config_n_get $node default_node)
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			[ "${DNS_MODE}" != "xray" ] && [ "${DNS_MODE}" != "udp" ] && [ "$protocol" = "_shunt" ] && [ "$default_node" = "_direct" ] && {
				DNS_MODE="xray"
				v2ray_dns_mode="tcp"
				echolog "* 当前TCP节点采用Xray分流且默认节点为直连，远程DNS过滤模式将默认使用Xray(TCP)，防止环回！"
			}

			[ "${DNS_MODE}" = "xray" ] && {
				resolve_dns=1
				config_file=$(echo $config_file | sed "s/.json/_DNS.json/g")
				_args="${_args} dns_query_strategy=${DNS_QUERY_STRATEGY}"
				DNSMASQ_FILTER_PROXY_IPV6=0
				local _dns_client_ip=$(config_t_get global dns_client_ip)
				[ -n "${_dns_client_ip}" ] && _args="${_args} dns_client_ip=${_dns_client_ip}"
				[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
				resolve_dns_port=${dns_listen_port}
				_args="${_args} dns_listen_port=${resolve_dns_port}"
				_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
				if [ "$v2ray_dns_mode" = "tcp+doh" ]; then
					remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
					_args="${_args} remote_dns_doh=${remote_dns_doh}"
					resolve_dns_log="Xray DNS(127.0.0.1#${resolve_dns_port}) -> (${remote_dns_doh})(A/AAAA) + tcp://${REMOTE_DNS}"
				else
					resolve_dns_log="Xray DNS(127.0.0.1#${resolve_dns_port}) -> tcp://${REMOTE_DNS}"
				fi
				dns_listen_port=$(expr $dns_listen_port + 1)
			}
			run_xray flag=$_flag node=$node tcp_redir_port=$local_port config_file=$config_file log_file=$log_file ${_args}
		;;
		trojan*)
			lua_tproxy_arg="-use_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
			}
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $UTIL_TROJAN gen_config -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel $lua_tproxy_arg > $config_file
			ln_run "$(binary_path ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			lua $UTIL_NAIVE gen_config -node $node -run_type redir -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(binary_path naive)" naive $log_file "$config_file"
		;;
		ssr)
			lua_tproxy_arg="-tcp_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="-u"
			}
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_tproxy_arg > $config_file
			ln_run "$(binary_path ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v ${_extra_param}
		;;
		ss)
			lua_tproxy_arg="-tcp_tproxy true"
			lua_mode_arg="-mode tcp_only"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				lua_mode_arg="-mode tcp_and_udp"
			}
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_mode_arg $lua_tproxy_arg > $config_file
			ln_run "$(binary_path ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			local _extra_param="-local_tcp_redir_port $local_port"
			_extra_param="${_extra_param} -tcp_tproxy true"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
				_extra_param="${_extra_param} -local_socks_address ${tcp_node_socks_bind} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			lua $UTIL_SS gen_config -node $node ${_extra_param} > $config_file
			ln_run "$(binary_path sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria2)
			local _extra_param="-local_tcp_redir_port $local_port"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
				_extra_param="${_extra_param} -local_socks_address ${tcp_node_socks_bind} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			lua $UTIL_HYSTERIA2 gen_config -node $node ${_extra_param} > $config_file
			ln_run "$(binary_path hysteria)" "hysteria" $log_file -c "$config_file" client
		;;
		esac
		if [ -n "${_socks_flag}" ]; then
			local _flag="TCP"
			[ "$TCP_UDP" = "1" ] && {
				_flag="TCP_UDP"
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
			}
			local _socks_tproxy=""
			_socks_tproxy="1"
			run_ipt2socks flag=default proto=${_flag} tcp_tproxy=${_socks_tproxy} local_port=${local_port} socks_address=${_socks_address} socks_port=${_socks_port} socks_username=${_socks_username} socks_password=${_socks_password} log_file=${log_file}
		fi

		[ -z "$tcp_node_socks_flag" ] && {
			[ "$tcp_node_socks" = "1" ] && {
				local config_file="SOCKS_TCP.json"
				local log_file="SOCKS_TCP.log"
				run_socks flag=TCP node=$node bind=$tcp_node_socks_bind socks_port=$tcp_node_socks_port config_file=$config_file
			}
		}

		[ "$tcp_node_socks" = "1" ] && {
			TCP_SOCKS_server="127.0.0.1:$tcp_node_socks_port"
			echo "${TCP_SOCKS_server}" > $TMP_ACL_PATH/default/TCP_SOCKS_server
		}
	;;
	esac
	unset tcp_node_socks_flag
	return 0
}

start_redir() {
	local proto=${1}
	eval node=\$${proto}_NODE
	if [ "$node" != "nil" ]; then
		TYPE=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		local config_file="${proto}.json"
		local log_file="${proto}.log"
		eval current_port=\$${proto}_REDIR_PORT
		local port=$(echo $(get_new_port $current_port $proto))
		eval ${proto}_REDIR_PORT=$port
		run_redir node=$node proto=${proto} bind=0.0.0.0 local_port=$port config_file=$config_file log_file=$log_file
		echo $node > $TMP_ACL_PATH/default/${proto}.id
	else
		[ "${proto}" = "UDP" ] && [ "$TCP_UDP" = "1" ] && return
		echolog "${proto}节点没有选择或为空，不代理${proto}。"
	fi
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "" > $LOG_FILE
		echolog "日志文件过长，清空处理！"
	}
}

app_monitor_start() {
	"$APP_PATH/monitor.sh" 9>&- >/dev/null 2>&1 &
	echo $! >> "$STATE_PATH/pids"
}

app_crontab() {
	local active="$1" file="$STATE_PATH/cron.next" week hour
	mkdir -p /etc/crontabs
	[ -f /etc/crontabs/root ] || touch /etc/crontabs/root
	# Remove only Passwall-owned entries, including obsolete jobs from older builds.
	sed '\|/usr/share/passwall/|d; \|/etc/init.d/passwall|d' /etc/crontabs/root > "$file" || return 1
	if [ "$active" = 1 ] && [ "$(config_t_get global_rules auto_update 0)" = 1 ]; then
		week=$(config_t_get global_rules week_update 4)
		hour=$(config_t_get global_rules time_update 6)
		case "$week" in
			0|1|2|3|4|5|6) ;;
			7) week='*' ;;
			*) week='' ;;
		esac
		case "$hour" in ''|*[!0-9]*) hour='' ;; esac
		if [ -n "$week" ] && [ -n "$hour" ] && [ "$hour" -le 23 ]; then
			printf '0 %s * * %s lua %s/rule_update.lua log all cron > /dev/null 2>&1\n' "$hour" "$week" "$APP_PATH" >> "$file"
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
	echolog "DNS域名解析："

	local china_ng_local_dns=$(IFS=','; set -- $LOCAL_DNS; [ "${1%%[#:]*}" = "127.0.0.1" ] && echo "$1" || ([ -n "$2" ] && echo "$1,$2" || echo "$1"))
	local sing_box_local_dns=
	local direct_dns_mode=$(config_t_get global direct_dns_mode "auto")
	case "$direct_dns_mode" in
		udp)
			LOCAL_DNS=$(config_t_get global direct_dns_udp 223.5.5.5 | sed 's/:/#/g')
			china_ng_local_dns=${LOCAL_DNS}
			sing_box_local_dns="direct_dns_udp_server=${LOCAL_DNS}"
			IPT_APPEND_DNS=${LOCAL_DNS}
		;;
		tcp)
			LOCAL_DNS="127.0.0.1#${dns_listen_port}"
			dns_listen_port=$(expr $dns_listen_port + 1)
			local DIRECT_DNS=$(config_t_get global direct_dns_tcp 223.5.5.5 | sed 's/:/#/g')
			china_ng_local_dns="tcp://${DIRECT_DNS}"
			sing_box_local_dns="direct_dns_tcp_server=${DIRECT_DNS}"
			IPT_APPEND_DNS="${LOCAL_DNS},${DIRECT_DNS}"
			ln_run "$(binary_path dns2tcp)" dns2tcp "/dev/null" -L "${LOCAL_DNS}" -R "$(get_first_dns DIRECT_DNS 53)" -v
			echolog "  - dns2tcp(${LOCAL_DNS}) -> tcp://$(get_first_dns DIRECT_DNS 53 | sed 's/#/:/g')"
			echolog "  * 请确保上游直连 DNS 支持 TCP 查询。"
		;;
		dot)
			if [ "$(chinadns-ng -V | grep -i wolfssl)" != "nil" ]; then
				LOCAL_DNS="127.0.0.1#${dns_listen_port}"
				local cdns_listen_port=${dns_listen_port}
				dns_listen_port=$(expr $dns_listen_port + 1)
				local DIRECT_DNS=$(config_t_get global direct_dns_dot "tls://dot.pub@1.12.12.12")
				china_ng_local_dns=${DIRECT_DNS}
				ln_run "$(binary_path chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${cdns_listen_port} -c ${DIRECT_DNS} -d chn
				echolog "  - ChinaDNS-NG(${LOCAL_DNS}) -> ${DIRECT_DNS}"
				echolog "  * 请确保上游直连 DNS 支持 DoT 查询。"

				local tmp_dot_ip=$(echo "$DIRECT_DNS" | sed -n 's/.*:\/\/\([^@#]*@\)*\([^@#]*\).*/\2/p')
				local tmp_dot_port=$(echo "$DIRECT_DNS" | sed -n 's/.*#\([0-9]\+\).*/\1/p')
				sing_box_local_dns="direct_dns_dot_server=$tmp_dot_ip#${tmp_dot_port:-853}"
				IPT_APPEND_DNS="${LOCAL_DNS},$tmp_dot_ip#${tmp_dot_port:-853}"
			else
				echolog "  - 你的ChinaDNS-NG版本不支持DoT，直连DNS将使用默认地址。"
			fi
		;;
		auto)
			#Automatic logic is already done by default
			:
		;;
	esac

	TUN_DNS="127.0.0.1#${dns_listen_port}"
	[ "${resolve_dns}" == "1" ] && TUN_DNS="127.0.0.1#${resolve_dns_port}"

	case "$DNS_MODE" in
	dns2socks)
		local dns2socks_socks_server=$(echo $(config_t_get global socks_server 127.0.0.1:1080) | sed "s/#/:/g")
		local dns2socks_forward=$(get_first_dns REMOTE_DNS 53 | sed 's/#/:/g')
		run_dns2socks socks=$dns2socks_socks_server listen_address=127.0.0.1 listen_port=${dns_listen_port} dns=$dns2socks_forward cache=$DNS_CACHE
		echolog "  - dns2socks(${TUN_DNS})，${dns2socks_socks_server} -> tcp://${dns2socks_forward}"
	;;
	sing-box)
		[ "${resolve_dns}" == "0" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=$TMP_PATH/DNS.log
			local log_file=/dev/null
			local _args="type=$DNS_MODE config_file=$config_file log_file=$log_file"
			[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
			_args="${_args} remote_dns_query_strategy=${DNS_QUERY_STRATEGY}"
			DNSMASQ_FILTER_PROXY_IPV6=0
			use_tcp_node_resolve_dns=1
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			_args="${_args} dns_listen_port=${dns_listen_port}"
			_args="${_args} remote_dns_protocol=${v2ray_dns_mode}"
			case "$v2ray_dns_mode" in
				tcp)
					_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
					echolog "  - Sing-Box DNS(${TUN_DNS}) -> tcp://${REMOTE_DNS}"
				;;
				doh)
					remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
					_args="${_args} remote_dns_doh=${remote_dns_doh}"

					local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
					local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
					local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
					local _is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
					local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
					[ -z "${_doh_port}" ] && _doh_port=443
					local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
					[ "${_is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
					[ -n "${_doh_bootstrap}" ] && REMOTE_DNS=${_doh_bootstrap}:${_doh_port}
					unset _doh_url _doh_host_port _doh_host _is_ip _doh_port _doh_bootstrap
					echolog "  - Sing-Box DNS(${TUN_DNS}) -> ${remote_dns_doh}"
				;;
			esac
			_args="${_args} dns_socks_address=127.0.0.1 dns_socks_port=${tcp_node_socks_port}"
			[ -n "${sing_box_local_dns}" ] && _args="${_args} ${sing_box_local_dns}"
			run_singbox ${_args}
		}
	;;
	xray)
		[ "${resolve_dns}" == "0" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=$TMP_PATH/DNS.log
			local log_file=/dev/null
			local _args="type=$DNS_MODE config_file=$config_file log_file=$log_file"
			[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
			_args="${_args} dns_query_strategy=${DNS_QUERY_STRATEGY}"
			DNSMASQ_FILTER_PROXY_IPV6=0
			local _dns_client_ip=$(config_t_get global dns_client_ip)
			[ -n "${_dns_client_ip}" ] && _args="${_args} dns_client_ip=${_dns_client_ip}"
			use_tcp_node_resolve_dns=1
			_args="${_args} dns_listen_port=${dns_listen_port}"
			_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			if [ "$v2ray_dns_mode" = "tcp+doh" ]; then
				remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
				_args="${_args} remote_dns_doh=${remote_dns_doh}"
				echolog "  - Xray DNS(${TUN_DNS}) -> (${remote_dns_doh})(A/AAAA) + tcp://${REMOTE_DNS}"
			else
				echolog "  - Xray DNS(${TUN_DNS}) -> tcp://${REMOTE_DNS}"
			fi
			_args="${_args} dns_socks_address=127.0.0.1 dns_socks_port=${tcp_node_socks_port}"
			run_xray ${_args}
		}
	;;
	udp)
		use_udp_node_resolve_dns=1
		if [ "$DNS_SHUNT" = "chinadns-ng" ] && [ -n "$(binary_path chinadns-ng)" ]; then
			local china_ng_listen_port=${dns_listen_port}
			local china_ng_trust_dns="udp://$(get_first_dns REMOTE_DNS 53 | sed 's/:/#/g')"
		else
			TUN_DNS="$(echo ${REMOTE_DNS} | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')"
			echolog "  - udp://${TUN_DNS}"
		fi
	;;
	*)
		use_tcp_node_resolve_dns=1
		if [ "$DNS_SHUNT" = "chinadns-ng" ] && [ -n "$(binary_path chinadns-ng)" ]; then
			local china_ng_listen_port=${dns_listen_port}
			local china_ng_trust_dns="tcp://$(get_first_dns REMOTE_DNS 53 | sed 's/:/#/g')"
		else
			ln_run "$(binary_path dns2tcp)" dns2tcp "/dev/null" -L "${TUN_DNS}" -R "$(get_first_dns REMOTE_DNS 53)" -v
			echolog "  - dns2tcp(${TUN_DNS}) -> tcp://$(get_first_dns REMOTE_DNS 53 | sed 's/#/:/g')"
		fi
	;;
	esac

	[ -n "${resolve_dns_log}" ] && echolog "  - ${resolve_dns_log}"

	[ "${use_tcp_node_resolve_dns}" = "1" ] && echolog "  * 请确认上游 DNS 支持 TCP 查询，如非直连地址，确保 TCP 代理打开，并且已经正确转发！"
	[ "${use_udp_node_resolve_dns}" = "1" ] && echolog "  * 请确认上游 DNS 支持 UDP 查询并已使用 UDP 节点，如上游 DNS 非直连地址，确保 UDP 代理打开，并且已经正确转发！"

	[ "$DNS_SHUNT" = "chinadns-ng" ] && [ -n "$(binary_path chinadns-ng)" ] && {
		chinadns_ng_min=2024.04.13
		chinadns_ng_now=$(chinadns-ng -V | grep -i "ChinaDNS-NG " | awk '{print $2}')
		if [ $(check_ver "$chinadns_ng_now" "$chinadns_ng_min") = 1 ]; then
			echolog "  * 注意：当前 ChinaDNS-NG 版本为[ $chinadns_ng_now ]，请更新到[ $chinadns_ng_min ]或以上版本，否则 DNS 有可能无法正常工作！"
		fi

		[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0
		[ -z "${china_ng_listen_port}" ] && local china_ng_listen_port=$(expr $dns_listen_port + 1)
		local china_ng_listen="127.0.0.1#${china_ng_listen_port}"
		[ -z "${china_ng_trust_dns}" ] && local china_ng_trust_dns=${TUN_DNS}

		run_chinadns_ng \
			_flag="default" \
			_listen_port=${china_ng_listen_port} \
			_dns_local=${china_ng_local_dns} \
			_dns_trust=${china_ng_trust_dns} \
			_no_ipv6_trust=${FILTER_PROXY_IPV6} \
			_use_direct_list=${USE_DIRECT_LIST} \
			_use_proxy_list=${USE_PROXY_LIST} \
			_gfwlist=${USE_GFW_LIST} \
			_chnroute=${CHN_LIST} \
			_default_mode=${TCP_PROXY_MODE} \
			_default_tag=$(config_t_get global chinadns_ng_default_tag smart)

		echolog "  - ChinaDNS-NG(${china_ng_listen})：直连DNS：${china_ng_local_dns}，可信DNS：${china_ng_trust_dns}"

		USE_DEFAULT_DNS="chinadns_ng"
	}

	[ "$USE_DEFAULT_DNS" = "remote" ] && {
		dnsmasq_version=$(dnsmasq -v | grep -i "Dnsmasq version " | awk '{print $3}')
		[ "$(expr $dnsmasq_version \>= 2.87)" == 0 ] && echolog "Dnsmasq版本低于2.87，有可能无法正常使用！！！"
	}
	CHINADNS_DNS=${china_ng_listen:-0}
}

app_dns_generate() {
	local work="$1"
	mkdir -p "$work/cache"
	lua "$APP_PATH/helper_dnsmasq_add.lua" -FLAG default \
		-CACHE_PATH "$work/cache" \
		-TMP_DNSMASQ_PATH "$work/files" -DNSMASQ_CONF_FILE "$work/entry.conf" \
		-DEFAULT_DNS "${DEFAULT_DNS:-nil}" -LOCAL_DNS "${LOCAL_DNS:-nil}" \
		-TUN_DNS "${TUN_DNS:-nil}" -REMOTE_FAKEDNS "${fakedns:-0}" \
		-USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" -CHINADNS_DNS "${CHINADNS_DNS:-0}" \
		-USE_DIRECT_LIST "$USE_DIRECT_LIST" -USE_PROXY_LIST "$USE_PROXY_LIST" \
		-USE_BLOCK_LIST "$USE_BLOCK_LIST" -USE_GFW_LIST "$USE_GFW_LIST" -CHN_LIST "$CHN_LIST" \
		-TCP_NODE "$TCP_NODE" -DEFAULT_PROXY_MODE "$TCP_PROXY_MODE" \
		-NO_PROXY_IPV6 "${DNSMASQ_FILTER_PROXY_IPV6:-0}" -NO_LOGIC_LOG 1 || return 1
	dnsmasq --test --conf-file="$work/entry.conf" > "$work/dns-check.log" 2>&1 || {
		echolog "DNS 候选配置检查失败：$(cat "$work/dns-check.log")"
		return 1
	}
	# Publish ordinary files, not a symlink into the temporary generator cache.
	cp -aL "$work/files" "$work/publish" || return 1
	sed "s|^conf-dir=.*|conf-dir=$TMP_DNSMASQ_PATH|" "$work/entry.conf" > "$work/publish.conf"
}

app_dns_signature() {
	[ -d "$1" ] || return 1
	(cd "$1" && find . -type f -exec sha256sum '{}' ';' | sort | sha256sum)
}

app_dns_restart() {
	local work="$1" server removed=0 status=0 had_delta=0
	local delta=/tmp/.uci/dhcp
	# Keep UCI's global upstreams configured, but do not let them race the
	# default upstream selected by Passwall in the running dnsmasq instance.
	if grep -q '^server=' /tmp/dnsmasq.d/dnsmasq-passwall.conf 2>/dev/null; then
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
	local work="$1" entry=/tmp/dnsmasq.d/dnsmasq-passwall.conf
	rm -rf "$TMP_DNSMASQ_PATH"
	[ ! -e "$work/old.files" ] || mv "$work/old.files" "$TMP_DNSMASQ_PATH"
	rm -f "$entry"
	[ ! -e "$work/old.conf" ] || mv "$work/old.conf" "$entry"
	app_dns_restart "$work"
}

app_dns_apply() {
	local work="$1" entry=/tmp/dnsmasq.d/dnsmasq-passwall.conf
	if [ "${APP_DNS_REDIRECT_CHANGED:-0}" = 0 ] && cmp -s "$work/publish.conf" "$entry" && [ "$(app_dns_signature "$work/publish")" = "$(app_dns_signature "$TMP_DNSMASQ_PATH")" ]; then
		return 0
	fi
	mkdir -p /tmp/dnsmasq.d || return 1
	if [ -e "$entry" ]; then
		cp -a "$entry" "$work/old.conf" || return 1
	fi
	if [ -e "$TMP_DNSMASQ_PATH" ]; then
		mv "$TMP_DNSMASQ_PATH" "$work/old.files" || return 1
	fi
	if ! mv "$work/publish" "$TMP_DNSMASQ_PATH" ||
		! mv "$work/publish.conf" "$entry" ||
		! app_dns_restart "$work"; then
		app_dns_restore "$work"
		echolog "DNS 配置应用失败，已尝试恢复旧配置。"
		return 1
	fi
	echolog "DNS 配置已更新。"
}

add_ip2route() {
	local ip=$(get_host_ip "ipv4" $1)
	[ -z "$ip" ] && {
		echolog "  - 无法解析[${1}]，路由表添加失败！"
		return 1
	}
	local remarks="${1}"
	[ "$remarks" != "$ip" ] && remarks="${1}(${ip})"

	. /lib/functions/network.sh
	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
	[ -z "${device}" ] && device="$2"

	if [ -n "${gateway}" ]; then
		route add -host ${ip} gw ${gateway} dev ${device} >/dev/null 2>&1
		echo "$ip" >> $TMP_ROUTE_PATH/${device}
		echolog "  - [${remarks}]添加到接口[${device}]路由表成功！"
	else
		echolog "  - [${remarks}]添加到接口[${device}]路由表失功！原因是找不到[${device}]网关。"
	fi
}

delete_ip2route() {
	[ -d "${TMP_ROUTE_PATH}" ] && {
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

app_core_signature() {
	# ACL, routing and scheduling changes never require a proxy-core restart.
	uci -q export "$CONFIG" | awk '
		/^config / { keep = $2 !~ /^(acl_rule|global_forwarding|global_rules|global_delay)$/ }
		keep && $1 == "option" && $2 == "dns_redirect" { next }
		keep { print }
	' | sha256sum | cut -d ' ' -f 1
}

app_runtime_save() {
	local key
	mkdir -p "$STATE_PATH/runtime"
	for key in TCP_REDIR_PORT UDP_REDIR_PORT LOCAL_DNS DEFAULT_DNS TUN_DNS IPT_APPEND_DNS USE_DEFAULT_DNS DNSMASQ_FILTER_PROXY_IPV6 CHINADNS_DNS fakedns; do
		eval 'printf "%s\n" "${'"$key"':-}"' > "$STATE_PATH/runtime/$key"
	done
}

app_runtime_load() {
	local key value
	for key in TCP_REDIR_PORT UDP_REDIR_PORT LOCAL_DNS DEFAULT_DNS TUN_DNS IPT_APPEND_DNS USE_DEFAULT_DNS DNSMASQ_FILTER_PROXY_IPV6 CHINADNS_DNS fakedns; do
		[ -f "$STATE_PATH/runtime/$key" ] || continue
		value=$(cat "$STATE_PATH/runtime/$key")
		export "$key=$value"
	done
}

app_owned_pid() {
	case "$1" in ''|*[!0-9]*) return 1 ;; esac
	[ -r "/proc/$1/cmdline" ] || return 1
	tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline" | grep -Fq '/passwall/'
}

app_processes_stop() {
	local pid attempt pending
	[ -f "$STATE_PATH/pids" ] || return 0
	for pid in $(cat "$STATE_PATH/pids"); do
		app_owned_pid "$pid" || continue
		kill "$pid" $(pgrep -P "$pid") 2>/dev/null || :
	done
	for attempt in 1 2 3 4; do
		pending=""
		for pid in $(cat "$STATE_PATH/pids"); do
			app_owned_pid "$pid" && pending="$pending $pid"
		done
		[ -n "$pending" ] || { rm -f "$STATE_PATH/pids"; return 0; }
		[ "$attempt" -ne 2 ] || kill -KILL $pending 2>/dev/null
		sleep 1
	done
	echolog "Passwall 进程未能退出，保留 PID，未继续启动。"
	return 1
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
	if [ "$APP_DNS_REDIRECT_CHANGED" = 1 ]; then uci commit dhcp || return 1; fi
	if [ "$APP_FLOW_OFFLOAD_CHANGED" = 1 ]; then
		uci commit firewall || return 1
		# fw4's include must not enqueue another update caused by our own change.
		PASSWALL_FW_RELOAD=1 /etc/init.d/firewall reload 9>&- || return 1
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

app_apply() {
	local work="$1" routes_changed=0
	if ! cmp -s "$work/network" "$STATE_PATH/network"; then
		routes_changed=1
		nft_routes_save "$work"
		if ! nft_routes; then
			nft_routes_restore "$work"
			echolog "策略路由更新失败，已尝试恢复原路由。"
			return 1
		fi
	fi
	app_system_save "$work"
	if ! app_system_apply running || ! nft_commit "$work"; then
		app_system_restore "$work"
		[ "$routes_changed" = 0 ] || nft_routes_restore "$work"
		return 1
	fi
	if ! app_dns_apply "$work"; then
		if [ -s "$STATE_PATH/rules.nft" ]; then nft_restore; else nft_stop; fi
		app_system_restore "$work"
		[ "$routes_changed" = 0 ] || nft_routes_restore "$work"
		return 1
	fi
	mv "$work/rules.nft" "$STATE_PATH/rules.nft" || return 1
	mv "$work/network" "$STATE_PATH/network" || return 1
}

app_reload() {
	local reason="${1:-config}" work old_local_dns="$LOCAL_DNS" old_default_dns="$DEFAULT_DNS" old_append_dns="$IPT_APPEND_DNS"
	if [ "$reason" = config ]; then
		[ "$ENABLED" = 1 ] || { app_stop; return $?; }
		[ -f "$STATE_PATH/running" ] || { app_start; return $?; }
		if [ "$(app_core_signature)" != "$(cat "$STATE_PATH/core.sha256")" ]; then
			app_stop && app_start
			return $?
		fi
	fi
	[ -f "$STATE_PATH/running" ] || return 0
	app_runtime_load
	if [ "$(config_t_get global direct_dns_mode auto)" = auto ]; then
		LOCAL_DNS="$old_local_dns"; DEFAULT_DNS="$old_default_dns"; IPT_APPEND_DNS="$old_append_dns"
	fi
	nft_read_config || return 1
	work=$(mktemp -d "$STATE_PATH/reload.XXXXXX") || return 1
	nft_network_snapshot > "$work/network"
	if { [ "$reason" = network ] || [ "$reason" = firewall ]; } &&
		cmp -s "$work/network" "$STATE_PATH/network" && app_system_matches && nft list table inet passwall >/dev/null 2>&1; then
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
	app_runtime_save
	app_crontab 1 || return 1
	rm -rf "$work"
	echolog "nftables 热更新完成（$reason）。"
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
		echolog "规则应用失败，已保留旧规则文件。"
		return 1
	fi
	rm -rf "$backup"
	echolog "规则文件发布完成。"
}

app_start() {
	[ "$ENABLED" = 1 ] || { app_stop; return $?; }
	[ ! -f "$STATE_PATH/running" ] || { app_reload config; return $?; }
	ulimit -n 65535
	if ! command -v fw4 >/dev/null || ! command -v nft >/dev/null ||
		! dnsmasq --version | grep -q 'Compile time options:.* nftset'; then
		echolog "需要 firewall4、nftables 和支持 nftset 的 dnsmasq，未启动。"
		return 1
	fi
	mkdir -p "$TMP_PATH" "$TMP_BIN_PATH" "$TMP_SCRIPT_FUNC_PATH" "$TMP_ID_PATH" "$TMP_ROUTE_PATH" "$TMP_ACL_PATH" "$TMP_IFACE_PATH" "$TMP_PATH2"
	APP_LAUNCH_FAILED=0
	local work
	work=$(mktemp -d "$STATE_PATH/start.XXXXXX") || return 1
	if [ "$ENABLED_DEFAULT_ACL" = 1 ]; then
		mkdir -p "$TMP_ACL_PATH/default"
		start_redir TCP
		start_redir UDP
		start_dns
	fi
	if [ "$APP_LAUNCH_FAILED" = 1 ]; then
		app_processes_stop
		rm -rf "$work"
		return 1
	fi
	# Asynchronous launches must still be alive before redirecting client traffic.
	local pid
	if [ -f "$STATE_PATH/pids" ]; then
		sleep 1
		for pid in $(cat "$STATE_PATH/pids"); do
			if ! kill -0 "$pid" 2>/dev/null; then
				echolog "代理/DNS 进程启动失败，未启用透明代理。"
				app_processes_stop
				rm -rf "$work"
				return 1
			fi
		done
	fi
	if ! nft_read_config || ! nft_prepare "$work" || ! app_dns_generate "$work"; then
		app_processes_stop
		rm -rf "$work"
		return 1
	fi
	nft_network_snapshot > "$work/network"
	nft_bridge_start
	if ! app_apply "$work"; then
		nft_bridge_stop
		app_processes_stop
		rm -rf "$work"
		return 1
	fi
	app_runtime_save
	app_core_signature > "$STATE_PATH/core.sha256"
	nft_include
	touch "$STATE_PATH/running"
	app_monitor_start
	app_crontab 1
	rm -rf "$work"
	echolog "Passwall 启动完成。"
}

app_stop() {
	rm -f "$STATE_PATH/running"
	nft_stop || return 1
	nft_bridge_stop
	[ -z "$FWI" ] || printf '#!/bin/sh\n' > "$FWI"
	delete_ip2route
	app_processes_stop || return 1
	app_crontab 0 || return 1
	local dns_removed=0
	if [ -e /tmp/dnsmasq.d/dnsmasq-passwall.conf ]; then
		rm -f /tmp/dnsmasq.d/dnsmasq-passwall.conf "$DNSMASQ_PATH/dnsmasq-passwall.conf"
		rm -rf "$TMP_DNSMASQ_PATH"
		dns_removed=1
	fi
	app_system_apply stopped || return 1
	if [ "$dns_removed" = 1 ] || [ "$APP_DNS_REDIRECT_CHANGED" = 1 ]; then
		/etc/init.d/dnsmasq restart 9>&- >/dev/null 2>&1 || return 1
	fi
	rm -rf "$TMP_PATH" "$TMP_PATH2" "$STATE_PATH/runtime"
	rm -f "$STATE_PATH/core.sha256" "$STATE_PATH/network" "$STATE_PATH/rules.nft" "$STATE_PATH"/bridge_nf_*
	echolog "Passwall 已停止。"
}

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
PROXY_IPV6=1
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
LOCALHOST_PROXY=$(config_t_get global localhost_proxy 0)
DNS_SHUNT=$(config_t_get global dns_shunt dnsmasq)
[ -z "$(binary_path $DNS_SHUNT)" ] && DNS_SHUNT="dnsmasq"
DNS_MODE=$(config_t_get global dns_mode tcp)
DNS_CACHE=0
REMOTE_DNS=$(config_t_get global remote_dns 1.1.1.1:53 | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')
USE_DEFAULT_DNS=$(config_t_get global use_default_dns direct)
FILTER_PROXY_IPV6=$(config_t_get global filter_proxy_ipv6 0)
dns_listen_port=${DNS_PORT}

TPROXY_LIST="socks ss ss-rust ssr sing-box xray trojan-plus hysteria2"
RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto

ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1)
ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}'| sort -u | grep -v -Fx ::1 | grep -v -Fx ::)

DEFAULT_DNS=$(uci show dhcp.@dnsmasq[0] | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | head -2 | sed ':label;N;s/\n/,/;b label')
[ -z "${DEFAULT_DNS}" ] && [ "$(echo $ISP_DNS | tr ' ' '\n' | wc -l)" -le 2 ] && DEFAULT_DNS=$(echo -n $ISP_DNS | tr ' ' '\n' | head -2 | tr '\n' ',')
LOCAL_DNS="${DEFAULT_DNS:-119.29.29.29,223.5.5.5}"
IPT_APPEND_DNS=${LOCAL_DNS}

DNS_QUERY_STRATEGY="UseIP"
[ "$FILTER_PROXY_IPV6" = "1" ] && DNS_QUERY_STRATEGY="UseIPv4"
DNSMASQ_FILTER_PROXY_IPV6=${FILTER_PROXY_IPV6}

export V2RAY_LOCATION_ASSET=/usr/share/v2ray/
export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
mkdir -p "$STATE_PATH" /tmp/etc $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ID_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_IFACE_PATH $TMP_PATH2

# nftables.sh is a library, never a second command dispatcher.
. "$APP_PATH/nftables.sh"

arg1=$1
shift
case $arg1 in
add_ip2route)
	add_ip2route $@
	;;
get_new_port)
	get_new_port $@
	;;
run_socks)
	run_socks $@
	;;
run_redir)
	run_redir $@
	;;
echolog)
	echolog $@
	;;
stop)
	app_stop
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
