#!/bin/sh

CONFIG=passwall

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}


url_test_node() {
	result=0
	local node_id=$1
	local _type=$(echo $(config_n_get ${node_id} type nil) | tr 'A-Z' 'a-z')
	[ "${_type}" != "nil" ] && {
		if [ "${_type}" == "socks" ]; then
			local _address=$(config_n_get ${node_id} address)
			local _port=$(config_n_get ${node_id} port)
			[ -n "${_address}" ] && [ -n "${_port}" ] && {
				local curlx="socks5h://${_address}:${_port}"
				local _username=$(config_n_get ${node_id} username)
				local _password=$(config_n_get ${node_id} password)
				[ -n "${_username}" ] && [ -n "${_password}" ] && curlx="socks5h://${_username}:${_password}@${_address}:${_port}"
			}
		else
			local _tmp_port=$(/usr/share/${CONFIG}/app.sh get_new_port 61080 tcp)
			/usr/share/${CONFIG}/app.sh run_socks flag="url_test_${node_id}" node=${node_id} bind=127.0.0.1 socks_port=${_tmp_port} config_file=url_test_${node_id}.json
			local curlx="socks5h://127.0.0.1:${_tmp_port}"
		fi
		sleep 1s
		result=$(curl --connect-timeout 3 -o /dev/null -I -skL -w "%{http_code}:%{time_starttransfer}" -x $curlx "https://www.google.com/generate_204")
		pgrep -af "url_test_${node_id}" | awk '! /test\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf "/tmp/etc/${CONFIG}/url_test_${node_id}.json"
	}
	echo $result
}


case "$1" in
url_test_node)
	shift
	url_test_node "$@"
	;;
esac
