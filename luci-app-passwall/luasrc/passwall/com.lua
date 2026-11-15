local _M = {}

_M.hysteria = {
	path = "/usr/bin/hysteria",
	cmd_version = "version | awk '/^Version:/ {print $2}'"
}

_M.singbox = {
	path = "/usr/bin/sing-box",
	cmd_version = "version | awk '{print $3}' | sed -n 1P"
}

_M.xray = {
	path = "/usr/bin/xray",
	cmd_version = "version | awk '{print $2}' | sed -n 1P"
}

_M["chinadns-ng"] = {
	path = "/usr/bin/chinadns-ng",
	cmd_version = "-V | awk '{print $2}'"
}

return _M
