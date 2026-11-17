#!/usr/bin/env python3
"""Run one or more real-browser Passwall WebUI cases against a test router."""

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


CASE_ROOT = Path(__file__).resolve().parent / "cases"
ROOT = Path(os.environ.get("PASSWALL_TEST_ARTIFACTS", "/tmp/passwall-webui-artifacts"))
HTTP_HOST = os.environ.get("HTTP_HOST", "192.168.114.215")
RESULTS = []
CURRENT_CASE = ""


def target_router():
    router = os.environ.get("PASSWALL_TEST_ROUTER", "").strip()
    if not router:
        raise SystemExit("PASSWALL_TEST_ROUTER is required; refusing to choose a router implicitly")
    if router.rstrip(".") == "192.168.114.1":
        raise SystemExit("PASSWALL_TEST_ROUTER=192.168.114.1 is forbidden")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", router):
        raise SystemExit("PASSWALL_TEST_ROUTER must be an IPv4 address or DNS hostname")
    parts = router.split(".")
    if len(parts) == 4 and all(part.isdecimal() for part in parts):
        if tuple(int(part, 10) for part in parts) == (192, 168, 114, 1):
            raise SystemExit("PASSWALL_TEST_ROUTER=192.168.114.1 is forbidden")
    try:
        if ipaddress.ip_address(router) == ipaddress.ip_address("192.168.114.1"):
            raise SystemExit("PASSWALL_TEST_ROUTER=192.168.114.1 is forbidden")
    except ValueError:
        pass
    return router


def fixture_host():
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", HTTP_HOST):
        raise SystemExit("HTTP_HOST must be an IPv4 address or DNS hostname")
    return HTTP_HOST


HOST = target_router()
fixture_host()
BASE = f"http://{HOST}/cgi-bin/luci/admin/services/passwall/"


def ssh(cmd, input=None):
    result = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            f"root@{HOST}",
            cmd,
        ],
        input=input,
        text=True,
        capture_output=True,
        timeout=40,
    )
    if result.returncode:
        raise AssertionError((cmd, result.returncode, result.stderr, result.stdout))
    return result.stdout.strip()


def config():
    return json.loads(
        ssh(
            "lua -e 'local u=require(\"uci\").cursor(); "
            "print(require(\"luci.jsonc\").stringify(u:get_all(\"passwall\")))'"
        )
    )


def ordered(kind):
    if not re.fullmatch(r"[A-Za-z0-9_]+", kind):
        raise ValueError(f"invalid UCI section type: {kind!r}")
    command = (
        "lua -e 'local r={};require(\"uci\").cursor():foreach(\"passwall\",\""
        + kind
        + "\",function(s) r[#r+1]=s[\".name\"] end);"
        "print(require(\"luci.jsonc\").stringify(r))'"
    )
    return json.loads(ssh(command))


def section(kind):
    return next(key for key, value in config().items() if value[".type"] == kind)


def wait(fn, timeout=25):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as error:
            last = str(error)
        # Pump Playwright's event loop while polling browser/device state.
        page.wait_for_timeout(300)
    raise AssertionError(("timed out", last))


def field(key, kind="input"):
    return page.locator(f'{kind}[name$=".{key}"]').filter(visible=True)


def fill(key, value):
    visible = field(key)
    if visible.count():
        visible.fill(str(value))
        return
    dropdown = page.locator(f'.cbi-dropdown[id$=".{key}"]').filter(visible=True)
    if dropdown.count():
        dropdown.locator(".open").click()
        option = dropdown.locator("li[data-value=" + json.dumps(str(value)) + "]")
        if option.count():
            option.filter(visible=True).first.click()
        else:
            custom = dropdown.locator(".create-item-input").filter(visible=True).first
            custom.fill(str(value))
            custom.press("Enter")
        page.mouse.click(5, 5)
        return
    raise AssertionError(("no editable control", key))


def select(key, value):
    field(key, "select").select_option(str(value))


def flag(key, value):
    field(key, "input[type=checkbox]").set_checked(bool(value))


def go(name):
    response = page.goto(BASE + name, wait_until="networkidle")
    assert response and response.status == 200, (name, response.status if response else None)
    # LuCI remembers the last selected settings tab between page visits.
    if name == "settings":
        tab("Main")
    assert not page.locator(".alert-message.danger").count(), page.locator(
        ".alert-message.danger"
    ).all_text_contents()


def tab(name):
    page.locator(f'li[data-tab="{name}"] a').click()


def submit(apply=True):
    selector = ".cbi-page-actions .cbi-button-apply" if apply else ".cbi-page-actions .cbi-button-save"
    targets = page.locator(selector)
    if not targets.count():
        # Some LuCI pages expose only Save; it applies the current form there.
        targets = page.locator(".cbi-page-actions .cbi-button-save")
    target = targets.last
    with page.expect_response(
        lambda response: response.request.method == "POST" and "/cgi-bin/luci/" in response.url
    ) as response:
        target.click()
    assert response.value.status == 200, (response.value.status, response.value.url)
    page.wait_for_load_state("networkidle")
    invalid = page.locator(".cbi-input-invalid,.cbi-value-error,.cbi-section-error")
    assert not invalid.count(), invalid.all_text_contents()
    if apply:
        page.wait_for_timeout(5000)
        page.wait_for_load_state("networkidle")
    else:
        page.wait_for_timeout(600)


def node_create(name, proto="socks", fields=None):
    go("node_list")
    page.locator('input[value="添加"]').click()
    page.wait_for_url("**/node_config/*", wait_until="networkidle")
    node_id = page.url.rsplit("/", 1)[1]
    fill("remarks", name)
    select("xray_protocol", proto)
    if not proto.startswith("_"):
        fill("xray_address", "127.0.0.1")
        fill("xray_port", "20180")
    for key, value in (fields or {}).items():
        if key.startswith("select:"):
            select(key[7:], value)
        elif key.startswith("flag:"):
            flag(key[5:], value)
        else:
            fill(key, value)
    submit()
    wait(lambda: config().get(node_id, {}).get("protocol") == proto)
    node = config()[node_id]
    assert node["type"] == "Xray"
    return node_id


def dyn_add(key, value):
    root = page.locator(f'.cbi-value[id$="-{key}"]')
    dropdown = root.locator(".cbi-dropdown .open")
    if dropdown.count():
        dropdown.last.click()
        option = root.locator("li[data-value=" + json.dumps(str(value)) + "]").filter(visible=True)
        if option.count():
            option.first.click()
            page.mouse.click(5, 5)
            return
    edit = root.locator('input[type="text"]').filter(visible=True).last
    edit.fill(str(value))
    edit.press("Enter")
    page.mouse.click(5, 5)


def generate(node_id):
    generated = ssh(
        "lua /usr/lib/lua/luci/passwall/util_xray.lua gen_config -node "
        + shlex.quote(node_id)
        + " -local_socks_port 2077"
    )
    data = json.loads(generated)
    result = ssh(
        'work=$(mktemp -d /tmp/passwall-webui-xray.XXXXXX) || exit 1; '
        'cat > "$work/config.json" && xray run -test -c "$work/config.json"; '
        'result=$?; rm -rf "$work"; exit "$result"',
        input=generated,
    )
    assert "Configuration OK" in result, result
    return data


def dyn_set(key, values):
    root = page.locator(f'.cbi-value[id$="-{key}"]')
    while root.locator(".cbi-dynlist > .item").count():
        item = root.locator(".cbi-dynlist > .item").first
        item.focus()
        item.press("Delete")
    for value in values:
        dyn_add(key, value)


def job():
    return context.request.get(BASE + "get_rule_update_status").json()


def choose(names):
    for name in ["gfwlist", "chnroute", "chnroute6"]:
        page.locator(f'#rule_update_actions input[type="checkbox"][value="{name}"]').set_checked(
            name in names
        )


def update(names, expected="done"):
    choose(names)
    with page.expect_response(lambda response: "/passwall/update_rules?" in response.url) as response:
        page.locator("[data-rule-update-start]").click()
    assert response.value.status in [200, 409], (response.value.status, response.value.text())
    wait(lambda: job().get("state") in ["done", "failed"], 50)
    state = job()
    assert state["state"] == expected, state
    wait(lambda: page.locator("[data-rule-update-start]").is_enabled(), 15)
    wait(lambda: page.locator("[data-rule-update-status]").inner_text() == "" if expected == "done"
         else "失败" in page.locator("[data-rule-update-status]").inner_text(), 15)


def write_results():
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / f"{CURRENT_CASE}-results.json").write_text(
        json.dumps(RESULTS, ensure_ascii=False, indent=2)
    )


def check(name, fn):
    print("START", name, flush=True)
    try:
        fn()
        assert not errors, ("uncaught browser pageerror", errors)
        RESULTS.append({"case": name, "status": "passed"})
        print("PASS", name, flush=True)
    except Exception as error:
        RESULTS.append({"case": name, "status": "failed", "error": str(error)})
        page.screenshot(path=str(ROOT / "failure.png"), full_page=True)
        (ROOT / "failure.html").write_text(page.content())
        raise
    finally:
        write_results()


def resolve_cases(names):
    paths = []
    for name in names:
        if Path(name).name != name:
            raise SystemExit(f"CASE must be a filename or case name, got {name!r}")
        filename = name if name.endswith(".py") else name + ".py"
        path = CASE_ROOT / filename
        if not path.is_file():
            available = ", ".join(sorted(p.stem for p in CASE_ROOT.glob("*.py")))
            raise SystemExit(f"unknown CASE {name!r}; available: {available}")
        paths.append(path)
    return paths


def run_cases(paths):
    global browser, context, page, errors, dialogs, dialog_accept, RESULTS, CURRENT_CASE
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(viewport={"width": 1366, "height": 900})
            login = context.request.post(
                BASE + "settings", form={"luci_username": "root", "luci_password": ""}
            )
            assert login.ok, ("LuCI login failed", login.status)
            errors = []

            def track_page(new_page):
                new_page.on("pageerror", lambda error: errors.append(str(error)))

            context.on("page", track_page)
            page = context.new_page()
            dialogs = []
            dialog_accept = True

            def handle_dialog(dialog):
                dialogs.append(dialog.message)
                if dialog_accept:
                    dialog.accept()
                else:
                    dialog.dismiss()

            page.on("dialog", handle_dialog)
            for case_path in paths:
                CURRENT_CASE = case_path.stem
                RESULTS = []
                print("CASE", case_path.name, flush=True)
                exec(compile(case_path.read_text(), str(case_path), "exec"), globals())
                page.wait_for_timeout(300)

                def no_page_errors():
                    assert not errors, errors

                check("uncaught browser pageerror array is empty", no_page_errors)
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("CASE", nargs="+", help="case filename(s), run in the supplied order")
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    run_cases(resolve_cases(args.CASE))


if __name__ == "__main__":
    main()
