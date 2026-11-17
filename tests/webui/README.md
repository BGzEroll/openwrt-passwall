# Passwall WebUI acceptance cases

These cases exercise the real LuCI pages with Playwright and inspect the resulting runtime state over SSH. They are for a dedicated, disposable test router only: the cases change and apply Passwall settings and leave their final state on the device.

## Before running

The caller must back up the test router, deploy the source revision being checked, prepare the expected empty/default Passwall configuration, and start the local protocol and HTTP fixtures. This suite does not back up, initialize, upload, restore, or clean up router or fixture state.

The current fixtures are prepared separately from this directory:

- HTTP rule-list files are served from `/tmp/passwall-webui-acceptance/http` on port `20181`.
- The slow HTTP handler is `/tmp/passwall-webui-acceptance/slow-http.py` on port `20183`.
- Protocol endpoints run on the test router at `127.0.0.1:20191–20199`; the upstream SOCKS fixture listens on `127.0.0.1:20180` and `[::1]:20180`.
- For `phase30-default-dns`, run `python3 tests/fixtures/dns/default_servers.py` on `HTTP_HOST`. Its UDP ports `20531` and `20532` return distinct synthetic answers for real DNS-selection checks.
- For `phase28-node-actions`, copy `tests/test_url_test_lock.sh` to `/tmp/passwall-test-url-lock.sh` on the test router.
- `HTTP_HOST` can replace `192.168.114.215` when the HTTP fixture host differs. The fixture ports and paths remain fixed by these cases.

The router must be reachable over HTTP at the LuCI Passwall URL and by root SSH with key-based, non-interactive authentication; its SSH host key must already be trusted. The runner currently logs into LuCI as `root` with an empty password. Python Playwright and its Chromium browser must already be installed.

Some cases make real DNS and proxy requests, including probes to `www.gstatic.com` and `www.google.com`; the test network must support the expected fixture and upstream traffic.

## Running

`PASSWALL_TEST_ROUTER` is mandatory. The runner rejects `192.168.114.1`; it has no router default. `PASSWALL_TEST_ARTIFACTS` selects where `ids.json`, per-case JSON results, and failure screenshots/HTML are written. If omitted, artifacts go to `/tmp/passwall-webui-artifacts`.

```sh
export PASSWALL_TEST_ROUTER=192.0.2.44   # replace with the dedicated test router
export PASSWALL_TEST_ARTIFACTS=/tmp/passwall-webui-run
# Optional when the fixture host is not 192.168.114.215:
export HTTP_HOST=192.0.2.45

python3 tests/webui/run.py \
  phase1 phase2 phase3 phase4 phase5 phase6-http phase7 phase8 \
  phase10-shunt phase11-protocol-traffic phase12-update-stress \
  phase13-advanced phase15-mixed-validation phase16-excluded-clear \
  phase17-domain-routing phase18-refs phase19-validation phase20-modes \
  phase21-no-node-xray phase22-concurrent-tests phase23-recovery-reset \
  phase24-fallback-stale phase25-core-options phase26-large-rules \
  phase27-save-copy phase28-node-actions phase29-pending-url-test phase30-default-dns
```

Each positional `CASE` may be given with or without `.py`; cases run in the supplied order. `phase1` creates the artifact `ids.json` used by later cases, so keep the same artifact directory and router for the whole sequence. A single case can be run by itself only when its earlier-case state and IDs are already present. `final-defaults-reboot` instead requires a freshly initialized profile and the upstream fixture to start automatically across a router reboot. It uses the native system reboot page and requires correctly configured LAN bypass lists.

The browser performs all form changes and submits. SSH reads UCI, generated runtime files, logs, and service state; it also runs read-only DNS/traffic probes and validates generated Xray JSON with `xray run -test` against a temporary JSON file that is removed afterward. The runner does not run these network cases as part of syntax checking.

## Case coverage

The selected cases cover node and ACL creation/edit/sort/delete, rule files and Hosts, DNS and proxy modes, Xray protocol/transport generation and live traffic, rule updates and concurrent updates, advanced routing and validation, reference-safe deletion, stale forms, recovery/reset behavior, and Save-versus-Apply copying. Intentional-failure reproductions and duplicate resume cases are not included.
