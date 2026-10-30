"""End-to-end check: a scenario must propagate into the topology graph, port
state, and event attribution — the event -> device -> topology correlation that
Splunk Network Intelligence relies on.

It also asserts Splunk NI's actual grading rules, because a fault that NI scores
as "ok" is worse than no fault at all: the demo would show a healthy network
while the scenario claims an outage. NI's meraki.interface_status binding grades

    critical  if enabled AND status=="disconnected" AND isUplink
    critical  if actionable_error_count > 0
    degraded  if warning_count > 0
    ok        otherwise (status present and non-empty)

where actionable errors exclude the literal strings "port disconnected" and
"port disabled". Both paths are exercised below.
"""

import json
import ssl
import sys
import time
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

DASH = "http://localhost:8081"
API = "https://localhost:5000/api/v1"
KEY = "6789123456789012345678901234567890123456"
ORG = "2947"
SWITCH = "Q2QN-S042-MS01"
NETWORK = "L_646829496405521106"

# The API cert is self-signed and trusted inside the Splunk container, not on
# this host; the scenario assertions care about payloads, not certificate chains.
_API_SSL = ssl.create_default_context()
_API_SSL.check_hostname = False
_API_SSL.verify_mode = ssl.CERT_NONE

FAILURES: list[str] = []


def get(path):
    return json.loads(urllib.request.urlopen(DASH + path).read().decode("utf-8"))


def api(path):
    req = urllib.request.Request(API + path, headers={"X-Cisco-Meraki-API-Key": KEY})
    return json.loads(urllib.request.urlopen(req, context=_API_SSL).read().decode("utf-8"))


def post(path):
    req = urllib.request.Request(DASH + path, method="POST")
    return urllib.request.urlopen(req).read().decode("utf-8")


def check(cond, label, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        if detail:
            print(f"          {detail}")
        FAILURES.append(label)


def port_status(serial, port_id):
    """Fetch one port from the org-level bySwitch endpoint NI actually polls."""
    data = api(f"/organizations/{ORG}/switch/ports/statuses/bySwitch")
    rec = next(r for r in data["items"] if r["serial"] == serial)
    return rec, next(p for p in rec["ports"] if p["portId"] == port_id)


def ni_state(port):
    """Reproduce NI's interface_status state_expr for one port record."""
    ignored = {"port disconnected", "port disabled"}
    actionable = [e for e in port.get("errors", []) if str(e).lower() not in ignored]
    warnings = port.get("warnings", [])
    enabled = str(port.get("enabled")).lower() == "true"
    status = str(port.get("status", "")).lower()
    is_uplink = bool(port.get("isUplink"))

    if enabled and status == "disconnected" and is_uplink:
        return "critical", "rule a: enabled + disconnected + isUplink"
    if actionable:
        return "critical", f"rule b: {len(actionable)} actionable error(s)"
    if warnings:
        return "degraded", f"{len(warnings)} warning(s)"
    if status:
        return "ok", "status present, no actionable signal"
    return "unknown", "no status"


def link_for(serial, port_id):
    """Find the modelled L2 link touching this device+port, from either end."""
    topo = get("/api/topology")
    for l in topo["links"]:
        if (l["sourceSerial"] == serial and l["sourcePort"] == port_id) or \
           (l["targetSerial"] == serial and l["targetPort"] == port_id):
            return l
    return None


print("=" * 78)
print("Scenario A: store_uplink_failure_flagship  (NI critical via rule a)")
print("=" * 78)

link = link_for(SWITCH, "23")
check(link is not None, "uplink port 23 has a modelled L2 link")
if link is None:
    print("\nCannot continue without the uplink link; aborting.")
    sys.exit(1)
check(link["isUp"] is True, "link up before the scenario")
check(link["isTrunk"] is True, "port 23 is a trunk (so isUplink=true for NI)")

_, p23 = port_status(SWITCH, "23")
check(p23["isUplink"] is True, "Meraki reports port 23 as isUplink")
state, why = ni_state(p23)
check(state == "ok", f"pre-fault NI state is 'ok' ({why})", f"got {state}")

print(f"\n  TRIGGER -> {post('/api/scenarios/store_uplink_failure_flagship/trigger').strip()}")
time.sleep(2.5)

link = link_for(SWITCH, "23")
check(link is not None and link["isUp"] is False,
      "port flap propagated to the L2 link (graph shows red)")

_, p23 = port_status(SWITCH, "23")
print(f"        port 23: status={p23['status']} enabled={p23['enabled']} "
      f"isUplink={p23['isUplink']} speed={p23['speed']!r}")
check(p23["status"] == "Disconnected", "status uses Meraki's enum value 'Disconnected'")
check(isinstance(p23["speed"], str) and p23["speed"] == "",
      "speed is an empty string while down (Meraki enum, not an integer)")

state, why = ni_state(p23)
check(state == "critical", f"NI grades the fault 'critical' ({why})", f"got {state}: {why}")

# The adjacency must also disappear from LLDP discovery.
nodes = api(f"/organizations/{ORG}/devices/topology/nodes/discovered?perPage=1000")
reporters = {(x["reporter"]["id"], x["reporter"]["interface"]["id"]) for x in nodes["items"]}
check((SWITCH, "23") not in reporters,
      "nodes/discovered drops the down adjacency",
      f"{len(nodes['items'])} adjacencies still advertised")

events = get("/api/events?limit=40")
mine = [e for e in events if e.get("deviceSerial") == SWITCH]
check(bool(mine), "event attributed to the specific switch, not an arbitrary device")
check(any(e["networkId"] == NETWORK for e in events),
      "event scoped to the flagship store network")
if mine:
    print(f"        latest: [{mine[-1]['severity']}] {mine[-1]['description'][:70]}")

print("\n" + "=" * 78)
print("Scenario B: pos_camera_port_crc_errors  (NI critical via rule b)")
print("=" * 78)

_, p11 = port_status(SWITCH, "11")
check(p11["isUplink"] is False,
      "port 11 is an ACCESS port — a bare link-down here would read 'ok' in NI")
state, why = ni_state(p11)
check(state == "ok", f"pre-fault NI state is 'ok' ({why})", f"got {state}")

print(f"\n  TRIGGER -> {post('/api/scenarios/pos_camera_port_crc_errors/trigger').strip()}")
time.sleep(2.0)

_, p11 = port_status(SWITCH, "11")
print(f"        port 11: status={p11['status']} errors={p11['errors']} "
      f"warnings={p11['warnings']}")
check(p11["status"] == "Connected", "port stays link-up (this is a degradation, not an outage)")
check(any("crc" in e.lower() for e in p11["errors"]),
      "port carries a genuine CRC error string")

state, why = ni_state(p11)
check(state == "critical", f"NI grades the CRC fault 'critical' ({why})", f"got {state}: {why}")

print("\n" + "=" * 78)
print("Regression guard: NI must NOT grade a healthy access port as a fault")
print("=" * 78)
_, p1 = port_status(SWITCH, "1")
state, why = ni_state(p1)
print(f"        port 1 (sales floor AP): status={p1['status']} isUplink={p1['isUplink']} "
      f"errors={p1['errors']} -> NI '{state}' ({why})")
check(state == "ok", "healthy access port grades 'ok'", f"got {state}")

print("\n  Note: scenario A self-heals after its 90s hold and B after 300s; not awaited.")

print("\n" + "=" * 78)
if FAILURES:
    print(f"FAILED — {len(FAILURES)} check(s):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("ALL SCENARIO PROPAGATION AND NI-GRADING CHECKS PASSED")
print("=" * 78)
