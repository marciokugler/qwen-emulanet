"""Live smoke test: call every endpoint the Splunk Meraki add-on will poll,
from inside the Splunk container, using the same base URL and API key.

This catches the two failure modes that offline checks cannot:
  - the container cannot reach the emulator (localhost vs host.docker.internal)
  - a route 404s or returns a non-200 to a bare GET, which makes the add-on
    refuse to save the input ("a deterministic 400, 403, or 404 is reported
    before the input is created")

Requires: emulator running on the host, emulanet-splunk container running.
"""

import json
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

CONTAINER = "emulanet-splunk"
BASE = "https://host.docker.internal:5000/api/v1"
# The emulator's cert is self-signed. The container trusts it through the same
# vendored certifi bundle the add-on's httpx client uses (the cert is appended
# to it), so this check exercises the add-on's real trust path.
CACERT = "/opt/splunk/etc/apps/Splunk_TA_cisco_meraki/lib/certifi/cacert.pem"
KEY = "6789123456789012345678901234567890123456"
ORG = "2947"

FAILURES: list[str] = []


def curl(path: str) -> tuple[int, str]:
    """GET a path from inside the container; return (status, body)."""
    cmd = [
        "docker", "exec", CONTAINER, "curl", "-s", "-w", "\n%{http_code}",
        "--max-time", "25", "--cacert", CACERT,
        "-H", f"X-Cisco-Meraki-API-Key: {KEY}",
        BASE + path,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    out = p.stdout
    if "\n" not in out:
        return -1, out
    body, _, status = out.rpartition("\n")
    try:
        return int(status), body
    except ValueError:
        return -1, out


def check(label: str, path: str, validate=None) -> dict | list | None:
    status, body = curl(path)
    if status != 200:
        print(f"  FAIL  {label}\n          HTTP {status} for {path}")
        if body.strip():
            print(f"          body: {body.strip()[:200]}")
        FAILURES.append(label)
        return None

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"  FAIL  {label} — non-JSON response ({exc})")
        FAILURES.append(label)
        return None

    if validate:
        problem = validate(data)
        if problem:
            print(f"  FAIL  {label} — {problem}")
            FAILURES.append(label)
            return None

    size = len(body)
    count = len(data) if isinstance(data, (list, dict)) else 0
    print(f"  PASS  {label:<52} HTTP 200  {size:>8,} bytes  {count} top-level")
    return data


print("=" * 78)
print("Live add-on smoke test — requests originate inside the Splunk container")
print(f"Base URL: {BASE}")
print("=" * 78)

# ---------------------------------------------------------------------------
print("\n[1] Container -> host reachability")
p = subprocess.run(
    ["docker", "exec", CONTAINER, "curl", "-s", "--max-time", "15",
     "--cacert", CACERT,
     "https://host.docker.internal:5000/health"],
    capture_output=True, text=True, timeout=60)
if '"devices"' in p.stdout:
    print(f"  PASS  host.docker.internal:5000 reachable -> {p.stdout.strip()}")
else:
    print(f"  FAIL  cannot reach emulator from container: {p.stdout[:200]} {p.stderr[:200]}")
    FAILURES.append("container->host reachability")

# ---------------------------------------------------------------------------
print("\n[2] Auth: valid key accepted, invalid key rejected")
status, _ = curl("/organizations")
print(f"  {'PASS' if status == 200 else 'FAIL'}  valid API key -> HTTP {status}")
if status != 200:
    FAILURES.append("valid key accepted")

p = subprocess.run(
    ["docker", "exec", CONTAINER, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
     "--max-time", "15", "--cacert", CACERT,
     "-H", "X-Cisco-Meraki-API-Key: wrong-key",
     f"{BASE}/organizations"],
    capture_output=True, text=True, timeout=60)
print(f"  {'PASS' if p.stdout.strip() == '401' else 'FAIL'}  invalid API key -> HTTP {p.stdout.strip()} (expect 401)")
if p.stdout.strip() != "401":
    FAILURES.append("invalid key rejected with 401")

# Cisco's own SDK authenticates with `Authorization: Bearer <key>`; the real
# Dashboard API accepts both forms, so the emulator must too.
p = subprocess.run(
    ["docker", "exec", CONTAINER, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
     "--max-time", "15", "--cacert", CACERT,
     "-H", f"Authorization: Bearer {KEY}",
     f"{BASE}/organizations"],
    capture_output=True, text=True, timeout=60)
print(f"  {'PASS' if p.stdout.strip() == '200' else 'FAIL'}  Bearer auth (SDK form) -> HTTP {p.stdout.strip()} (expect 200)")
if p.stdout.strip() != "200":
    FAILURES.append("bearer auth accepted")

# ---------------------------------------------------------------------------
print("\n[3] OpenAPI document the add-on uses for endpoint discovery")


def v_spec(d):
    if not isinstance(d.get("paths"), dict) or not d["paths"]:
        return "no paths object"
    for path, item in d["paths"].items():
        op = item.get("get")
        if not op:
            return f"{path} has no GET"
        if not str(op.get("operationId", "")).startswith("get"):
            return f"{path} operationId does not start with 'get'"
        names = [p.get("name") for p in op.get("parameters", []) if p.get("in") == "query"]
        if "perPage" not in names:
            return f"{path} missing perPage -> collector will not unwrap items[]"
        resp = op.get("responses", {}).get("200", {})
        if "application/json" not in resp.get("content", {}):
            return f"{path} 200 response is not application/json"
    return None


spec = check("GET /organizations/{id}/openapiSpec", f"/organizations/{ORG}/openapiSpec", v_spec)
if spec:
    ops = [item["get"]["operationId"] for item in spec["paths"].values()]
    print(f"          discoverable operations: {ops}")

# ---------------------------------------------------------------------------
print("\n[4] Endpoints that feed Splunk Network Intelligence")


def v_bare_devices(d):
    if not isinstance(d, list) or not d:
        return "expected a non-empty bare array"
    return None


def v_avail(d):
    if not isinstance(d, list) or not d:
        return "expected a non-empty bare array"
    want = {"mac", "name", "network", "productType", "serial", "status", "tags"}
    extra = set(d[0]) - want
    missing = want - set(d[0])
    if extra or missing:
        return f"field mismatch extra={sorted(extra)} missing={sorted(missing)}"
    allowed = {"alerting", "dormant", "offline", "online"}
    bad = {r["status"] for r in d} - allowed
    if bad:
        return f"status outside Meraki enum: {bad}"
    return None


def v_enveloped(d):
    if not isinstance(d, dict) or not isinstance(d.get("items"), list):
        return "expected an object with an items[] list"
    if "meta" not in d:
        return "missing meta (pagination counts)"
    return None


def v_ports_by_switch(d):
    if not isinstance(d, list) or not d:
        return "expected a non-empty bare array"
    r = d[0]
    for f in ("serial", "mac", "network", "model", "ports"):
        if f not in r:
            return f"record missing {f!r}"
    if "id" not in r["network"]:
        return "network.id missing (NI site parenting)"
    if not r["ports"]:
        return "ports[] empty"
    return None


def v_statuses_by_switch(d):
    if not isinstance(d, dict) or not isinstance(d.get("items"), list) or not d["items"]:
        return "expected an envelope with a non-empty items[]"
    r = d["items"][0]
    for f in ("serial", "mac", "network", "model", "ports"):
        if f not in r:
            return f"record missing {f!r}"
    p = r["ports"][0]
    for f in ("portId", "enabled", "status", "isUplink", "errors", "warnings",
              "speed", "duplex", "spanningTree", "poe", "securePort"):
        if f not in p:
            return f"port missing {f!r} (NI reads it)"
    if p["status"] not in ("Connected", "Disabled", "Disconnected"):
        return f"port status {p['status']!r} outside Meraki enum"
    if not isinstance(p["speed"], str):
        return f"port speed must be a string, got {type(p['speed']).__name__}"
    return None


def v_usage_history(d):
    if not isinstance(d, dict) or not isinstance(d.get("items"), list) or not d["items"]:
        return "expected an envelope with a non-empty items[]"
    withports = next((r for r in d["items"] if r.get("ports")), None)
    if not withports:
        return "no switch reports any port usage"
    iv = withports["ports"][0]["intervals"][0]
    for f in ("startTs", "endTs", "data", "bandwidth", "energy"):
        if f not in iv:
            return f"interval missing {f!r}"
    return None


def v_uplink_addresses(d):
    if not isinstance(d, list) or not d:
        return "expected a non-empty bare array"
    r = d[0]
    for f in ("mac", "name", "network", "productType", "serial", "tags", "uplinks"):
        if f not in r:
            return f"record missing {f!r}"
    iface = r["uplinks"][0]["interface"]
    if iface not in ("cellular", "man1", "man2", "wan1", "wan2"):
        return f"interface {iface!r} outside Meraki enum"
    return None


def v_loss_latency(d):
    if not isinstance(d, list) or not d:
        return "expected a non-empty bare array"
    r = d[0]
    for f in ("networkId", "serial", "uplink", "ip", "timeSeries"):
        if f not in r:
            return f"record missing {f!r}"
    if not r["timeSeries"]:
        return "timeSeries[] empty"
    pt = r["timeSeries"][0]
    for f in ("ts", "lossPercent", "latencyMs"):
        if f not in pt:
            return f"timeSeries point missing {f!r}"
    return None


def v_nodes(d):
    if not isinstance(d, dict) or not isinstance(d.get("items"), list) or not d["items"]:
        return "expected an envelope with a non-empty items[]"
    it = d["items"][0]
    if it.get("protocol") not in ("CDP", "LLDP"):
        return f"protocol {it.get('protocol')!r} not CDP/LLDP"
    if "id" not in it.get("reporter", {}):
        return "reporter.id missing (NI src_id_value)"
    if "interface" not in it.get("reporter", {}):
        return "reporter.interface missing"
    disc = it.get("discovered", {})
    for f in ("derivedId", "system", "chassis", "port", "mac", "addresses"):
        if f not in disc:
            return f"discovered.{f} missing"
    return None


def v_links(d):
    if not isinstance(d, dict) or not isinstance(d.get("items"), list) or not d["items"]:
        return "expected an envelope with a non-empty items[]"
    it = d["items"][0]
    for f in ("linkId", "isStpDisabled", "site", "source", "target"):
        if f not in it:
            return f"link missing {f!r}"
    for side in ("source", "target"):
        dev = it[side].get("device", {})
        if not dev.get("id"):
            return f"{side}.device.id missing (NI {'src' if side=='source' else 'dst'}_id_value)"
        if not dev.get("port", {}).get("id"):
            return f"{side}.device.port.id missing"
    return None


avail = check("devices/availabilities  -> NI vertex:device",
              f"/organizations/{ORG}/devices/availabilities", v_avail)
check("devices  -> meraki:devices inventory",
      f"/organizations/{ORG}/devices", v_bare_devices)
check("organizations/networks  -> site vertices",
      f"/organizations/{ORG}/networks", v_bare_devices)
check("switch/ports/bySwitch  -> interface vertices",
      f"/organizations/{ORG}/switch/ports/bySwitch", v_ports_by_switch)
check("switch/ports/statuses/bySwitch  -> interface_status",
      f"/organizations/{ORG}/switch/ports/statuses/bySwitch", v_statuses_by_switch)
check("switch/ports/usage/history/byDevice/byInterval  -> throughput+power",
      f"/organizations/{ORG}/switch/ports/usage/history/byDevice/byInterval?timespan=1200",
      v_usage_history)
check("devices/uplinks/addresses/byDevice  -> uplink vertices",
      f"/organizations/{ORG}/devices/uplinks/addresses/byDevice", v_uplink_addresses)
check("devices/uplinksLossAndLatency  -> uplink_quality",
      f"/organizations/{ORG}/devices/uplinksLossAndLatency?timespan=3600", v_loss_latency)
nodes = check("devices/topology/nodes/discovered  -> NI edges",
              f"/organizations/{ORG}/devices/topology/nodes/discovered?perPage=1000", v_nodes)
links = check("devices/topology/l2/links  -> NI edges",
              f"/organizations/{ORG}/devices/topology/l2/links?perPage=1000", v_links)

# ---------------------------------------------------------------------------
print("\n[5] Save-time probe: the add-on rejects a deterministic 404")
# On save the add-on issues one bounded, non-paginated request. Every endpoint
# it might select must answer 200 to a bare GET with no query parameters.
for label, path in (
    ("nodes/discovered (bare GET)", f"/organizations/{ORG}/devices/topology/nodes/discovered"),
    ("l2/links (bare GET)", f"/organizations/{ORG}/devices/topology/l2/links"),
):
    status, _ = curl(path)
    ok = status == 200
    print(f"  {'PASS' if ok else 'FAIL'}  {label} -> HTTP {status}")
    if not ok:
        FAILURES.append(label)

# ---------------------------------------------------------------------------
print("\n[6] Topology volume the graph will contain")
if nodes and links:
    n_items = nodes["items"]
    l_items = links["items"]
    reporters = {x["reporter"]["id"] for x in n_items}
    discovered = {x["discovered"]["derivedId"] for x in n_items}
    print(f"          nodes/discovered : {len(n_items)} adjacencies, "
          f"{len(reporters)} reporters, {len(discovered)} distinct neighbours")
    print(f"          l2/links         : {len(l_items)} links, "
          f"meta.total={links['meta']['counts']['items']['total']}")
    srcs = {x["source"]["device"]["id"] for x in l_items}
    tgts = {x["target"]["device"]["id"] for x in l_items}
    print(f"          distinct endpoints in graph: {len(srcs | tgts)}")
    if avail:
        print(f"          device vertices available  : {len(avail)}")

print("\n" + "=" * 78)
if FAILURES:
    print(f"FAILED — {len(FAILURES)} check(s):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("ALL LIVE ADD-ON CHECKS PASSED")
print("=" * 78)
