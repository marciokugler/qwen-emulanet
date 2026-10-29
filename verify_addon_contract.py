"""Verify the emulator satisfies the Splunk Meraki add-on + Network Intelligence contract.

Two independent sources of truth are checked:

1. The add-on's endpoint-discovery policy, mirrored from
   Splunk_TA_cisco_meraki/bin/cisco_meraki_catalog_refresh.py (v3.5.0) and
   cisco_meraki_custom_api_policy.py. If our OpenAPI document fails these rules
   the topology endpoints cannot be selected in the add-on UI at all.

2. Splunk Network Intelligence's field expressions, mirrored from
   network_intelligence/default/props.conf and capability_bindings.conf (v26.9.0).
   These decide whether ingested data becomes graph edges, device vertices, and
   correct health states.

Runs offline against the generators; also asserts every required route is
registered on the FastAPI app so path typos cannot slip through.
"""

import re
import sys

from src.api.server import create_api_server
from src.data import generators as gen
from src.data import topology as topo
from src.topology.loader import load_topology
from src.topology.models import DeviceStatus

sys.stdout.reconfigure(encoding="utf-8")

FAILURES: list[str] = []


def check(condition: bool, label: str, detail: str = ""):
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}{(' — ' + detail) if detail else ''}")
        FAILURES.append(label)


# ---------------------------------------------------------------------------
# Constants mirrored from the add-on (cisco_meraki_custom_api_policy.py)
# ---------------------------------------------------------------------------
ORGANIZATION_ROOT = "/organizations/{organizationId}"
MAX_PATH_LENGTH = 1024
MERAKI_PAGINATION_PARAMETERS = frozenset({"startingAfter", "endingBefore"})
SUPPORTED_QUERY_TYPES = frozenset({"string", "integer", "number", "boolean"})
QUERY_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")

BLOCKED_DISCOVERY_SEGMENTS = frozenset({
    "admins", "administrators", "apikeys", "apnscert", "artifacts", "authorities",
    "captures", "certificates", "certs", "clientsecrets", "credentials", "crls",
    "download", "downloadurl", "exports", "idps", "keys", "liveresults",
    "livetools", "loginsecurity", "mqttsettings", "packetcapture", "permissions",
    "privatekeys", "roles", "saml", "secrets", "snmp", "thirdpartyvpnpeers",
    "tokens", "vppaccounts",
})
BLOCKED_DISCOVERY_TAGS = frozenset({
    "administer", "admins", "artifacts", "certificates", "configure",
    "credentials", "liveresults", "livetools", "packetcapture", "permissions",
    "saml", "secrets", "snmp", "tokens",
})

# Mirrored from NI props.conf / capability_bindings.conf.
NI_EDGE_ENDPOINTS = {"devices_topology_l2_links", "devices_topology_nodes_discovered"}
SPEED_RE = re.compile(r"^[0-9.]+ (gbps|mbps|kbps|bps)$")
PORT_STATUS_ENUM = {"Connected", "Disabled", "Disconnected"}
UPLINK_INTERFACE_ENUM = {"cellular", "man1", "man2", "wan1", "wan2"}
AVAILABILITY_ENUM = {"alerting", "dormant", "offline", "online"}


def endpoint_name(operation_id: str) -> str:
    """Mirror of the add-on's _endpoint_name()."""
    name = operation_id.removeprefix("getOrganization")
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:96]


def validate_discovery(path: str, operation: dict) -> list[str]:
    """Return a list of reasons the add-on would reject this operation."""
    problems = []

    if len(path) > MAX_PATH_LENGTH:
        problems.append("path too long")

    placeholders = re.findall(r"\{([^{}]+)\}", path)
    if not (path == ORGANIZATION_ROOT or path.startswith(f"{ORGANIZATION_ROOT}/")):
        problems.append("not organization-scoped")
    if placeholders != ["organizationId"]:
        problems.append(f"placeholders must be exactly ['organizationId'], got {placeholders}")

    op_id = operation.get("operationId")
    if not isinstance(op_id, str) or not op_id.startswith("get") or len(op_id) > 256:
        problems.append("invalid operationId")
        return problems

    tags = operation.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
        problems.append("invalid tags")

    path_tokens = {seg.lower() for seg in path.split("/") if seg and not seg.startswith("{")}
    op_tokens = {t.lower() for t in re.findall(r"[A-Z][a-z0-9]*", op_id)}
    if (path_tokens | op_tokens) & BLOCKED_DISCOVERY_SEGMENTS:
        problems.append("blocked path/operation segment")
    if {t.lower() for t in tags} & BLOCKED_DISCOVERY_TAGS:
        problems.append("blocked tag")

    if operation.get("requestBody") is not None:
        problems.append("GET with requestBody is rejected")

    responses = operation.get("responses")
    has_json = False
    if isinstance(responses, dict):
        for status, resp in responses.items():
            s = str(status).upper()
            if s != "DEFAULT" and not s.startswith("2"):
                continue
            content = (resp or {}).get("content")
            if isinstance(content, dict) and any(
                str(mt).lower() == "application/json" or str(mt).lower().endswith("+json")
                for mt in content
            ):
                has_json = True
    if not has_json:
        problems.append("no JSON 2xx/default response declared")

    for param in operation.get("parameters", []):
        loc, name = param.get("in"), param.get("name")
        if loc == "path":
            continue
        if loc != "query" or not isinstance(name, str):
            continue
        if len(name) > 128 or not QUERY_NAME_RE.fullmatch(name):
            problems.append(f"unsafe query parameter name {name!r}")
            continue
        if name in MERAKI_PAGINATION_PARAMETERS:
            continue
        schema = param.get("schema") or {}
        if schema.get("type") not in SUPPORTED_QUERY_TYPES:
            problems.append(f"unsupported query parameter type for {name!r}")

    return problems


def is_paginated(operation: dict) -> bool:
    """Mirror of: paginated = bool(pagination_names or "perPage" in query_names)."""
    pagination_names = set()
    query_names = set()
    for param in operation.get("parameters", []):
        if param.get("in") != "query":
            continue
        name = param.get("name")
        if not isinstance(name, str):
            continue
        if name in MERAKI_PAGINATION_PARAMETERS:
            pagination_names.add(name)
        else:
            query_names.add(name)
    return bool(pagination_names or "perPage" in query_names)


# ===========================================================================
state = load_topology("config/topology.yaml")
print(f"Loaded {len(state.networks)} networks, {len(state.devices)} devices, "
      f"{len(state.links)} links\n")

# ---------------------------------------------------------------------------
print("[1] OpenAPI document passes the add-on's discovery policy")
spec = topo.generate_openapi_spec(state)
check(isinstance(spec.get("paths"), dict) and spec["paths"], "spec has a non-empty paths object")
check(len(spec["paths"]) <= 5000, "spec within MAX_PATHS (5000)")

discovered_names = set()
for path, item in spec["paths"].items():
    op = item.get("get")
    check(op is not None, f"{path} declares a GET operation")
    if not op:
        continue
    problems = validate_discovery(path, op)
    check(not problems, f"{path} passes discovery policy", "; ".join(problems))
    check(is_paginated(op),
          f"{path} declares perPage so paginated=True",
          "without this the collector will NOT unwrap the items[] envelope")
    discovered_names.add(endpoint_name(op["operationId"]))

check(NI_EDGE_ENDPOINTS <= discovered_names,
      "discovered endpoint_names include both NI edge sources",
      f"got {sorted(discovered_names)}")
print(f"        derived endpoint_names: {sorted(discovered_names)}")

# ---------------------------------------------------------------------------
print("\n[2] Every endpoint NI consumes is registered at the documented path")
app = create_api_server(state, "test-key")
registered = {getattr(r, "path", "") for r in app.routes}

REQUIRED_PATHS = {
    "/api/v1/organizations/{org_id}/devices": "meraki:devices",
    "/api/v1/organizations/{org_id}/devices/availabilities": "meraki.device_availability",
    "/api/v1/organizations/{org_id}/switch/ports/bySwitch": "meraki.switchportsbyswitch adapter",
    "/api/v1/organizations/{org_id}/switch/ports/statuses/bySwitch": "meraki.interface_status",
    "/api/v1/organizations/{org_id}/switch/ports/usage/history/byDevice/byInterval":
        "meraki.interface_throughput + interface_power",
    "/api/v1/organizations/{org_id}/devices/uplinks/addresses/byDevice": "uplink interface vertices",
    "/api/v1/organizations/{org_id}/devices/uplinksLossAndLatency": "meraki.interface_uplink_quality",
    "/api/v1/organizations/{org_id}/devices/topology/nodes/discovered": "NI edge (dst via discovered.derivedId)",
    "/api/v1/organizations/{org_id}/devices/topology/l2/links": "NI edge (src/dst device.id)",
    "/api/v1/organizations/{org_id}/openapiSpec": "add-on catalog discovery",
}
for path, consumer in REQUIRED_PATHS.items():
    check(path in registered, f"{path}", f"not registered — needed by {consumer}")

# The old wrong paths must be gone, or the add-on may hit a stale route.
for stale in ("/api/v1/organizations/{org_id}/openapi/spec",
              "/api/v1/organizations/{org_id}/devices/uplinks/lossAndLatency"):
    check(stale not in registered, f"stale path removed: {stale}")

# ---------------------------------------------------------------------------
print("\n[3] devices/availabilities matches the documented 7-field bare array")
avail = gen.generate_device_availability(state)
check(isinstance(avail, list), "response is a bare array, not an envelope")
DOCUMENTED = {"mac", "name", "network", "productType", "serial", "status", "tags"}
check(set(avail[0]) == DOCUMENTED,
      "fields are exactly the documented set",
      f"extra={sorted(set(avail[0]) - DOCUMENTED)} missing={sorted(DOCUMENTED - set(avail[0]))}")
bad_status = {r["status"] for r in avail} - AVAILABILITY_ENUM
check(not bad_status, "every status is in Meraki's enum", f"invalid: {bad_status}")
check(all("id" in r["network"] for r in avail), "network.id present on every record")
check(len({r["serial"] for r in avail}) == len(state.devices),
      "one availability record per device (NI keys vertex:device on serial)")

# A degraded device must surface as "alerting", which NI grades as degraded.
probe = next(iter(state.devices.values()))
original = probe.status
try:
    probe.status = DeviceStatus.DEGRADED
    mapped = {r["status"] for r in gen.generate_device_availability(state)
              if r["serial"] == probe.serial}
    check(mapped == {"alerting"},
          "internal DEGRADED maps to Meraki 'alerting'",
          f"got {mapped}; NI would grade this 'unknown'")
    probe.status = DeviceStatus.OFFLINE
    mapped = {r["status"] for r in gen.generate_device_availability(state)
              if r["serial"] == probe.serial}
    check(mapped == {"offline"}, "internal OFFLINE maps to 'offline' (NI grades critical)")
finally:
    probe.status = original

# ---------------------------------------------------------------------------
print("\n[4] switch/ports/statuses/bySwitch matches NI's interface_status expressions")
by_switch = topo.generate_switch_port_statuses_by_switch(state)
check("items" in by_switch and "meta" in by_switch, "enveloped with items + meta")
rec = by_switch["items"][0]
check({"name", "serial", "mac", "network", "model", "ports"} <= set(rec),
      "per-switch record carries serial, mac, network and nested ports[]")
port = rec["ports"][0]
NI_PORT_FIELDS = {"portId", "enabled", "status", "isUplink", "errors", "warnings",
                  "speed", "duplex", "spanningTree", "poe", "securePort"}
check(NI_PORT_FIELDS <= set(port),
      "port exposes every field NI reads",
      f"missing {sorted(NI_PORT_FIELDS - set(port))}")
check("statuses" in port["spanningTree"], "spanningTree.statuses[] present")
check("isAllocated" in port["poe"], "poe.isAllocated present")
check({"active", "authenticationStatus"} <= set(port["securePort"]),
      "securePort.active and .authenticationStatus present")

all_statuses = {p["status"] for r in by_switch["items"] for p in r["ports"]}
check(all_statuses <= PORT_STATUS_ENUM,
      "port status uses Meraki's enum", f"invalid: {all_statuses - PORT_STATUS_ENUM}")
all_speeds = {p["speed"] for r in by_switch["items"] for p in r["ports"]}
check(all(isinstance(s, str) for s in all_speeds),
      "speed is a string, never an integer")
check(all(s == "" or SPEED_RE.match(s.lower()) for s in all_speeds),
      "every non-empty speed matches NI's '^[0-9.]+ (g| m|k|)bps$' pattern",
      f"offenders: {[s for s in all_speeds if s and not SPEED_RE.match(s.lower())]}")

# The demo-critical rule: a down uplink must read "Disconnected" while enabled.
switch = state.get_device("Q2QN-HQ01-MS01")
uplink_port = next(p for p in switch.ports if p.number == "49")
was_up = uplink_port.is_up
try:
    uplink_port.is_up = False
    down = topo.generate_switch_port_statuses_by_switch(state)
    target = next(p for r in down["items"] if r["serial"] == switch.serial
                  for p in r["ports"] if p["portId"] == "49")
    check(target["status"] == "Disconnected" and target["enabled"] and target["isUplink"],
          "down uplink yields enabled=true + status='Disconnected' + isUplink=true",
          f"got status={target['status']!r} enabled={target['enabled']} isUplink={target['isUplink']}")
    print("        -> NI state_expr grades this combination 'critical' (score 0)")
finally:
    uplink_port.is_up = was_up

# ---------------------------------------------------------------------------
print("\n[5] switch/ports/bySwitch supports NI's mac-parented interface vertices")
ports_by_switch = topo.generate_switch_ports_by_switch(state)
check(isinstance(ports_by_switch, list), "bare array per the documented schema")
sw = ports_by_switch[0]
check({"name", "serial", "mac", "network", "model", "ports"} <= set(sw),
      "per-switch record has mac and network.id for vertex parenting")
ADAPTER_FIELDS = {"portId", "name", "type", "enabled", "vlan", "voiceVlan",
                  "allowedVlans", "poeEnabled", "linkNegotiation", "rstpEnabled",
                  "stpGuard", "accessPolicyType"}
p0 = sw["ports"][0]
check(ADAPTER_FIELDS <= set(p0),
      "port carries every field the graph adapter expands",
      f"missing {sorted(ADAPTER_FIELDS - set(p0))}")
check(all(re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", r["mac"].lower())
          for r in ports_by_switch), "every mac is colon-formatted lowercase hex")

# ---------------------------------------------------------------------------
print("\n[6] uplinksLossAndLatency matches NI's interface_uplink_quality expansion")
ll = topo.generate_uplinks_loss_and_latency(state)
check(isinstance(ll, list) and ll, "bare non-empty array")
check({"networkId", "serial", "uplink", "ip", "timeSeries"} <= set(ll[0]),
      "record has serial, uplink, ip and timeSeries[]")
check(all(u["uplink"] in UPLINK_INTERFACE_ENUM for u in ll),
      "uplink values come from the documented enum",
      f"invalid: {sorted({u['uplink'] for u in ll} - UPLINK_INTERFACE_ENUM)}")
pt = ll[0]["timeSeries"][0]
check({"ts", "lossPercent", "latencyMs"} <= set(pt), "timeSeries point has ts/lossPercent/latencyMs")
check(all(isinstance(x["lossPercent"], float) and isinstance(x["latencyMs"], float)
          for u in ll for x in u["timeSeries"]), "lossPercent and latencyMs are floats")

# NI grades critical at loss>=20 or latency>=300. A degraded gateway must cross it.
gw = state.get_device("Q2QN-S0203-MX01")
saved = (gw.status, gw.uplink.latency_ms, gw.uplink.loss_percent)
try:
    gw.status = DeviceStatus.DEGRADED
    gw.uplink.latency_ms = 280.0
    gw.uplink.loss_percent = 9.0
    row = next(r for r in topo.generate_uplinks_loss_and_latency(state) if r["serial"] == gw.serial)
    worst_loss = max(x["lossPercent"] for x in row["timeSeries"])
    worst_lat = max(x["latencyMs"] for x in row["timeSeries"])
    check(worst_loss >= 5 or worst_lat >= 150,
          "degraded gateway crosses NI's 'degraded' threshold (loss>=5 or latency>=150)",
          f"worst loss={worst_loss} latency={worst_lat}")
finally:
    gw.status, gw.uplink.latency_ms, gw.uplink.loss_percent = saved

healthy = [r for r in ll if r["serial"] == "Q2QN-HQ01-MX01"]
if healthy:
    worst = max(max(x["lossPercent"] for x in healthy[0]["timeSeries"]), 0)
    worst_l = max(max(x["latencyMs"] for x in healthy[0]["timeSeries"]), 0)
    check(worst < 5 and worst_l < 150,
          "healthy hub stays inside NI's 'ok' band", f"loss={worst} latency={worst_l}")

# ---------------------------------------------------------------------------
print("\n[7] uplinks/addresses/byDevice supports uplink interface vertices")
addr = topo.generate_uplink_addresses_by_device(state)
check(isinstance(addr, list) and addr, "bare non-empty array")
check({"mac", "name", "network", "productType", "serial", "tags", "uplinks"} <= set(addr[0]),
      "record has mac, network.id, productType and uplinks[]")
iface = addr[0]["uplinks"][0]
check({"interface", "addresses"} <= set(iface), "uplink has interface and addresses[]")
check(all(u["interface"] in UPLINK_INTERFACE_ENUM
          for r in addr for u in r["uplinks"]),
      "every interface is in the documented enum")
a0 = iface["addresses"][0]
check({"protocol", "assignmentMode", "address", "gateway", "nameservers", "public", "vlan"}
      <= set(a0), "address object carries all documented fields")

# ---------------------------------------------------------------------------
print("\n[8] port usage history supports throughput and power capabilities")
usage = topo.generate_switch_ports_usage_history(state, timespan=1200)
check("items" in usage and "meta" in usage, "enveloped with items + meta")
u_rec = next((r for r in usage["items"] if r["ports"]), None)
check(u_rec is not None, "at least one switch reports port usage")
if u_rec:
    iv = u_rec["ports"][0]["intervals"][0]
    check({"startTs", "endTs", "data", "bandwidth", "energy"} <= set(iv),
          "interval has startTs/endTs/data/bandwidth/energy")
    check({"total", "upstream", "downstream"} <= set(iv["data"]["usage"]),
          "data.usage has total/upstream/downstream (kilobytes, int)")
    check({"total", "upstream", "downstream"} <= set(iv["bandwidth"]["usage"]),
          "bandwidth.usage has total/upstream/downstream (kbps, float)")
    check("total" in iv["energy"]["usage"], "energy.usage.total present (watt-hours)")
    check(all(isinstance(v, int) for v in iv["data"]["usage"].values()),
          "data.usage values are integers")
    check(all(isinstance(v, float) for v in iv["bandwidth"]["usage"].values()),
          "bandwidth.usage values are floats")

# ---------------------------------------------------------------------------
print("\n[9] Topology endpoints still emit the exact paths NI's EVALs read")
nodes = topo.generate_topology_nodes_discovered(state)
n0 = nodes["items"][0]
check({"protocol", "reporter", "discovered"} <= set(n0), "node has protocol/reporter/discovered")
check({"id", "interface"} <= set(n0["reporter"])
      and {"id", "status"} <= set(n0["reporter"]["interface"]),
      "reporter.id and reporter.interface.{id,status} present")
d0 = n0["discovered"]
check({"derivedId", "system", "chassis", "port", "mac", "addresses"} <= set(d0),
      "discovered.{derivedId,system,chassis,port,mac,addresses} present")
check({"name", "description", "platform", "capabilities"} <= set(d0["system"]),
      "discovered.system.{name,description,platform,capabilities} present")

links = topo.generate_topology_l2_links(state)
l0 = links["items"][0]
check("source" in l0 and "target" in l0, "link has source and target")
check(l0["source"]["device"]["id"] and l0["source"]["device"]["port"]["id"],
      "source.device.id and source.device.port.id present")
check(l0["target"]["device"]["id"] and l0["target"]["device"]["port"]["id"],
      "target.device.id and target.device.port.id present")
check("linkId" in l0 and "isStpDisabled" in l0, "linkId and isStpDisabled present")
check(l0["site"]["resource"]["type"] in ("network", "site"), "site.resource.type is network|site")

# ---------------------------------------------------------------------------
print("\n[10] Envelope shape is what the collector's _page_items() unwraps")
for label, payload in (("nodes/discovered", nodes), ("l2/links", links),
                       ("ports/statuses/bySwitch", by_switch),
                       ("ports/usage/history", usage)):
    check(isinstance(payload, dict) and isinstance(payload.get("items"), list),
          f"{label} is a dict with an items[] list (unwrappable)")

for label, payload in (("devices/availabilities", avail),
                       ("switch/ports/bySwitch", ports_by_switch),
                       ("devices/uplinks/addresses/byDevice", addr),
                       ("devices/uplinksLossAndLatency", ll)):
    check(isinstance(payload, list),
          f"{label} is a bare list (iterated directly)")

# ---------------------------------------------------------------------------
print("\n[11] Every registered route answers without a 500")
# A dangling model-field reference raises AttributeError inside a handler and
# surfaces only as HTTP 500 at runtime — invisible to shape checks that never
# call the function. Exercising every route catches that class of regression.
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app, headers={"X-Cisco-Meraki-API-Key": "test-key"})

sample_network = next(iter(state.networks.values()))
sample_device = state.get_device("Q2QN-HQ01-MS01") or next(iter(state.devices.values()))
sample_client_mac = next(iter(state.clients.values())).mac

SUBSTITUTIONS = {
    "org_id": "2947",
    "organizationId": "2947",
    "network_id": sample_network.id,
    "networkId": sample_network.id,
    "serial": sample_device.serial,
    "client_mac": sample_client_mac,
    "clientMac": sample_client_mac,
    "config_template_id": "N_1",
    "admin_id": "1",
    "ssid_number": "0",
    "vlan_id": "10",
    "id": "1",
}

errors_500 = []
route_count = 0
for route in app.routes:
    path = getattr(route, "path", "")
    methods = getattr(route, "methods", set()) or set()
    if not path.startswith("/api/v1/") or "GET" not in methods:
        continue

    resolved = path
    for token, value in SUBSTITUTIONS.items():
        resolved = resolved.replace("{" + token + "}", value)
    if "{" in resolved:
        # Unsubstituted placeholder — skip rather than send a bogus literal.
        continue

    route_count += 1
    try:
        resp = client.get(resolved)
    except Exception as exc:  # handler raised before returning a response
        errors_500.append(f"{resolved} -> exception {type(exc).__name__}: {exc}")
        continue
    if resp.status_code >= 500:
        errors_500.append(f"{resolved} -> HTTP {resp.status_code}")

print(f"        exercised {route_count} GET routes")
check(not errors_500,
      "no route returns a 5xx",
      f"{len(errors_500)} failing: {errors_500[:6]}")
if errors_500:
    for e in errors_500[:12]:
        print(f"          {e}")

# ---------------------------------------------------------------------------
print("\n" + "=" * 72)
if FAILURES:
    print(f"FAILED — {len(FAILURES)} check(s):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("ALL ADD-ON / NI CONTRACT CHECKS PASSED")
print("=" * 72)
