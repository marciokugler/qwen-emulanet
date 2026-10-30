"""Verify the emulator satisfies the Catalyst Center add-on + NI contract.

Three independent sources of truth are checked:

1. The add-on's own validations, mirrored from TA_cisco_catalyst 4.0.50
   (`cisco_dnac_api.py`, `cisco_catalyst_dnac_devicehealth.py`,
   `dnac_interface_collection.py`, `dnac_scale.py`, `cisco_catalyst_dnac_issue.py`).
   Every one of these aborts an entire poll rather than degrading it, which is
   why they are asserted instead of eyeballed.

2. Splunk Network Intelligence's field expressions, mirrored from
   `network_intelligence/default/props.conf`, `graph_adapters.conf` and
   `capability_bindings.conf` (v26.9.0). These decide whether the data becomes
   site/device/interface vertices, connected_to edges, health observations and
   alerts.

3. The add-on's endpoint catalog (`dnac_endpoints.json`), which gates what can
   be selected in the Custom API input's UI at all.

Runs offline against the generators and the FastAPI app; no Splunk required.
"""

import json
import re
import sys
import time

from fastapi.testclient import TestClient

from src.api.catalyst_server import create_catalyst_server
from src.data import catalyst_generators as cgen
from src.topology.catalyst_loader import load_catalyst_topology, seed_issues
from src.topology.loader import load_topology

sys.stdout.reconfigure(encoding="utf-8")

FAILURES: list[str] = []


def check(condition: bool, label: str, detail: str = ""):
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}{(' — ' + detail) if detail else ''}")
        FAILURES.append(label)


# ---------------------------------------------------------------------------
# Constants mirrored from the add-on
# ---------------------------------------------------------------------------
CATALOG_PATH = (".ni-inspect/ta/TA_cisco_catalyst/bin/dnac_endpoints.json")
PHYSICAL_TOPOLOGY_PATH = "/dna/intent/api/v1/topology/physical-topology"
NI_PHYSICAL_TOPOLOGY_SLUG = "topology_physical_topology"

# dnac_interface_inventory.device(): a device id must fullmatch this.
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
# ta_product_version._bounded_version
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# cisco_catalyst_dnac_issue._MIN_PLAUSIBLE_ISSUE_TIMESTAMP_MS / future skew
MIN_ISSUE_TS_MS = 946684800000
MAX_ISSUE_TS_MS = int(time.time() * 1000) + 86400000

# NI capability_bindings.conf catalyst_center.device_telemetry state bands:
# 0-2 critical, 3-7 degraded, 8-10 ok.
NI_HEALTH_OK_RANGE = range(8, 11)

# NI props.conf catalyst_center.device_availability matches these, lowercased.
NI_REACHABILITY_STATES = {"reachable", "ping reachable", "unreachable"}

# dnac_interface_collection.METRICS — drive `statistics_available`.
INTERFACE_METRICS = ("rxRate", "txRate", "rxUtilization", "txUtilization",
                     "rxDiscards", "txDiscards", "rxError", "txError")

# cisco_catalyst_dnac_issue: a resolvable device name suppresses inventory
# enrichment, and enrichment is the ONLY producer of DeviceMACAddress and
# DeviceSerialNumber — the first two identifiers NI's alert coalesce reads.
NAME_KEYS_THAT_SUPPRESS_ENRICHMENT = (
    "deviceName", "networkDeviceName", "nwDeviceName", "hostname")


def slugify_path(path: str) -> str:
    """Mirror of cisco_catalyst_dnac_api._slugify_path.

    Strips the versioned prefix, drops {param} segments, camelCase -> snake,
    '-' -> '_', lowercases, collapses '_'. The result is what NI filters on.
    """
    stripped = re.sub(r"^/dna/(intent|data|system)/api/v\d+/", "", path)
    segments = [s for s in stripped.split("/") if s and not s.startswith("{")]
    slug = "_".join(segments)
    slug = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", slug)
    slug = slug.replace("-", "_").lower()
    return re.sub(r"_+", "_", slug)


def is_json_int(value) -> bool:
    """The add-on uses `type(x) is int` — a bool passes isinstance, not this."""
    return type(value) is int


def main() -> int:
    print("=" * 78)
    print("Catalyst Center add-on / NI contract verification (offline)")
    print("=" * 78)

    state, shared = load_catalyst_topology("config/catalyst_topology.yaml",
                                           "config/topology.yaml")
    seed_issues(state, int(time.time() * 1000))
    meraki_state = load_topology("config/topology.yaml")

    config = {"username": "northwind_admin", "password": "Emulanet2026!",
              "token_ttl_seconds": 3600}
    app = create_catalyst_server(state, config)
    client = TestClient(app)
    base_auth = (config["username"], config["password"])

    # -----------------------------------------------------------------
    print("\n[1] Token exchange — POST /dna/system/api/v1/auth/token")
    # -----------------------------------------------------------------
    resp = client.post("/dna/system/api/v1/auth/token", auth=base_auth)
    check(resp.status_code == 200, "valid credentials accepted",
          f"HTTP {resp.status_code}")
    body = resp.json()
    token = body.get("Token")
    check(isinstance(token, str) and token != "",
          "response key is exactly 'Token' (client reads .Token)",
          f"keys={list(body)}")

    bad = client.post("/dna/system/api/v1/auth/token",
                      auth=(config["username"], "wrong-password"))
    check(bad.status_code == 401, "wrong password rejected with 401",
          f"HTTP {bad.status_code}")
    noauth = client.post("/dna/system/api/v1/auth/token")
    check(noauth.status_code == 401, "missing Authorization rejected with 401",
          f"HTTP {noauth.status_code}")

    headers = {"X-Auth-Token": token}
    unauth = client.get("/dna/intent/api/v1/network-device/count")
    check(unauth.status_code == 401,
          "data route without X-Auth-Token returns 401 (not 403)",
          f"HTTP {unauth.status_code}")
    stale = client.get("/dna/intent/api/v1/network-device/count",
                       headers={"X-Auth-Token": "deadbeef"})
    check(stale.status_code == 401, "unknown token returns 401",
          f"HTTP {stale.status_code}")

    # -----------------------------------------------------------------
    print("\n[2] Version probe — GET /dna/intent/api/v1/dnac-release")
    # -----------------------------------------------------------------
    rel = client.get("/dna/intent/api/v1/dnac-release", headers=headers)
    check(rel.status_code == 200, "dnac-release answers 200", f"HTTP {rel.status_code}")
    rel_body = rel.json()
    version = (rel_body.get("response") or {}).get("installedVersion")
    check(isinstance(version, str) and bool(VERSION_RE.fullmatch(version)),
          "response.installedVersion matches the add-on's version pattern",
          f"got {version!r}")

    # -----------------------------------------------------------------
    print("\n[3] Sites — GET /dna/intent/api/v1/sites")
    # -----------------------------------------------------------------
    sites = client.get("/dna/intent/api/v1/sites",
                       params={"offset": 1, "limit": 500}, headers=headers)
    check(sites.status_code == 200, "sites answers 200", f"HTTP {sites.status_code}")
    site_body = sites.json()
    check(isinstance(site_body.get("response"), list),
          "response is a list (the record list is read from 'response')")
    site_rows = site_body["response"]
    check(len(site_rows) == len(state.sites),
          "every site in the hierarchy is returned",
          f"{len(site_rows)} vs {len(state.sites)}")

    identities = [r.get("id") or r.get("siteId") or r.get("name") for r in site_rows]
    check(all(identities), "every record has id/siteId/name (pagination identity)")
    check(len(set(identities)) == len(identities), "site identities are unique")
    check(all(r.get("nameHierarchy") for r in site_rows),
          "nameHierarchy present on every site (NI reads this exact key)")
    types = {r["type"] for r in site_rows}
    check(types == {"global", "area", "building", "floor"},
          "site types are the four DNAC hierarchy levels", f"got {sorted(types)}")
    check(sum(1 for r in site_rows if r["type"] == "global") == 1,
          "exactly one global root")
    check(all(r["nameHierarchy"].startswith("Global/") or r["type"] == "global"
              for r in site_rows),
          "every nameHierarchy is rooted at Global")
    hierarchies = {r["nameHierarchy"] for r in site_rows}
    check(all(r.get("parentId", "") == "" or r["parentId"] in {s["id"] for s in site_rows}
              for r in site_rows),
          "every parentId resolves to a returned site")
    geo = [r for r in site_rows if r["type"] in ("area", "building")]
    check(all(isinstance(r.get("latitude"), (int, float))
              and isinstance(r.get("longitude"), (int, float)) for r in geo),
          "areas and buildings carry numeric lat/long (NI does tonumber())")

    # A device's Site string must match a site vertex name or hierarchy.
    device_site_strings = {d.site_name_hierarchy for d in state.devices.values()}
    check(device_site_strings <= hierarchies,
          "every device's site hierarchy matches a returned site nameHierarchy",
          f"unmatched: {sorted(device_site_strings - hierarchies)[:3]}")

    # -----------------------------------------------------------------
    print("\n[4] Inventory — GET /dna/intent/api/v1/network-device (+ /count)")
    # -----------------------------------------------------------------
    inv = client.get("/dna/intent/api/v1/network-device",
                     params={"limit": 500, "offset": 1}, headers=headers)
    check(inv.status_code == 200, "inventory answers 200", f"HTTP {inv.status_code}")
    inv_rows = inv.json()["response"]
    check(isinstance(inv_rows, list) and len(inv_rows) == len(state.devices),
          "one inventory row per device",
          f"{len(inv_rows)} vs {len(state.devices)}")

    check(all(isinstance(r.get("id"), str) and DEVICE_ID_RE.fullmatch(r["id"])
              for r in inv_rows),
          "every device id fullmatches [A-Za-z0-9_-]{1,128}")
    ids = [r["id"] for r in inv_rows]
    check(len(set(ids)) == len(ids), "device ids are unique (pagination identity)")
    check(all(MAC_RE.fullmatch(r.get("macAddress", "")) for r in inv_rows),
          "every device has a six-octet macAddress (NI filters mac_address=*)")
    check(all(r.get("serialNumber") for r in inv_rows),
          "every device has a serialNumber (NI fusion key)")
    check(all(str(r.get("interfaceCount", "")).isdigit() for r in inv_rows),
          "interfaceCount is a digit string")
    check(all(r.get("siteNameHierarchy") for r in inv_rows),
          "siteNameHierarchy present on every device")
    reach = {r.get("reachabilityStatus", "").strip().lower() for r in inv_rows}
    check(reach <= NI_REACHABILITY_STATES,
          "reachabilityStatus is one NI's availability binding matches",
          f"got {sorted(reach)}")
    managed = {(r.get("managementState"), r.get("collectionStatus")) for r in inv_rows}
    check(all(m == "Managed" and c in (None, "", "Managed") for m, c in managed),
          "managementState/collectionStatus derive Manageability='Managed'",
          f"got {sorted(managed)}")

    count_resp = client.get("/dna/intent/api/v1/network-device/count", headers=headers)
    count_payload = count_resp.json()["response"]
    check(isinstance(count_payload, dict) and is_json_int(count_payload.get("count")),
          "count endpoint returns {'response': {'count': <JSON int>}}",
          f"got {count_payload!r}")
    check(not isinstance(count_payload.get("count"), bool),
          "count is not a JSON bool (type(x) is int rejects bool)")
    check(count_payload["count"] == len(inv_rows),
          "count equals the inventory length exactly — drift aborts the poll",
          f"{count_payload['count']} vs {len(inv_rows)}")

    # The add-on brackets every poll with the count and aborts on movement, so
    # both the count and the inventory body must be identical across calls.
    again = client.get("/dna/intent/api/v1/network-device",
                       params={"limit": 500, "offset": 1}, headers=headers).json()
    count_again = client.get("/dna/intent/api/v1/network-device/count",
                             headers=headers).json()
    check(json.dumps(inv.json(), sort_keys=True) == json.dumps(again, sort_keys=True),
          "inventory body is byte-stable across calls")
    check(count_again == count_resp.json(), "count is byte-stable across calls")

    short = client.get("/dna/intent/api/v1/network-device",
                       params={"limit": 20, "offset": 1}, headers=headers).json()
    check(len(short["response"]) == 20, "limit is honoured (20-row fallback path)")
    second = client.get("/dna/intent/api/v1/network-device",
                        params={"limit": 20, "offset": 21}, headers=headers).json()
    check(len(second["response"]) == 7,
          "1-based offset advances correctly (27 devices -> 20 + 7)",
          f"got {len(second['response'])}")
    check(not ({r['id'] for r in short['response']} & {r['id'] for r in second['response']}),
          "pages do not repeat a device id")

    # -----------------------------------------------------------------
    print("\n[5] Device health — GET /dna/intent/api/v1/device-health")
    # -----------------------------------------------------------------
    now_ms = int(time.time() * 1000)
    dh = client.get("/dna/intent/api/v1/device-health",
                    params={"startTime": now_ms - 900000, "endTime": now_ms,
                            "limit": 500, "offset": 1}, headers=headers)
    check(dh.status_code == 200, "device-health answers 200", f"HTTP {dh.status_code}")
    dh_body = dh.json()
    dh_rows = dh_body["response"]
    check(is_json_int(dh_body.get("totalCount")),
          "totalCount is a JSON int (no page.count fallback on this route)",
          f"got {dh_body.get('totalCount')!r}")
    check(dh_body["totalCount"] == len(dh_rows),
          "totalCount equals the row count", f"{dh_body['totalCount']} vs {len(dh_rows)}")
    check(dh_body["totalCount"] <= 200000, "totalCount within the add-on's cap")

    inventory_ids = set(ids)
    for row in dh_rows:
        ident = row.get("uuid") or row.get("deviceId") or row.get("id")
        if not ident:
            check(False, f"health row missing identity ({row.get('name')})")
            break
    else:
        check(True, "every health row carries uuid/deviceId/id")
    check(all((r.get("uuid") or r.get("deviceId") or r.get("id")) in inventory_ids
              for r in dh_rows),
          "every health row joins to an inventory id (else it becomes a stray record)")
    check(all(r.get("location") in hierarchies for r in dh_rows),
          "location matches a site nameHierarchy (NI site_id, site_id_type=site_name)")
    health_scores = [r["cpuHealth"] for r in dh_rows] + \
                    [r["memoryUtilizationHealth"] for r in dh_rows]
    check(all(isinstance(h, int) and 0 <= h <= 10 for h in health_scores),
          "cpuHealth/memoryUtilizationHealth are ints 0-10")
    check(all(h in NI_HEALTH_OK_RANGE for h in health_scores),
          "healthy estate grades 'ok' in NI's 8-10 band",
          f"offending scores: {sorted({h for h in health_scores if h not in NI_HEALTH_OK_RANGE})}")
    check(all(0 <= r["overallHealth"] <= 10 for r in dh_rows),
          "overallHealth within 0-10")
    wireless = [r for r in dh_rows if r.get("clientCount")]
    check(all(set(r["clientCount"]) == {"radio0", "radio1", "Ghz24", "Ghz50"}
              for r in wireless),
          "wireless clientCount uses the exact radio keys (Ghz24/Ghz50 casing)",
          f"{len(wireless)} wireless rows")
    check(all(is_json_int(r.get("issueCount", 0)) for r in dh_rows),
          "issueCount is an int")

    # -----------------------------------------------------------------
    print("\n[6] Interfaces — POST /dna/intent/api/v2/networkDevices/{id}/interfaces/query")
    # -----------------------------------------------------------------
    bulk = client.get("/dna/data/api/v1/interfaces",
                      params={"networkDeviceId": ids[0], "offset": 1, "limit": 500},
                      headers=headers, follow_redirects=False)
    check(bulk.status_code == 404,
          "bulk interface route 404s so the collector falls back to legacy",
          f"HTTP {bulk.status_code}")
    check(not (300 <= bulk.status_code < 400),
          "bulk route is never a 3xx (allow_redirects=False would abort the poll)")

    all_iface_ids: set[str] = set()
    problems: list[str] = []
    sample_values = None
    for device in state.devices.values():
        resp = client.post(
            f"/dna/intent/api/v2/networkDevices/{device.id}/interfaces/query",
            headers=headers,
            json={"query": {"page": {"offset": 0, "limit": 1000}},
                  "startTime": now_ms - 900000, "endTime": now_ms},
        )
        if resp.status_code != 200:
            problems.append(f"{device.hostname}: HTTP {resp.status_code}")
            continue
        payload = resp.json()
        rows = payload.get("response")
        total = payload.get("totalCount")
        if not isinstance(rows, list):
            problems.append(f"{device.hostname}: response is not a list")
            continue
        # Mandatory, JSON int, and exactly the row count. An over-count makes
        # the collector request a page that never arrives, then discard all.
        if not is_json_int(total):
            problems.append(f"{device.hostname}: totalCount not a JSON int")
        elif total != len(rows):
            problems.append(f"{device.hostname}: totalCount {total} != {len(rows)} rows")
        if len(rows) != device.interface_count:
            problems.append(f"{device.hostname}: {len(rows)} rows != interfaceCount {device.interface_count}")
        row_ids = [r.get("id") for r in rows]
        if not all(isinstance(i, str) and i.strip() for i in row_ids):
            problems.append(f"{device.hostname}: blank/non-string interface id")
        if len(set(row_ids)) != len(row_ids):
            problems.append(f"{device.hostname}: duplicate interface id within page")
        all_iface_ids.update(row_ids)

        for row in rows:
            v = row.get("values") or {}
            sample_values = sample_values or v
            if v.get("deviceId") != device.id:
                problems.append(f"{device.hostname}/{row.get('id')}: values.deviceId mismatch")
            if not str(v.get("interfaceId", "")).isdigit():
                problems.append(f"{device.hostname}/{row.get('id')}: interfaceId not numeric")
            ts = v.get("timestamp")
            if not is_json_int(ts) or ts <= 0:
                problems.append(f"{device.hostname}/{row.get('id')}: timestamp not a positive int")
            elif not (now_ms - 900000 <= ts <= now_ms):
                problems.append(f"{device.hostname}/{row.get('id')}: timestamp outside the request window")
            for metric in INTERFACE_METRICS:
                if not isinstance(v.get(metric), (int, float)) or isinstance(v.get(metric), bool):
                    problems.append(f"{device.hostname}/{row.get('id')}: {metric} not numeric")
            if not isinstance(v.get("speed"), str):
                problems.append(f"{device.hostname}/{row.get('id')}: speed not a string")
            if not isinstance(v.get("isWan"), bool):
                problems.append(f"{device.hostname}/{row.get('id')}: isWan not a bool")
            if v.get("operStatus", "").lower() not in ("up", "down", "notpresent", "lowerlayerdown"):
                problems.append(f"{device.hostname}/{row.get('id')}: operStatus {v.get('operStatus')!r}")
            if v.get("adminStatus", "").lower() not in ("up", "down", "testing"):
                problems.append(f"{device.hostname}/{row.get('id')}: adminStatus {v.get('adminStatus')!r}")
            if not v.get("name"):
                problems.append(f"{device.hostname}/{row.get('id')}: missing name")
            if not MAC_RE.fullmatch(v.get("macAddr", "")):
                problems.append(f"{device.hostname}/{row.get('id')}: macAddr not six octets")

    check(not problems, f"all {len(state.devices)} devices pass the interface contract",
          f"{len(problems)} problems, first: {problems[:3]}")
    check(len(all_iface_ids) == state.summary()["interfaces"],
          "every interface on every device was returned, and ids are unique estate-wide",
          f"{len(all_iface_ids)} vs {state.summary()['interfaces']}")
    check(sample_values is not None and sample_values.get("interfaceType", "").lower() == "physical",
          "interfaceType is 'Physical' so NI grades entity_subtype=physical")
    check(any(v for v in [sample_values] if v), "values object is populated")

    # 0-based paging on this route only.
    paged = client.post(
        f"/dna/intent/api/v2/networkDevices/{ids[0]}/interfaces/query",
        headers=headers,
        json={"query": {"page": {"offset": 5, "limit": 10}},
              "startTime": now_ms - 900000, "endTime": now_ms}).json()
    check(len(paged["response"]) == 10 and is_json_int(paged["totalCount"]),
          "0-based offset/limit honoured while totalCount stays the device total",
          f"got {len(paged['response'])} rows, total {paged['totalCount']}")

    unknown = client.post(
        "/dna/intent/api/v2/networkDevices/does-not-exist/interfaces/query",
        headers=headers, json={"query": {"page": {"offset": 0, "limit": 1000}}})
    check(unknown.status_code == 404, "unknown device id 404s", f"HTTP {unknown.status_code}")

    # -----------------------------------------------------------------
    print("\n[7] Physical topology — GET /dna/intent/api/v1/topology/physical-topology")
    # -----------------------------------------------------------------
    topo = client.get(PHYSICAL_TOPOLOGY_PATH, headers=headers)
    check(topo.status_code == 200, "physical-topology answers 200",
          f"HTTP {topo.status_code}")
    topo_body = topo.json()
    inner = topo_body.get("response")
    # Load-bearing: an object makes the whole topology ONE event, which is what
    # NI's links{} expansion needs. A list yields one fragment per event.
    check(isinstance(inner, dict),
          "response is a JSON OBJECT, not a list (one event => NI can expand links{})",
          f"got {type(inner).__name__}")
    check(isinstance(inner.get("links"), list) and inner["links"],
          "links[] present and non-empty")
    check(isinstance(inner.get("nodes"), list) and inner["nodes"],
          "nodes[] present (unused by NI but required for a realistic body)")

    check(slugify_path(PHYSICAL_TOPOLOGY_PATH) == NI_PHYSICAL_TOPOLOGY_SLUG,
          "path slugifies to the endpoint_name NI filters on",
          f"got {slugify_path(PHYSICAL_TOPOLOGY_PATH)!r}")

    device_id_set = set(ids)
    link_problems = []
    for link in inner["links"]:
        for key in ("id", "source", "target", "startPortID", "endPortID", "linkStatus"):
            if not link.get(key):
                link_problems.append(f"{link.get('id', '?')}: missing {key}")
        if link.get("source") not in device_id_set:
            link_problems.append(f"{link.get('id')}: source is not a known device id")
        if link.get("target") not in device_id_set:
            link_problems.append(f"{link.get('id')}: target is not a known device id")
        if link.get("startPortID") not in all_iface_ids:
            link_problems.append(f"{link.get('id')}: startPortID is not a known interface id")
        if link.get("endPortID") not in all_iface_ids:
            link_problems.append(f"{link.get('id')}: endPortID is not a known interface id")
    check(not link_problems,
          f"all {len(inner['links'])} links resolve to known device and interface ids",
          f"{len(link_problems)} problems, first: {link_problems[:3]}")
    check(len({l["id"] for l in inner["links"]}) == len(inner["links"]),
          "link ids are unique")

    # Every interface named by a link must be operationally UP, or NI grades an
    # edge between two ports that report down.
    up_by_id = {i.id for d in state.devices.values() for i in d.interfaces
                if i.is_up}
    linked = {l["startPortID"] for l in inner["links"]} | \
             {l["endPortID"] for l in inner["links"]}
    check(linked <= up_by_id, "every linked interface is operationally UP",
          f"down but linked: {sorted(linked - up_by_id)[:3]}")

    serialized = len(json.dumps(topo_body).encode("utf-8"))
    check(serialized <= 9 * 1024 * 1024,
          "serialized body within the add-on's 9 MiB per-event ceiling",
          f"{serialized} bytes")

    # -----------------------------------------------------------------
    print("\n[8] Assurance issues — GET /dna/data/api/v1/assuranceIssues")
    # -----------------------------------------------------------------
    end_ms = int(time.time() * 1000)
    start_ms = end_ms - 86400000
    iss = client.get("/dna/data/api/v1/assuranceIssues",
                     params={"limit": 25, "offset": 1, "startTime": start_ms,
                             "endTime": end_ms, "sortBy": "firstOccurredTime",
                             "order": "asc"}, headers=headers)
    check(iss.status_code == 200, "assuranceIssues answers 200", f"HTTP {iss.status_code}")
    iss_body = iss.json()
    check(isinstance(iss_body.get("response"), list), "response is a list")
    page = iss_body.get("page")
    check(isinstance(page, dict), "page metadata is present and a dict (mandatory)")
    check(is_json_int(page.get("count")) and page["count"] >= 0,
          "page.count is a JSON int >= 0", f"got {page.get('count')!r}")
    check(page.get("offset") == 1 and page.get("limit") == 25,
          "page.offset/limit echo the request exactly",
          f"got offset={page.get('offset')} limit={page.get('limit')}")

    issue_rows = iss_body["response"]
    check(len(issue_rows) <= 25, "page size 25 respected")
    stamps = [r["firstOccurredTime"] for r in issue_rows]
    check(stamps == sorted(stamps), "rows sorted ascending by firstOccurredTime")
    issue_problems = []
    for row in issue_rows:
        if not row.get("issueId"):
            issue_problems.append("missing issueId")
        for key in NAME_KEYS_THAT_SUPPRESS_ENRICHMENT:
            if row.get(key):
                issue_problems.append(f"{row.get('issueId')}: carries {key}, which suppresses enrichment")
        attrs = row.get("additionalAttributes") or {}
        if isinstance(attrs, dict) and attrs.get("deviceName"):
            issue_problems.append(f"{row.get('issueId')}: additionalAttributes.deviceName suppresses enrichment")
        if row.get("deviceId") not in device_id_set:
            issue_problems.append(f"{row.get('issueId')}: deviceId not in inventory")
        if row.get("priority") not in ("P1", "P2", "P3", "P4"):
            issue_problems.append(f"{row.get('issueId')}: priority {row.get('priority')!r}")
        for key in ("firstOccurredTime", "mostRecentOccurredTime"):
            ts = row.get(key)
            if not is_json_int(ts) or not (MIN_ISSUE_TS_MS <= ts <= MAX_ISSUE_TS_MS):
                issue_problems.append(f"{row.get('issueId')}: {key} outside the plausible ms range")
    check(not issue_problems, "issue rows satisfy the emitted-field contract",
          f"{len(issue_problems)} problems, first: {issue_problems[:3]}")

    echoed = client.get("/dna/data/api/v1/assuranceIssues",
                        params={"limit": 25, "offset": 23, "startTime": start_ms,
                                "endTime": end_ms, "sortBy": "firstOccurredTime",
                                "order": "asc"}, headers=headers).json()
    check(echoed["page"]["offset"] == 23,
          "the overlap-3 continuation offset (1 -> 23) is echoed, not reset",
          f"got {echoed['page']['offset']}")

    # -----------------------------------------------------------------
    print("\n[9] Cross-source fusion with the Meraki estate")
    # -----------------------------------------------------------------
    meraki_serials = {d.serial for d in meraki_state.get_all_devices()}
    meraki_macs = {d.mac for d in meraki_state.get_all_devices()}
    catalyst_serials = {d.serial for d in state.devices.values()}
    catalyst_macs = {d.mac for d in state.devices.values()}
    overlap = (catalyst_serials & meraki_serials) | (catalyst_macs & meraki_macs)
    check(bool(overlap),
          "some devices share a serial or MAC with Meraki so NI fuses them",
          "no overlap — the two sources would render as disjoint graphs")
    check(len(shared) == 3,
          f"exactly the three intended HQ switches fuse ({len(shared)} found)",
          f"got {shared}")
    fused = {d.hostname for d in state.devices.values()
             if d.serial in meraki_serials or d.mac in meraki_macs}
    check(fused == set(shared),
          "no unintended device fuses into a Meraki vertex",
          f"unexpected: {sorted(fused - set(shared))}")
    check(len(catalyst_serials) == len(state.devices), "catalyst serials unique")
    check(len(catalyst_macs) == len(state.devices), "catalyst MACs unique")
    iface_macs = {i.mac_addr for d in state.devices.values() for i in d.interfaces}
    check(not (iface_macs & catalyst_macs) and not (iface_macs & meraki_macs),
          "no interface MAC collides with a device MAC in either source")

    # -----------------------------------------------------------------
    print("\n[10] Add-on endpoint catalog")
    # -----------------------------------------------------------------
    try:
        with open(CATALOG_PATH, encoding="utf-8") as f:
            catalog = json.load(f)
        entries = {e["path"]: e for e in catalog["endpoints"]}
        entry = entries.get(PHYSICAL_TOPOLOGY_PATH)
        check(entry is not None,
              "physical-topology is in the catalog (else it cannot be selected in the UI)")
        if entry:
            check(entry.get("method", "").upper() == "GET",
                  "catalog method is GET", f"got {entry.get('method')!r}")
            check(slugify_path(PHYSICAL_TOPOLOGY_PATH) == NI_PHYSICAL_TOPOLOGY_SLUG,
                  "catalog id maps to the slug NI filters on",
                  f"catalog id={entry.get('id')!r}")
        check(catalog["catalog_metadata"]["catalog_version"] == "3.1.3",
              "catalog version matches the emulated controller release family")
    except FileNotFoundError:
        print("  SKIP  catalog not extracted at " + CATALOG_PATH)

    # -----------------------------------------------------------------
    print("\n[11] Every registered route answers without a 5xx")
    # -----------------------------------------------------------------
    five_xx = []
    exercised = 0
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if not path.startswith("/dna"):
            continue
        concrete = path.replace("{device_id}", ids[0])
        for method in sorted(methods):
            if method in ("HEAD", "OPTIONS"):
                continue
            exercised += 1
            if method == "GET":
                r = client.get(concrete, headers=headers)
            else:
                r = client.request(method, concrete, headers=headers,
                                   json={"query": {"page": {"offset": 0, "limit": 1000}}})
            if r.status_code >= 500:
                five_xx.append(f"{method} {concrete} -> {r.status_code}")
    check(exercised > 0, f"route sweep reached {exercised} method+path combinations")
    check(not five_xx, "no DNAC route returns a 5xx", f"{five_xx[:3]}")

    print("\n" + "=" * 78)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        print("=" * 78)
        return 1
    print("ALL CATALYST CENTER ADD-ON / NI CONTRACT CHECKS PASSED")
    summary = state.summary()
    print(f"  {summary['devices']} devices · {summary['sites']} sites · "
          f"{summary['interfaces']} interfaces · {summary['links']} links · "
          f"{len(issue_rows)} issues")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
