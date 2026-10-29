"""Verify topology generators match the documented Meraki API schemas."""

import re

from src.topology.loader import load_topology
from src.data import topology as topo

s = load_topology("config/topology.yaml")
print(f"Loaded: {len(s.networks)} networks, {len(s.devices)} devices, "
      f"{len(s.links)} links, {len(s.clients)} clients, {len(s.vpn_peers)} VPN peers\n")

# --- MAC addresses must be valid and unique ---
# Splunk NI parents interface vertices to devices with
# lower(replace(trim(mac),"-",":")), so a malformed or duplicated MAC silently
# breaks the device-to-interface join rather than raising an error.
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
bad_macs = [(d.serial, d.mac) for d in s.get_all_devices()
            if not MAC_RE.fullmatch(d.mac.lower())]
assert not bad_macs, f"malformed MAC addresses: {bad_macs[:5]}"
mac_counts: dict[str, int] = {}
for d in s.get_all_devices():
    mac_counts[d.mac.lower()] = mac_counts.get(d.mac.lower(), 0) + 1
dupes = {m: c for m, c in mac_counts.items() if c > 1}
assert not dupes, f"duplicate MAC addresses: {dupes}"
bad_client_macs = [c.mac for c in s.clients.values() if not MAC_RE.fullmatch(c.mac.lower())]
assert not bad_client_macs, f"malformed client MACs: {bad_client_macs[:5]}"
print(f"[0] MAC addresses: {len(s.devices)} device + {len(s.clients)} client, "
      f"all valid six-octet and unique")

# --- nodes/discovered (feeds Splunk NI graph nodes) ---
n = topo.generate_topology_nodes_discovered(s)
print(f"[1] topology/nodes/discovered: {len(n['items'])} items, {len(n['errors'])} errors")
i = n["items"][0]
assert {"protocol", "reporter", "discovered"} <= set(i), "missing top-level keys"
assert {"id", "interface"} <= set(i["reporter"]), "missing reporter keys"
assert {"id", "status"} <= set(i["reporter"]["interface"]), "missing interface keys"
d = i["discovered"]
assert {"derivedId", "system", "chassis", "port", "mac", "addresses"} <= set(d), "missing discovered keys"
assert {"name", "description", "platform", "capabilities"} <= set(d["system"]), "missing system keys"
print(f"    reporter={i['reporter']['id']} port={i['reporter']['interface']['id']} "
      f"-> discovered={d['system']['name']} ({d['system']['platform']})")
print(f"    derivedId={d['derivedId']} protocol={i['protocol']} caps={d['system']['capabilities']}")

# Guard against silent lookup fallbacks — every device must resolve a real
# Meraki system description, not the generic default.
fallbacks = {x["discovered"]["system"]["name"] for x in n["items"]
             if x["discovered"]["system"]["description"] == "Meraki Cloud Managed Device"}
assert not fallbacks, f"generic fallback description for: {sorted(fallbacks)}"
descriptions = sorted({x["discovered"]["system"]["description"] for x in n["items"]})
print(f"    system descriptions resolved: {len(descriptions)}")
for desc in descriptions:
    print(f"      - {desc}")

# LLDP discovery is bidirectional — every device family that participates in a
# link must be discoverable, including the MX gateway seen from the switch side.
expected = {"Meraki MX Cloud Managed Security Appliance", "Meraki MS Cloud Managed Switch",
            "Meraki MR Cloud Managed Access Point", "Meraki MV Cloud Managed Camera",
            "Meraki MT Cloud Managed Sensor"}
missing = expected - set(descriptions)
assert not missing, f"device families missing from discovered nodes: {missing}"

# Bidirectionality: for every A->B discovery there must be a matching B->A.
# reporter.id is a serial but discovered has no serial, so map MAC -> serial.
mac_to_serial = {d.mac: d.serial for d in s.get_all_devices()}
pairs = {(x["reporter"]["id"], mac_to_serial[x["discovered"]["mac"]]) for x in n["items"]}
reverse_missing = [(a, b) for (a, b) in pairs if (b, a) not in pairs]
assert not reverse_missing, f"discovery not bidirectional for: {reverse_missing[:5]}"
print(f"    bidirectional discovery verified across {len(pairs)} report pairs")

# --- l2/links (feeds Splunk NI graph edges) ---
l = topo.generate_topology_l2_links(s)
print(f"\n[2] topology/l2/links: {len(l['items'])} links")
lk = l["items"][0]
assert {"linkId", "isStpDisabled", "site", "source", "target"} <= set(lk), "missing link keys"
assert lk["site"]["resource"]["type"] in ("network", "site"), "bad resource type"
assert "id" in lk["source"]["device"]["port"], "missing source port"
assert "id" in lk["target"]["device"]["port"], "missing target port"
print(f"    {lk['source']['device']['id']}[{lk['source']['device']['port']['id']}] <-> "
      f"{lk['target']['device']['id']}[{lk['target']['device']['port']['id']}]")
print(f"    linkId={lk['linkId']} stpDisabled={lk['isStpDisabled']} site={lk['site']['resource']['id']}")

# --- linkLayer per network ---
hq = s.get_network("L_646829496405521104")
ll = topo.generate_link_layer_topology(s, hq.id)
print(f"\n[3] networks/{hq.id}/topology/linkLayer: {len(ll['nodes'])} nodes, {len(ll['links'])} links")
assert {"nodes", "links", "errors"} <= set(ll), "missing linkLayer keys"
nd = ll["nodes"][0]
assert {"derivedId", "mac", "type", "root"} <= set(nd), "missing node keys"
assert nd["type"] in ("device", "discovered", "stack", "unknown"), "bad node type"
dev = nd["device"]
assert {"serial", "name", "model", "productType", "status", "lastReportedAt",
        "clients", "uplinks"} <= set(dev), "missing device keys"
assert "total" in dev["clients"]["counts"], "missing client count"
roots = [x for x in ll["nodes"] if x["root"]]
assert len(roots) == 1, f"expected exactly 1 root, got {len(roots)}"
print(f"    root={roots[0]['device']['name']} type={roots[0]['device']['productType']}")
ends = ll["links"][0]["ends"]
assert len(ends) == 2, "link must have 2 ends"
assert "lldp" in ends[0]["discovered"] and "cdp" in ends[0]["discovered"], "missing discovery blocks"
print(f"    link: {ends[0]['device']['name']}[{ends[0]['discovered']['lldp']['portId']}] <-> "
      f"{ends[1]['device']['name']}[{ends[1]['discovered']['lldp']['portId']}]")

# --- lldpCdp per device ---
lc = topo.generate_device_lldp_cdp(s, "Q2QN-HQ01-MS01")
print(f"\n[4] devices/Q2QN-HQ01-MS01/lldpCdp: {len(lc['ports'])} ports with neighbors")
assert "sourceMac" in lc and "ports" in lc, "missing lldpCdp keys"
p, v = next(iter(lc["ports"].items()))
assert {"systemName", "systemDescription", "portId", "chassisId", "managementVlan",
        "portVlan", "managementAddress", "portDescription", "systemCapabilities",
        "sourcePort"} <= set(v["lldp"]), "missing lldp keys"
assert {"platform", "deviceId", "model", "version", "portId", "nativeVlan",
        "vtpManagementDomain", "capabilities", "address", "sourcePort"} <= set(v["cdp"]), "missing cdp keys"
print(f"    port {p}: LLDP {v['lldp']['systemName']} / CDP {v['cdp']['platform']} "
      f"nativeVlan={v['cdp']['nativeVlan']}")

# --- switch port statuses reflect real cabling ---
ps = topo.generate_switch_port_statuses(s, "Q2QN-HQ01-MS01")
conn = [x for x in ps if x["status"] == "Connected"]
print(f"\n[5] switch port statuses Core-SW01: {len(ps)} ports, {len(conn)} connected")
assert len(conn) > 0, "no connected ports — links not applied"
for x in conn[:4]:
    print(f"    port {x['portId']:>3}: vlan {x['vlan']:>3} uplink={x['isUplink']} "
          f"-> {x['connectedDeviceSerial']}")

# --- VLANs carry business function ---
vl = topo.generate_vlans(s, hq.id)
print(f"\n[6] VLANs at HQ ({len(vl)}):")
for x in vl:
    print(f"    {x['id']:>3} {x['name']:<20} {x['subnet']:<18} {x['description']}")

# --- SSIDs carry business function ---
ss = topo.generate_ssids(s, hq.id)
print(f"\n[7] SSIDs at HQ ({len(ss)}):")
for x in ss:
    print(f"    {x['number']} {x['name']:<20} vlan={x['vlanId']:<3} auth={x['authMode']:<18} visible={x['visible']}")

# --- business tags present on devices ---
print("\n[8] Business context sampling:")
for serial in ("Q2QN-HQ01-MX01", "Q2QN-S042-MV02", "Q2QN-DC01-MT01", "Q2QN-S0203-MS01"):
    d = s.get_device(serial)
    if not d:
        continue
    print(f"    {d.name}")
    print(f"      notes: {d.notes}")
    print(f"      tags:  {', '.join(d.tags)}")
    print(f"      addr:  {d.address}")

# --- client business functions ---
print("\n[9] Clients by business type:")
by_type = {}
for c in s.clients.values():
    by_type.setdefault(c.client_type, []).append(c)
for t, cs in sorted(by_type.items()):
    print(f"    {t:<12} {len(cs):>2}  e.g. {cs[0].hostname} — {cs[0].business_function}")

# --- site criticality summary ---
print("\n[10] Site summary:")
summ = s.business_summary()
for site, info in summ["sites"].items():
    print(f"    {site:<18} {info['site_type']:<18} {info['criticality']:<7} "
          f"hc={info['headcount']:>3} dev={info['device_count']:>2} pci={info['pci_devices']:>2}")

print("\nAll schema assertions passed.")

# --- Scenario config must reference real devices and networks ---
import yaml

with open("config/scenarios.yaml", encoding="utf-8") as f:
    scenarios = yaml.safe_load(f)["scenarios"]

device_serials = set(s.devices.keys())
network_ids = set(s.networks.keys())
errors = []

print(f"\n[11] Validating {len(scenarios)} scenarios against topology:")
for sc in scenarios:
    for action in sc.get("actions", []):
        for field in ("device",):
            serial = action.get(field)
            if serial and serial not in device_serials:
                errors.append(f"{sc['name']}: unknown device {serial}")
        for dev in action.get("devices", []) or []:
            if dev not in device_serials:
                errors.append(f"{sc['name']}: unknown device {dev}")
        tunnel = action.get("tunnel") or {}
        for end in (tunnel.get("from"), tunnel.get("to")):
            if end and end not in device_serials:
                errors.append(f"{sc['name']}: unknown tunnel endpoint {end}")
        net = action.get("networkId")
        if net and net not in network_ids:
            errors.append(f"{sc['name']}: unknown networkId {net}")

    # Every event-producing action must attribute to a specific device,
    # otherwise Splunk NI cannot walk event -> device -> topology.
    for action in sc.get("actions", []):
        if action.get("type") == "generate_event" and not action.get("device"):
            errors.append(f"{sc['name']}: generate_event has no explicit device")

if errors:
    print("    FAILURES:")
    for e in errors:
        print(f"      - {e}")
    raise SystemExit(1)

print(f"    all {len(scenarios)} scenarios reference valid devices/networks")
print(f"    every generate_event is attributed to a specific device")
for sc in scenarios:
    print(f"      {sc['name']:<38} {sc['trigger']:<10} {sc.get('business_impact','')[:52]}")

print("\nAll validations passed.")
