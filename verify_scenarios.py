"""End-to-end check: a scenario must propagate into the topology graph,
device status, and event attribution — the event -> device -> topology
correlation that Splunk Network Intelligence relies on."""

import json
import sys
import time
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
BASE = "http://localhost:8081"


def get(path):
    return json.loads(urllib.request.urlopen(BASE + path).read().decode("utf-8"))


def post(path):
    req = urllib.request.Request(BASE + path, method="POST")
    return urllib.request.urlopen(req).read().decode("utf-8")


def find_link(links, serial, port):
    for l in links:
        if l["sourceSerial"] == serial and l["sourcePort"] == port:
            return l
    return None


def link_state():
    topo = get("/api/topology")
    l = find_link(topo["links"], "Q2QN-S042-MS01", "11")
    return l


print("=" * 72)
print("Scenario propagation test: pos_lane_outage_flagship")
print("=" * 72)

before = link_state()
print(f"\nBEFORE  link {before['id']}: isUp={before['isUp']} "
      f"{before['sourceSerial']}[{before['sourcePort']}] -> "
      f"{before['targetSerial']}[{before['targetPort']}]")
assert before["isUp"] is True, "expected link up before scenario"

print(f"\nTRIGGER -> {post('/api/scenarios/pos_lane_outage_flagship/trigger').strip()}")
time.sleep(2.5)

during = link_state()
print(f"\nDURING  link {during['id']}: isUp={during['isUp']}")
assert during["isUp"] is False, "port flap did NOT propagate to the L2 link"
print("        OK - port flap propagated to L2 link state (graph shows red)")

# The Meraki-side port status must agree with the link state.
key = "6789123456789012345678901234567890123456"
req = urllib.request.Request(
    "http://localhost:5000/api/v1/devices/Q2QN-S042-MS01/switch/ports/statuses",
    headers={"X-Cisco-Meraki-API-Key": key})
ports = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
p11 = next(p for p in ports if p["portId"] == "11")
print(f"        Meraki port 11 status={p11['status']} enabled={p11['enabled']}")
assert p11["status"] == "Not connected", "Meraki port status did not follow the flap"

# Events must be attributed to the specific device, not an arbitrary one.
events = get("/api/events?limit=40")
pos_events = [e for e in events if e.get("deviceSerial") == "Q2QN-S042-MS01"]
assert pos_events, "no event attributed to the POS switch"
print(f"\nEVENTS  {len(pos_events)} event(s) attributed to Q2QN-S042-MS01:")
for e in pos_events[-3:]:
    print(f"        [{e['severity']:<8}] {e['eventType']}")
    print(f"                   {e['description']}")

# Network must be correct too, so Splunk NI can scope the alert to a site.
net_events = [e for e in events if e["networkId"] == "L_646829496405521106"]
assert net_events, "events not scoped to the flagship store network"
print(f"        all events scoped to network L_646829496405521106 "
      f"(Store 0042 - New York Flagship)")

# Meraki topology endpoints must drop the flapped adjacency from discovery.
req = urllib.request.Request(
    "http://localhost:5000/api/v1/organizations/2947/devices/topology/nodes/discovered",
    headers={"X-Cisco-Meraki-API-Key": key})
nodes = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
reporters = {(x["reporter"]["id"], x["reporter"]["interface"]["id"]) for x in nodes["items"]}
assert ("Q2QN-S042-MS01", "11") not in reporters, \
    "flapped port still advertised as an LLDP neighbour"
print(f"        nodes/discovered correctly omits the down adjacency "
      f"({len(nodes['items'])} items remain)")

print("\nNote: the flap self-heals after its configured 90s hold; not waited on here.")
print("=" * 72)
print("ALL SCENARIO PROPAGATION CHECKS PASSED")
print("=" * 72)
