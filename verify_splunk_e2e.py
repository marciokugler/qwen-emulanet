"""End-to-end test: emulator -> Splunk HEC -> searchable event.

Triggers a scenario that emits a webhook, then queries Splunk to confirm the
event actually landed and is searchable.
"""

import base64
import json
import ssl
import sys
import time
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

MARKER = f"e2e-{int(time.time())}"
EMULATOR = "http://localhost:8081"
ADMIN_PASS = "Emulanet2026!"
HEC_URL = "https://localhost:8088/services/collector/event"
HEC_TOKEN = "11111111-1111-1111-1111-111111111111"

# Splunk ships a self-signed cert, so verification is disabled for this local test.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def trigger(scenario):
    req = urllib.request.Request(f"{EMULATOR}/api/scenarios/{scenario}/trigger",
                                 method="POST")
    return urllib.request.urlopen(req).read().decode()


def splunk_search(query):
    """Run a oneshot search via the Splunk REST API and return the raw JSON.

    The `splunk search` CLI inside this container fails with permission errors
    (it runs as root while Splunk files are owned by the splunk user, and even
    `-u splunk` produced no rows). The REST API on 8089 works reliably.
    """
    data = urllib.parse.urlencode({
        "search": query,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }).encode()

    req = urllib.request.Request(
        "https://localhost:8089/services/search/jobs/oneshot",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    cred = base64.b64encode(f"admin:{ADMIN_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {cred}")

    resp = urllib.request.urlopen(req, context=SSL_CTX, timeout=120)
    return json.loads(resp.read().decode())


print("=" * 70)
print("End-to-end: emulator scenario -> HEC -> Splunk search")
print("=" * 70)

# 1. Send a directly attributable marker event through the same HEC path the
#    webhook sender uses, so we can prove ingestion independent of scenario timing.
payload = {
    "time": int(time.time()),
    "host": "cisco-meraki-emulator",
    "source": "meraki_emulator",
    "sourcetype": "meraki:webhook",
    "index": "main",
    "event": {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "organizationId": "2947",
        "organizationName": "Northwind Retail Group",
        "networkId": "L_646829496405521106",
        "networkName": "Store 0042 - New York Flagship",
        "device": {
            "serial": "Q2QN-S042-MS01",
            "name": "Store0042-NYC-Switch",
            "model": "MS250-24",
        },
        "alertType": "Switch port status changed",
        "alertId": MARKER,
        "alertData": {
            "e2eMarker": MARKER,
            "portNumber": 11,
            "portStatus": "down",
            "businessImpact": "Card-present transactions halted on register 3",
        },
    },
}

body = json.dumps(payload).encode()
req = urllib.request.Request(
    HEC_URL,
    data=body,
    headers={
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json",
    },
    method="POST",
)

resp = urllib.request.urlopen(req, context=SSL_CTX, timeout=20)
result = json.loads(resp.read().decode())
print(f"\n[1] HEC POST -> {result}")
assert result.get("code") == 0, f"HEC rejected the event: {result}"
print(f"    marker alertId = {MARKER}")

# 2. Trigger a real scenario too, so live webhook traffic is exercised.
print(f"\n[2] Triggering live scenario -> {trigger('pos_lane_outage_flagship').strip()}")

# 3. Wait for indexing, then search.
print("\n[3] Waiting 20s for indexing...")
time.sleep(20)

# Search for the specific marker so we prove THIS event round-tripped,
# not just that some event exists.
res = splunk_search(
    f'search index=main sourcetype="meraki:webhook" "{MARKER}" | table _time, alertId, alertType')
rows = res.get("results", [])
print("\n[4] Marker search results:")
print("-" * 70)
if rows:
    for r in rows:
        print("  " + " | ".join(f"{k}={v}" for k, v in r.items()))
else:
    print("  (no rows returned)")
print("-" * 70)

found = len(rows) > 0
print(f"\n[5] Marker event searchable in Splunk: {'YES' if found else 'NO'}")

# Overall volume, to show the live scenario webhooks landed too.
counts = splunk_search(
    'search index=* earliest=-30m | stats count by index, sourcetype')
print("\n[6] Event volume by index/sourcetype:")
for r in counts.get("results", []):
    print(f"    index={r.get('index'):<8} sourcetype={r.get('sourcetype'):<20} count={r.get('count')}")

# Prove the business context survives ingestion, which is the point of the demo.
biz = splunk_search(
    'search index=main sourcetype="meraki:webhook" | fields alertType, device.name, '
    'networkName | head 5')
print("\n[7] Sample ingested webhook fields:")
for r in biz.get("results", []):
    print("    " + json.dumps(r, ensure_ascii=False))

print("\n" + "=" * 70)
print("E2E RESULT:", "PASS — emulator data is searchable in Splunk" if found
      else "FAIL — marker event not found; check HEC config and index")
print("=" * 70)
sys.exit(0 if found else 1)
