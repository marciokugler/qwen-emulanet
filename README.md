# Cisco Network Emulator for Splunk Network Intelligence

A Cisco Meraki emulator that generates realistic, business-contextual network
data for **Splunk Network Intelligence** demos — without needing real Cisco
hardware.

It mocks the Meraki Dashboard API, so the genuine **Cisco Meraki Add-on for
Splunk** polls it exactly as it would poll `api.meraki.com`. Splunk Network
Intelligence then builds inventory, health, alerts, and its topology graph from
that ingested data.

## Why this exists

Splunk Network Intelligence **collects nothing itself**. Per Splunk's docs it
"reads events that supported Splunk apps, add-ons, and external collectors send
to Splunk indexes, then normalizes that data for inventory, health, alerts, and
topology."

Its topology graph is built from two specific Meraki endpoints:

| Add-on input | Meraki endpoint | Feeds |
|---|---|---|
| `meraki:custom` | `devices/topology/nodes/discovered` | Graph **nodes** (LLDP/CDP neighbours) |
| `meraki:custom` | `devices/topology/l2/links` | Graph **edges** (L2 adjacency) |
| `switch_ports_statuses_by_switch` | `switch/ports/statuses/bySwitch` | Port state |
| `meraki:devices`, `meraki:organizationsnetworks` | `devices`, `networks` | Inventory |

If those endpoints return nothing, Network Intelligence renders an **empty
graph** — which is the core feature of the product being demoed. This emulator
implements all of them against schemas taken from `developer.cisco.com/meraki`.

## Quick start

```bash
pip install -r requirements.txt
cp config/settings.example.yaml config/settings.yaml
python run.py
```

- **Meraki API mock** → https://localhost:5000 (self-signed TLS, see below)
- **Dashboard** → http://localhost:8081
- **API key** → `6789123456789012345678901234567890123456`

> The dashboard defaults to **8081**, not 8080. On Windows `wslrelay.exe`
> frequently forwards a WSL-hosted app to `127.0.0.1:8080`; that binding is
> more specific than our `0.0.0.0:8080`, so localhost requests silently reach
> the other app and the bind raises no error. On startup the emulator now
> self-checks both ports and logs a warning if something else is answering.

## Splunk test instance

A docker-compose file provides a local Splunk Enterprise:

```bash
cd splunk
docker compose up -d          # ~2-4 min for first-time init
docker compose logs -f splunk
```

| | |
|---|---|
| Web UI | http://localhost:8000 |
| User | `admin` |
| Password | `Emulanet2026!` (override with `SPLUNK_PASSWORD`) |
| HEC token | `11111111-1111-1111-1111-111111111111` |

Volumes are persistent, so apps installed from Splunkbase survive restarts.

> Starting Splunk this way accepts the [Splunk General
> Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html) and the
> EULA on your behalf. Current `splunk/splunk` images require **both**
> `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` and
> `SPLUNK_START_ARGS=--accept-license`; missing the first crash-loops the
> container with "License not accepted".

### Install the Splunk apps

Both are free but need a Splunk.com login. Install from the Splunk UI
(**Apps → Find More Apps**) or drop the tarballs into `/opt/splunk/etc/apps`:

1. **Splunk Network Intelligence** — [splunkbase app 9913](https://splunkbase.splunk.com/app/9913) (app id `network_intelligence`)
2. **Cisco Meraki Add-on for Splunk** (app id `Splunk_TA_cisco_meraki`)

> The **Cisco Enterprise Networking Add-on** (`TA_cisco_catalyst`) is *not* what
> this emulator feeds. Its own manifest says it "collects data from Cisco
> Catalyst Center, Cisco SD-WAN, Cisco Identity Services Engine, and Cisco
> Cyber Vision" — it contains no Meraki code and no place to enter a Meraki API
> key. Cisco runs Meraki and Catalyst as separate product lines with separate
> management APIs, so NI treats them as separate sources (`meraki`,
> `catalyst_center`, `thousandeyes`).

### TLS — the emulator serves HTTPS, like the real Dashboard API

The add-on's account form rejects any Base URL not starting with `https://`,
because `api.meraki.com` is HTTPS-only. `run.py` therefore serves the API over
TLS whenever `config/tls/server.crt` and `config/tls/server.key` exist (paths
overridable with `server.tls_cert` / `server.tls_key` in `config/settings.yaml`);
without them it falls back to plain HTTP.

The certificate is self-signed for `host.docker.internal`, `localhost` and
`127.0.0.1`, valid ten years. Splunk's bundled Python ships `cryptography`
while the host Python does not, so it is minted inside the container:

```bash
docker cp tools/mint_tls_cert.py emulanet-splunk:/tmp/mint_tls_cert.py
docker exec -e LD_LIBRARY_PATH=/opt/splunk/lib -e CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1 ^
    emulanet-splunk /opt/splunk/bin/python3 /tmp/mint_tls_cert.py
docker cp emulanet-splunk:/tmp/emulanet.crt config/tls/server.crt
docker cp emulanet-splunk:/tmp/emulanet.key config/tls/server.key
```

Then teach the container to trust it. The add-on's httpx verifies against the
**certifi bundle vendored inside the app**, not the system store, so that is
the file to extend:

```bash
docker cp config/tls/server.crt emulanet-splunk:/opt/splunk/etc/auth/emulanet.crt
docker exec -u root emulanet-splunk sh -c "chown splunk:splunk /opt/splunk/etc/auth/emulanet.crt && chmod 644 /opt/splunk/etc/auth/emulanet.crt"
docker exec -u root emulanet-splunk sh -c "B=/opt/splunk/etc/apps/Splunk_TA_cisco_meraki/lib/certifi/cacert.pem; grep -q emulanet-emulator-ca $B || { printf '\n# emulanet-emulator-ca\n' >> $B; cat /opt/splunk/etc/auth/emulanet.crt >> $B; chown splunk:splunk $B; }"
```

Both steps survive `docker compose stop` / `start`. Recreating the container
(`down`, or `up -d --force-recreate`) restores the image layer and the trust
append must be repeated.

### Configure the Meraki Add-on

The emulator runs on the **host**, not inside Splunk's container, so
`localhost` resolves to the container itself. Use `host.docker.internal`:

| Setting | Value |
|---|---|
| Base URL | `https://host.docker.internal:5000` |
| API Key | `6789123456789012345678901234567890123456` |
| Organization ID | `2947` |
| Service Region | `Other` (this is what unlocks the Base URL field) |
| Index | `main` |

> **No `/api/v1` suffix.** The add-on appends it itself
> (`cisco_meraki_utils.py`: `base_url += "/api/v1"`), so typing it in the form
> makes every call hit `/api/v1/api/v1/...` and fail with "Could not connect to
> Meraki". The form also validates Base URL against `^https://`, because the
> real Dashboard API is HTTPS-only — hence the emulator serves TLS.

Creating the organization account also creates the **dedicated inputs**
(`devices`, `devices/availabilities`, `switch/ports/bySwitch`,
`devices/uplinks/addresses/byDevice`, `devices/uplinksLossAndLatency`, …).

#### Topology inputs need the Custom API picker

`devices/topology/nodes/discovered` and `devices/topology/l2/links` are **not**
in the add-on's bundled SDK catalog, so they will not appear by default. The
add-on is catalog-constrained — it refuses arbitrary URLs — but it discovers
extra endpoints from the organization's OpenAPI document, which this emulator
serves at `/organizations/{orgId}/openapiSpec`.

To select them:

1. **Configuration → Inputs → Custom API (Generic Endpoint)**
2. Choose the organization account (the picker stays disabled until you do)
3. Tick **Include newly discovered** — the two topology endpoints appear there
4. If they don't show, click **Refresh now** (the catalog is cached 24h)
5. Set query parameters to `{"perPage": 1000}`
6. Interval `3600` (the minimum allowed), index `main`

`perPage` matters more than it looks. The collector only unwraps a
`{"items": [...]}` envelope when the endpoint is flagged `paginated`, and that
flag is set by the presence of `perPage`. Without it the whole envelope lands as
a single event and NI finds no `source.device.id` / `target.device.id` at the
top level — an empty graph with no error anywhere.

On save the add-on issues one real request and rejects a deterministic
400/403/404, so every endpoint must answer 200 to a bare GET.
`verify_addon_live.py` checks exactly that.

### Enable the Meraki source in Network Intelligence

NI ships with all three sources disabled. In **Network Intelligence →
Configuration**, enable `meraki` and set the index (`main`) plus a collection
interval. NI reads events the add-on already wrote; it does not poll Meraki
itself.

### Optional: webhook alerts via HEC

Left **disabled** by default so that anything appearing in Splunk provably came
from the add-on polling this API. To also exercise Meraki's webhook alerting,
set in `config/settings.yaml`:

```yaml
splunk_hec:
  enabled: true
  url: "https://localhost:8088/services/collector"   # https — see below
  token: "11111111-1111-1111-1111-111111111111"
  index: "main"
  verify_ssl: false
```

> Splunk sets `enableSplunkHTTPSSL=true` by default, so HEC is **HTTPS only**.
> Plain `http://` to 8088 fails with `connection reset by peer`, which reads
> like a firewall problem rather than a scheme mismatch.

## The demo topology: Northwind Retail Group

Modelled on Cisco's published retail customer patterns, and structured per
Cisco Meraki best practice: **one organization, one network per physical
location** (splitting networks by device type is only recommended for small
deployments).

**8 sites · 75 devices · 70 L2 links · 46 clients · 648 staff**

| Site | Type | Criticality | Staff | Devices | PCI scope |
|---|---|---|---|---|---|
| HQ – Seattle | corporate | tier-1 | 240 | 15 | 5 |
| DC – Reno | distribution | tier-1 | 180 | 12 | 0 |
| Store 0042 – NYC | retail-flagship | tier-2 | 65 | 8 | 3 |
| Store 0117 – LA | mall-anchor | tier-2 | 42 | 8 | 3 |
| Store 0203 – Chicago | urban-street | tier-2 | 38 | 8 | 3 |
| Store 0288 – Dallas | standard | tier-3 | 28 | 8 | 3 |
| Store 0351 – Boston | standard | tier-3 | 31 | 8 | 3 |
| Store 0429 – Denver | standard | tier-3 | 24 | 8 | 3 |

HQ runs an MX450 HA pair as the SD-WAN hub; the DC and all six stores are
spokes. Stores share one structural template (gateway → switch → 2 APs → 3
cameras → sensor) so the demo shows a **repeatable site pattern**, which is how
retail chains actually deploy.

### Business context — no invented fields

Business meaning is carried **only** through fields the real Meraki API
exposes, following Meraki's documented tagging convention (lowercase,
hyphenated, no spaces or commas, geographic + functional dimensions):

- **VLAN names** — `Corporate`, `VoIP`, `POS-PCI`, `Inventory`, `Guest-WiFi`, `Security-Cameras`, `Building-IoT`, `Management`
- **SSID names** — `Northwind-Corp` (802.1X), `Northwind-Guest` (captive portal), `Northwind-VoIP`, `Northwind-Scanning`
- **Device notes** — e.g. *"Register transaction monitoring. Retention 90 days for PCI DSS audit."*
- **Tags** — `pci-scope`, `loss-prevention`, `cold-chain`, `sdwan-hub`, `store-0042`, `metro-nyc`, `tier-1-critical`
- **Address** — physical/rack location
- **Client notes** — e.g. *"POS — card-present transactions, PCI DSS scope"*

## Scenarios

15 retail scenarios, each with an explicit `business_impact`, ordered by what
Cisco's growth story actually emphasises — revenue first, then loss prevention,
security, and growth:

| Category | Scenarios |
|---|---|
| **Revenue impact** | POS lane outage at flagship, store WAN degradation, HQ firewall HA failover, sales-floor AP offline |
| **Loss prevention / cold chain** | POS camera offline (PCI audit gap), cold-storage temperature excursion, HQ server room environmental |
| **Security** | PCI segment intrusion attempt, SSH brute force on store gateway, rogue device on POS VLAN |
| **Operations / growth** | Warehouse scanner roaming failure, weekend guest WiFi saturation, Dallas VPN tunnel down, fleet firmware window, new-store zero-touch onboarding |

Scenario effects **propagate consistently**: a port flap flips the switch port
status, the L2 link state, and drops the adjacency from `nodes/discovered` — so
the topology graph, port tables, and discovery data all agree. Events are
attributed to the specific device that generated them, because Network
Intelligence's value is walking **event → device → topology**.

## Verification

Four scripts assert behaviour rather than just printing it:

```bash
python verify_topology.py         # offline: schemas, business context, scenario refs
python verify_addon_contract.py   # offline: add-on discovery policy + NI field contract
python verify_addon_live.py       # live: every endpoint called from inside the container
python verify_scenarios.py        # live: scenario propagation + NI fault grading
```

The last two need `run.py` and the Splunk container running.

**`verify_topology.py`** — response shapes against the documented Meraki schemas;
all five device families discoverable; LLDP discovery bidirectional; uncabled
ports not reporting `Connected`; no silent fallback descriptions; MACs valid
six-octet and unique; every scenario references a real device and network.

**`verify_addon_contract.py`** — mirrors the add-on's discovery policy from
`cisco_meraki_catalog_refresh.py` and asserts our OpenAPI document passes it,
that `_endpoint_name()` derives the exact strings NI matches on, that `perPage`
is declared so `paginated` resolves true, that every NI-consumed route is
registered at the documented path, and that each payload matches the field
expressions in NI's `props.conf` / `capability_bindings.conf`. It finishes by
exercising **all 110 GET routes**, which is what caught two handlers that had
been returning HTTP 500 since they were written.

**`verify_addon_live.py`** — issues every request the add-on will make, from
inside the Splunk container over `host.docker.internal`, asserting 200s and
documented shapes. Also checks the save-time probe (bare GET must not 404) and
that an invalid API key is rejected with 401.

**`verify_scenarios.py`** — triggers live scenarios and asserts the fault
propagates to the L2 link state, the Meraki port enum, LLDP discovery, and event
attribution — then reproduces NI's `state_expr` to confirm the fault is actually
graded `critical` rather than `ok`.

### Why the grading checks exist

NI grades an interface like this:

```
critical  if enabled AND status=="disconnected" AND isUplink
critical  if actionable_error_count > 0
degraded  if warning_count > 0
ok        otherwise, when status is non-empty
```

and it **excludes** the literal strings `"port disconnected"` and
`"port disabled"` from the actionable-error count. The consequence is
counter-intuitive: a down *access* port reads as healthy, because an unplugged
access port is normal. Scenarios must therefore either target an uplink or
inject a genuine error string. Both paths are covered and asserted.

## Project layout

```
config/
  topology.yaml          # Sites, devices, L2 cabling, VLANs, SSIDs, clients
  scenarios.yaml         # Retail scenarios with business impact
  settings.yaml          # Ports, API key, HEC target (gitignored)
  settings.example.yaml  # Template
src/
  topology/models.py     # Device, Link, Vlan, Ssid, Client, TopologyState
  topology/loader.py     # YAML -> state, expands the store template
  api/server.py          # Meraki Dashboard API mock (110 GET routes)
  data/topology.py       # Topology, port, uplink and OpenAPI responses
  data/generators.py     # Inventory, health, VPN, client, security responses
  data/scenarios.py      # Async scenario engine (scheduled + probabilistic)
  webhooks/generator.py  # Meraki webhook alert payloads
  webhooks/sender.py     # Splunk HEC delivery
web/index.html           # Dashboard — topology, sites, events, scenarios
splunk/docker-compose.yml
verify_topology.py
verify_addon_contract.py
verify_addon_live.py
verify_scenarios.py
verify_splunk_e2e.py     # Live emulator -> HEC -> Splunk search
build_preview.py         # Snapshots live data into a static HTML preview
```

## Data source support

- [x] **Cisco Meraki Add-on for Splunk** — API polling + webhooks
- [ ] **Cisco Enterprise Networking Add-on** — Catalyst Center / SD-WAN Manager (`topology_physical_topology`, `site:topology`, `devicehealth`, `issue`)
- [ ] **Cisco ThousandEyes App for Splunk** — path visualization, synthetic tests

## Notes

- The API mock is a **demo tool**, not a Meraki-compatible production service.
  Response shapes follow the documented schemas, but coverage is partial and
  some values are synthetic.
- Telemetry is generated in-process; nothing is persisted across restarts.
