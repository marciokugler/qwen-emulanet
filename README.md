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

- **Meraki API mock** → http://localhost:5000
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

Both are free but require a Splunk.com login, so install them from the Splunk
UI (**Apps → Find More Apps**) or download from Splunkbase:

1. **Splunk Network Intelligence** — [splunkbase app 9913](https://splunkbase.splunk.com/app/9913)
2. **Cisco Meraki Add-on for Splunk** — the collector NI depends on

### Point the Meraki Add-on at the emulator

The emulator runs on the **host**, not inside Splunk's container, so
`localhost` will not resolve to it. Use `host.docker.internal`:

| Setting | Value |
|---|---|
| Base URL | `http://host.docker.internal:5000/api/v1` |
| API Key | `6789123456789012345678901234567890123456` |
| Organization ID | `2947` |
| Service Region | Global |

Enable the topology inputs (`devices_topology_nodes_discovered`,
`devices_topology_l2_links`, `switch_ports_statuses_by_switch`) or Network
Intelligence will have no graph to draw.

To also send webhook alerts via HEC, set in `config/settings.yaml`:

```yaml
splunk_hec:
  enabled: true
  url: "http://localhost:8088/services/collector"
  token: "11111111-1111-1111-1111-111111111111"
  index: "main"
```

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

Three scripts assert behaviour rather than just printing it:

```bash
python verify_topology.py     # schema + business context + scenario references
python verify_scenarios.py    # live scenario propagation (needs run.py up)
python verify_splunk_e2e.py   # live emulator -> HEC -> Splunk search (needs both up)
```

**`verify_topology.py`** checks response shapes against the documented Meraki
schemas, asserts all five device families appear as discovered nodes, that LLDP
discovery is **bidirectional**, that uncabled ports do not report `Connected`,
that no device silently falls back to a generic system description, and that
every scenario references a real device and network.

**`verify_scenarios.py`** triggers a live scenario and asserts the port flap
reaches the L2 link state, the Meraki port status, event attribution, network
scoping, and removal from `nodes/discovered`.

**`verify_splunk_e2e.py`** posts a uniquely-marked webhook through HEC, triggers
a live scenario, then queries Splunk over REST to confirm the event is
searchable and that business context survives ingestion. It uses the REST API
rather than `splunk search` — the CLI fails with permission errors in this
container (it runs as root while Splunk files are owned by `splunk`).

## Project layout

```
config/
  topology.yaml          # Sites, devices, L2 cabling, VLANs, SSIDs, clients
  scenarios.yaml         # 15 retail scenarios with business impact
  settings.yaml          # Ports, API key, HEC target (gitignored)
  settings.example.yaml  # Template
src/
  topology/models.py     # Device, Link, Vlan, Ssid, Client, TopologyState
  topology/loader.py     # YAML -> state, expands the store template
  api/server.py          # Meraki Dashboard API mock (80+ endpoints)
  data/topology.py       # The Splunk NI topology endpoints + LLDP/CDP
  data/generators.py     # Inventory, health, VPN, client, security responses
  data/scenarios.py      # Async scenario engine (scheduled + probabilistic)
  webhooks/generator.py  # Meraki webhook alert payloads
  webhooks/sender.py     # Splunk HEC delivery
web/index.html           # Dashboard — topology, sites, events, scenarios
splunk/docker-compose.yml
verify_topology.py
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
