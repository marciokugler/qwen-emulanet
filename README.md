# Emulanet — Meraki Dashboard API emulator for Splunk Network Intelligence demos

Emulanet emulates the Cisco Meraki Dashboard API so that the genuine Cisco
Meraki Add-on for Splunk can poll it exactly as it polls the production API,
and Splunk Network Intelligence can build inventory, health, alerts and its
topology graph from the ingested data — with no Cisco hardware and no Meraki
account.

It generates a fictional retail company's network (8 sites, 75 devices, 70
cabled links) with realistic telemetry, then plays retail-flavoured incidents
through the same API surfaces a real deployment would expose: a POS lane
outage, a cold-chain temperature excursion, a PCI-segment intrusion attempt,
a zero-touch store onboarding.

## Quick start

```bash
pip install -r requirements.txt
cp config/settings.example.yaml config/settings.yaml
python run.py
```

| | |
|---|---|
| Meraki API (HTTPS, self-signed) | `https://localhost:5000` |
| Emulator dashboard | `http://localhost:8081` |
| API key | `6789123456789012345678901234567890123456` |
| Organization ID | `2947` |
| Catalyst Center API (HTTPS, self-signed) | `https://localhost:5001` |
| Catalyst Center username / password | `northwind_admin` / `Emulanet2026!` |

## Demo topology — Northwind Retail Group (fictional)

8 sites · 75 devices · 70 L2 links · 46 clients · 648 staff. One network per
physical location; every store follows one repeatable template (gateway →
switch → access points → cameras → sensor); the HQ firewall pair is the SD-WAN
hub for the DC and the six stores. Business context is carried only through
fields the real API exposes — VLAN and SSID names, device notes, tags and
rack addresses. Details: [docs/topology.md](docs/topology.md).

A second source emulates Cisco Catalyst Center for the campus core, data
centre and a regional office (13 sites, 27 devices, 35 links). Three HQ
switches appear in both sources, so analytics that join on serial or MAC show
one estate assembled from two management systems. Details:
[docs/catalyst.md](docs/catalyst.md).

## Scenarios

Four families, ordered by business impact: revenue (POS outage, WAN
degradation, HA failover, AP offline), loss prevention (camera offline,
cold-chain excursion, server-room environmental), security (PCI intrusion,
brute force, rogue device), and operations/growth (scanner roaming, WiFi
saturation, VPN tunnel down, firmware window, new-store onboarding).
Full list and propagation rules: [docs/scenarios.md](docs/scenarios.md).

## Project layout

```
config/
  topology.yaml          # Sites, devices, L2 cabling, VLANs, SSIDs, clients
  catalyst_topology.yaml # Catalyst Center sites, devices, interfaces, links
  scenarios.yaml         # Retail scenarios with business impact
  settings.yaml          # Ports, API key, HEC target (gitignored)
  settings.example.yaml  # Template
  tls/                   # Self-signed cert and key (gitignored)
src/
  topology/              # YAML -> state, Meraki and Catalyst Center models
  api/server.py          # Meraki Dashboard API mock (~110 GET routes)
  api/catalyst_server.py # Catalyst Center API mock (token auth, 11 routes)
  data/                  # Topology, inventory, health, scenario responses
  webhooks/              # Webhook alert payloads and HEC delivery
web/index.html           # Emulator dashboard: topology, sites, events, scenarios
splunk/docker-compose.yml# Local Splunk Enterprise for the demo
tools/mint_tls_cert.py   # Self-signed cert generator (runs in the container)
verify_*.py              # Offline and live verification suites
```

## Documentation

- [docs/topology.md](docs/topology.md) — the fictional network and its business context
- [docs/scenarios.md](docs/scenarios.md) — scenario catalogue and propagation rules
- [docs/catalyst.md](docs/catalyst.md) — the Catalyst Center source: estate, routes, configuration
- [docs/verification.md](docs/verification.md) — what each verification suite proves

## Roadmap

- [x] Meraki Dashboard API polling and webhooks
- [x] Catalyst Center source (physical topology, site topology, device
      health, interfaces, issues)
- [ ] Catalyst Center: scenario-driven issues and the remaining datasets
      (client, network and site health, compliance, advisories, events)
- [ ] SD-WAN Manager style source
- [ ] ThousandEyes style source (synthetic tests, path visualization)
