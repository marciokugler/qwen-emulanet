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

## Notice

- Independent demo project. Not affiliated with, endorsed by, or sponsored by
  Cisco Systems, Inc. or Splunk Inc.
- Cisco, Meraki, Splunk and Network Intelligence are trademarks of their
  respective owners, used only to name the products this tool integrates with.
- This repository contains no Cisco or Splunk source code, configuration, or
  documentation. API response shapes were implemented from publicly available
  API documentation and from observed integration behaviour; the observations
  themselves are kept in local, uncommitted notes (see `notes/` below).
- All company names, sites, devices, addresses and telemetry are fictional.

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

Setting up the local Splunk instance and connecting the add-on to this
emulator is described in `notes/splunk-setup.md` (local-only, not committed).

## What it emulates

- ~110 GET endpoints of the Meraki Dashboard API v1, including the
  organization OpenAPI document that clients use for endpoint discovery.
- Authentication by API-key header or Bearer token, as the production API
  accepts both.
- Webhook alert delivery to a Splunk HEC endpoint (disabled by default, so
  anything in Splunk provably arrived by polling).
- 16 scheduled and probabilistic scenarios whose effects propagate
  consistently: a port flap flips the port status, the L2 link state and the
  neighbour-discovery data at the same time, and every event is attributed to
  the device that generated it.

## Demo topology — Northwind Retail Group (fictional)

8 sites · 75 devices · 70 L2 links · 46 clients · 648 staff. One network per
physical location; every store follows one repeatable template (gateway →
switch → access points → cameras → sensor); the HQ firewall pair is the SD-WAN
hub for the DC and the six stores. Business context is carried only through
fields the real API exposes — VLAN and SSID names, device notes, tags and
rack addresses. Details: [docs/topology.md](docs/topology.md).

## Scenarios

Four families, ordered by business impact: revenue (POS outage, WAN
degradation, HA failover, AP offline), loss prevention (camera offline,
cold-chain excursion, server-room environmental), security (PCI intrusion,
brute force, rogue device), and operations/growth (scanner roaming, WiFi
saturation, VPN tunnel down, firmware window, new-store onboarding).
Full list and propagation rules: [docs/scenarios.md](docs/scenarios.md).

## Verification

```bash
python verify_topology.py         # offline: schemas, business context, scenario refs
python verify_addon_contract.py   # offline: discovery policy + downstream field contract
python verify_addon_live.py       # live: every polled endpoint, from inside Splunk
python verify_scenarios.py        # live: scenario propagation + fault grading
python verify_splunk_e2e.py       # live: emulator -> HEC -> Splunk search
```

What each script asserts: [docs/verification.md](docs/verification.md).

## Project layout

```
config/
  topology.yaml          # Sites, devices, L2 cabling, VLANs, SSIDs, clients
  scenarios.yaml         # Retail scenarios with business impact
  settings.yaml          # Ports, API key, HEC target (gitignored)
  settings.example.yaml  # Template
  tls/                   # Self-signed cert and key (gitignored)
src/
  topology/              # YAML -> state, device/link/vlan/client models
  api/server.py          # Meraki Dashboard API mock (~110 GET routes)
  data/                  # Topology, inventory, health, scenario responses
  webhooks/              # Webhook alert payloads and HEC delivery
web/index.html           # Emulator dashboard: topology, sites, events, scenarios
splunk/docker-compose.yml# Local Splunk Enterprise for the demo
tools/mint_tls_cert.py   # Self-signed cert generator (runs in the container)
verify_*.py              # Offline and live verification suites
notes/                   # Third-party integration notes (gitignored, local only)
```

## Documentation map

| Document | Committed? | Contents |
|---|---|---|
| [docs/topology.md](docs/topology.md) | yes | The fictional network and its business context |
| [docs/scenarios.md](docs/scenarios.md) | yes | Scenario catalogue and propagation rules |
| [docs/verification.md](docs/verification.md) | yes | What each verification suite asserts |
| `notes/splunk-setup.md` | no | Splunk instance, add-on connection, input recipe |
| `notes/meraki-addon-contract.md` | no | Observed add-on collector behaviour and API fidelity notes |
| `notes/ni-integration.md` | no | How the downstream analytics app consumes this data |
| `notes/troubleshooting.md` | no | Every integration gotcha hit while building this |

Third-party integration detail lives only in `notes/` because it describes
the internals of software this project does not own.

## Roadmap

- [x] Meraki Dashboard API polling and webhooks
- [ ] Catalyst Center / SD-WAN Manager style source (physical topology, site
      topology, device health, issues)
- [ ] ThousandEyes style source (synthetic tests, path visualization)

## Limitations

- A demo tool, not a production-compatible Meraki service: coverage is partial
  and some values are synthetic.
- Telemetry is generated in-process; nothing persists across restarts.
