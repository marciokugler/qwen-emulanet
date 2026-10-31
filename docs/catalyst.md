# The Catalyst Center source

A second, independent API that emulates a Cisco Catalyst Center (formerly DNA
Center) controller for the same fictional company. Where the Meraki API covers
the stores, Catalyst Center manages the campus core, the data centre fabric
and a regional office. The two sources overlap at HQ, which is what lets the
analytics side show one estate assembled from two management systems.

**13 sites · 27 devices · 35 links · 744 interfaces · 4 issues**

| | |
|---|---|
| Catalyst Center API (HTTPS, self-signed) | `https://localhost:5001` |
| Username / password | `northwind_admin` / `Emulanet2026!` |
| Reported release | `3.1.3.0` |

The API runs on its own port because a Catalyst Center client treats the host
as a controller and needs the controller's own root paths. It serves TLS with
the same certificate as the Meraki API (`config/tls/`), and `run.py` starts it
whenever `catalyst.enabled` is true.

## The estate

Defined in `config/catalyst_topology.yaml`. The site tree is
Global → area → building → floor, with coordinates on every building:

| Area | Building | Floors | Devices |
|---|---|---|---|
| HQ Campus | HQ-Seattle | Floor 1, Floor 2, Data Hall | 15 |
| Data Centre | DC-Reno | Server Room, Warehouse | 8 |
| Regional Offices | Office-Chicago | Floor 3 | 4 |

- **HQ** — C9500 core pair, ISR4431 edge router, three C9300 access switches,
  a C9800 wireless controller and five C9120 access points, plus the three
  shared switches below.
- **DC** — a C9500 spine pair, four C9300 leaves, an IE3400 industrial switch
  in the warehouse and an ISR4331 edge router.
- **Chicago** — ISR4321 edge router, one C9300 access switch, two C9120 access
  points.

Every device, interface and site has a Catalyst Center–style UUID derived
deterministically from `controller.uuid_namespace`, so identifiers are stable
across restarts. Each link references its two interfaces by those UUIDs.

## Two systems, one estate

Three HQ switches — `HQ-Seattle-Core-SW01`, `HQ-Seattle-Core-SW02` and
`HQ-Seattle-Access-Floor1` — exist in both `config/topology.yaml` and
`config/catalyst_topology.yaml` with the same serial and MAC. The story is a
migration in progress: Meraki still manages them, and Catalyst Center has
discovered them. Downstream analytics that join devices on serial or MAC show
each of them once, attributed to both sources, while the other 24 Catalyst
devices and 72 Meraki devices stay distinct. `run.py` logs the shared devices
at startup.

## API surface

Authentication follows the controller: HTTP Basic against the token endpoint
returns `{"Token": "..."}`, and every later call sends it as `X-Auth-Token`.
Tokens expire after `token_ttl_seconds`; an expired or unknown token gets a
401, and the client is expected to authenticate again.

| Route | Data |
|---|---|
| `POST /dna/system/api/v1/auth/token` | token exchange |
| `GET /dna/intent/api/v1/dnac-release` | controller release |
| `GET /dna/intent/api/v1/sites` | site hierarchy |
| `GET /dna/intent/api/v1/device-health` | per-device health, CPU, memory, reachability |
| `GET /dna/intent/api/v1/network-device` | device inventory |
| `GET /dna/intent/api/v1/network-device/count` | inventory count, always equal to the inventory length |
| `GET /dna/intent/api/v1/network-device/{id}` | one device |
| `POST /dna/intent/api/v2/networkDevices/{id}/interfaces/query` | per-device interfaces with rates, errors and discards |
| `GET /dna/intent/api/v1/topology/physical-topology` | nodes and links, as one object |
| `GET /dna/data/api/v1/assuranceIssues` | assurance issues, paged |
| `GET /dna/data/api/v1/interfaces` | deliberately 404 — the per-device interface query is the supported path |
| `GET /health` | emulator status (not a controller route) |

Errors use the controller's envelope:
`{"response": {"errorCode": ..., "message": ...}, "version": "1.0"}`.
Why each field has the shape it has is recorded in the local-only
`notes/catalyst-addon-contract.md`.

## Data behaviour

- The inventory is fixed when the emulator starts: no device is added or
  removed while it runs, and the count never moves between polls.
- CPU, memory, health scores and interface rates, errors and discards are
  drawn fresh on every request within healthy ranges, so repeated polls look
  alive. A device that is down reports zeros.
- Four issues are seeded at startup, staggered an hour apart: high memory on
  `HQ-C9500-Core-01`, interface flapping on `DC-IE3400-Warehouse-01`, high CPU
  on `CHI-C9300-Access-01`, and `DC-C9300-Leaf-03` unreachable. Each carries
  the device's MAC, serial and UUID so it can attach to the right device.
- The scenario engine does not yet drive this source: a Meraki incident does
  not appear here, and the issue set does not change while the emulator runs.

## Configuration

The `catalyst:` block in `config/settings.yaml` (template in
`config/settings.example.yaml`):

```yaml
catalyst:
  enabled: true
  host: "0.0.0.0"
  port: 5001
  topology_file: "config/catalyst_topology.yaml"
  username: "northwind_admin"
  password: "Emulanet2026!"
  token_ttl_seconds: 3600
```

At startup `run.py` checks that the API answers on localhost and that a token
is issued and accepted, and logs `Catalyst API auth verified ... inventory
count=27`.

## Verification

`python verify_catalyst_contract.py` runs offline against the app in-process:
envelopes and field types for every route, pagination that echoes the request,
count equal to inventory, every link resolving to known device and interface
UUIDs, physical topology as a single object, unique serials and MACs, exactly
the three intended devices shared with the Meraki estate, and no route
returning a 5xx. See [verification.md](verification.md).

Validated live on 2026-10-31 against the local Splunk instance: all five
collected datasets arrived with the expected counts (13 sites, 27 devices per
health poll, 744 interfaces per poll, 4 issues, one topology snapshot), and
the analytics side built 99 devices (75 + 27 − 3 shared), 21 sites and 35
Catalyst links, with device and interface health accepted.

## Not yet served

Client health and client detail, network and site health, compliance,
software images, security advisories, events, audit logs and reports. A
client that asks for them gets a 404 today.
