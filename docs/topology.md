# The demo topology — Northwind Retail Group

A fictional US retail chain used as the demo dataset. Everything in it —
names, addresses, staff counts, device serials, telemetry — is invented.

**8 sites · 75 devices · 70 L2 links · 46 clients · 648 staff**

| Site | Type | Criticality | Staff | Devices | PCI-scoped devices |
|---|---|---|---|---|---|
| HQ – Seattle | corporate | tier-1 | 240 | 15 | 5 |
| DC – Reno | distribution | tier-1 | 180 | 12 | 0 |
| Store 0042 – NYC | retail-flagship | tier-2 | 65 | 8 | 3 |
| Store 0117 – LA | mall-anchor | tier-2 | 42 | 8 | 3 |
| Store 0203 – Chicago | urban-street | tier-2 | 38 | 8 | 3 |
| Store 0288 – Dallas | standard | tier-3 | 28 | 8 | 3 |
| Store 0351 – Boston | standard | tier-3 | 31 | 8 | 3 |
| Store 0429 – Denver | standard | tier-3 | 24 | 8 | 3 |

## Structure

- One network per physical location. Splitting a location's network by device
  type is only sensible for very small deployments; retail chains standardise
  per site, and so does this dataset.
- Every store follows one template: gateway → access switch → two access
  points → three cameras → one environmental sensor. The repetition is the
  point: it shows a chain's rollout pattern, and it makes scenario effects
  comparable across sites.
- HQ runs a firewall HA pair as the SD-WAN hub; the DC and all six stores are
  spokes. VPN mesh links are modelled as first-class objects so tunnel
  failures have somewhere to live.
- Five device families appear (security appliance, switch, access point,
  camera, sensor) so family-specific behaviour can be demonstrated.

## Business context, carried only in real API fields

No invented fields. Business meaning lives in the fields a real deployment
would use, following the vendor's documented tagging conventions (lowercase,
hyphenated, geographic plus functional dimensions):

- **VLAN names** — `Corporate`, `VoIP`, `POS-PCI`, `Inventory`, `Guest-WiFi`,
  `Security-Cameras`, `Building-IoT`, `Management`
- **SSID names** — `Northwind-Corp` (802.1X), `Northwind-Guest` (captive
  portal), `Northwind-VoIP`, `Northwind-Scanning`
- **Device notes** — e.g. *"Register transaction monitoring. Retention 90 days
  for PCI DSS audit."*
- **Tags** — `pci-scope`, `loss-prevention`, `cold-chain`, `sdwan-hub`,
  `store-0042`, `metro-nyc`, `tier-1-critical`
- **Address** — physical and rack location, e.g. *"POS lane bank, registers 1-12"*
- **Client notes** — e.g. *"POS — card-present transactions, PCI DSS scope"*

Client mix is deliberately business-shaped: 13 POS terminals, 9 warehouse
scanners, 7 IoT/OT devices, 8 associate workstations, 23 guest devices.

## Why retail

Retail concentrates the failure modes a network analytics demo needs: revenue
stops when a POS lane loses connectivity, loss prevention stops when a camera
goes dark, compliance exposure appears when a segmented VLAN is breached, and
growth shows up as a new site onboarding with zero touch. Each of those maps
to a scenario in [scenarios.md](scenarios.md).
