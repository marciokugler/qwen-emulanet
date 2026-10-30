# Scenarios

16 retail scenarios, each with an explicit `business_impact` in
`config/scenarios.yaml`. They run on two triggers: `scheduled` (fixed period,
fixed duration) and `random` (probability per check window).

| Category | Scenario | Trigger | Business impact |
|---|---|---|---|
| Revenue | `store_uplink_failure_flagship` | scheduled | Whole flagship store loses wired connectivity: 12 POS lanes dark |
| Revenue | `store_gateway_wan_degradation` | scheduled | Slow POS authorisation, scanner timeouts, degraded guest WiFi |
| Revenue | `hq_firewall_ha_failover` | scheduled | All VPN tunnels re-converge to the secondary hub |
| Revenue | `store_ap_offline_trading_hours` | random | Customer WiFi unavailable; inventory handhelds drop |
| Loss prevention | `pos_camera_port_crc_errors` | random | Loss-prevention video for the register bank unreliable |
| Loss prevention | `lp_camera_offline_pos_lanes` | random | No video retention for register transactions — audit gap |
| Loss prevention | `cold_chain_temperature_excursion` | scheduled | Product safety risk and shrink; refrigeration failure |
| Loss prevention | `hq_server_room_environmental` | scheduled | Tier-1 site overheating threatens HQ and PCI systems |
| Security | `pci_segment_intrusion_attempt` | random | Attempted lateral movement into the cardholder environment |
| Security | `guest_wifi_brute_force` | random | External attack surface on a branch gateway |
| Security | `unauthorized_device_on_pos_vlan` | random | Segmentation control event — rogue device on POS VLAN |
| Operations | `warehouse_scanner_roaming` | random | Pick-and-putaway slowdowns; forklift terminals stall |
| Operations | `guest_wifi_saturation_weekend` | scheduled | Customer experience degradation at peak footfall |
| Operations | `vpn_tunnel_down_dallas` | random | Store cut off from HQ merchandising and payroll |
| Growth | `fleet_firmware_upgrade_window` | scheduled | Planned overnight maintenance; no trading impact |
| Growth | `new_store_onboarding_denver` | scheduled | New site brought online with zero-touch provisioning |

## Propagation rules

A scenario never changes one number in isolation. Effects propagate so that
every view of the network agrees:

- A port fault flips the switch port status enum, the L2 link state, and
  removes the adjacency from neighbour discovery — graph, port tables and
  discovery data stay consistent.
- A device fault changes availability, drops its clients, and emits an event
  attributed to that specific device and scoped to its network.
- A WAN fault degrades uplink loss/latency series and marks VPN tunnels down.
- Every fault self-heals after its duration, restoring the pre-fault state.

## Grading expectations

Scenarios are written so that a downstream fault-grading engine classifies the
fault as critical rather than healthy. The rules themselves, and the
counter-intuitive cases they produce (a down access port reading as healthy,
for instance), are documented in `notes/ni-integration.md` — local only, since
they describe third-party behaviour.
