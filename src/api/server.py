"""FastAPI Meraki Dashboard API mock server."""

from __future__ import annotations

from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import zlib

from src.topology.models import TopologyState
from src.data import generators as gen
from src.data import topology as topo

logger = logging.getLogger(__name__)

# Valid Meraki radio channels, used to derive a stable per-AP assignment.
_CHANNELS_24 = [1, 6, 11]
_CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161]


def create_api_server(state: TopologyState, api_key: str) -> FastAPI:
    app = FastAPI(
        title="Cisco Meraki API Emulator",
        description="Mock Meraki Dashboard API for Splunk Network Intelligence demos",
        version="1.53.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    async def verify_api_key(x_cisco_meraki_api_key: str = Header(None)):
        if x_cisco_meraki_api_key != api_key:
            logger.warning(f"Invalid API key attempt: {x_cisco_meraki_api_key}")
            raise HTTPException(status_code=401, detail="Invalid API key")

    @app.get("/api/v1/organizations")
    async def get_organizations(key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return gen.generate_organizations_list(state)

    @app.get("/api/v1/organizations/{org_id}")
    async def get_organization(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return gen.generate_organization_response(state)

    @app.get("/api/v1/organizations/{org_id}/networks")
    async def get_networks(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                           perPage: int = 1000, startingAfter: str = None, endingBefore: str = None,
                           tags: list[str] = None, productTypes: list[str] = None,
                           isBoundToConfigTemplate: bool = None, tagFilterPolicy: str = "applyTagsToAllOrNone"):
        await verify_api_key(key)
        return gen.generate_networks_response(state)

    @app.get("/api/v1/organizations/{org_id}/devices")
    async def get_org_devices(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                              perPage: int = 1000, startingAfter: str = None, endingBefore: str = None,
                              configurationUpdatedAfter: str = None, networkIds: list[str] = None,
                              serials: list[str] = None, models: list[str] = None,
                              productTypes: list[str] = None, tags: list[str] = None,
                              tagsFilterType: str = "withAnyTags", name: str = None,
                              mac: str = None):
        await verify_api_key(key)
        network_id = networkIds[0] if networkIds else None
        return gen.generate_devices_response(state, network_id=network_id,
                                              product_types=productTypes, tags=tags,
                                              per_page=perPage)

    @app.get("/api/v1/organizations/{org_id}/devices/availabilities")
    async def get_device_availabilities(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                         perPage: int = 1000, startingAfter: str = None,
                                         endingBefore: str = None, serials: list[str] = None,
                                         productTypes: list[str] = None, networkIds: list[str] = None,
                                         statuses: list[str] = None):
        await verify_api_key(key)
        return gen.generate_device_availability(state)

    @app.get("/api/v1/organizations/{org_id}/devices/overview/byNetwork")
    async def get_devices_overview_by_network(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        networks = []
        for net in state.networks.values():
            devices = state.get_devices_by_network(net.id)
            networks.append({
                "network": {"id": net.id, "name": net.name},
                "gatewayApplianceCount": sum(1 for d in devices if d.model.startswith("MX")),
                "switchCount": sum(1 for d in devices if d.model.startswith("MS")),
                "wirelessCount": sum(1 for d in devices if d.model.startswith("MR")),
                "cameraCount": sum(1 for d in devices if d.model.startswith("MV")),
                "sensorCount": sum(1 for d in devices if d.model.startswith("MT")),
            })
        return {"networks": networks}

    @app.get("/api/v1/organizations/{org_id}/summary/top/appliances/byUtilization")
    async def get_top_appliances(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                  t0: str = None, timespan: int = 86400, networkIds: list[str] = None,
                                  topCount: int = 10):
        await verify_api_key(key)
        return gen.generate_top_appliances_by_utilization(state, top_count=topCount)

    @app.get("/api/v1/organizations/{org_id}/summary/top/switches/byEnergyUsage")
    async def get_top_switches_energy(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                       t0: str = None, timespan: int = 86400, networkIds: list[str] = None,
                                       topCount: int = 10):
        await verify_api_key(key)
        return gen.generate_top_switches_by_energy(state, top_count=topCount)

    @app.get("/api/v1/organizations/{org_id}/summary/top/clients/byUsage")
    async def get_top_clients(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                               t0: str = None, timespan: int = 86400, networkIds: list[str] = None,
                               topCount: int = 10):
        await verify_api_key(key)
        return gen.generate_top_clients_by_usage(state, top_count=topCount)

    @app.get("/api/v1/organizations/{org_id}/appliance/vpn/stats")
    async def get_vpn_stats(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                             t0: str = None, timespan: int = 3600, networkIds: list[str] = None,
                             serials: list[str] = None):
        await verify_api_key(key)
        return gen.generate_vpn_stats(state)

    @app.get("/api/v1/organizations/{org_id}/appliance/vpn/statuses")
    async def get_vpn_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                perPage: int = 1000, networkIds: list[str] = None,
                                serials: list[str] = None):
        await verify_api_key(key)
        return gen.generate_vpn_statuses(state)

    @app.get("/api/v1/organizations/{org_id}/securityEvents")
    async def get_security_events(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   t0: str = None, timespan: int = 86400, perPage: int = 100,
                                   startingAfter: str = None, endingBefore: str = None,
                                   deviceSerials: list[str] = None, deviceTypes: list[str] = None,
                                   ssidNames: list[str] = None, searchTerms: str = None):
        await verify_api_key(key)
        return gen.generate_security_events(state, per_page=perPage)

    @app.get("/api/v1/organizations/{org_id}/sensor/readings/history")
    async def get_sensor_readings(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   t0: str = None, t1: str = None, timespan: int = 86400,
                                   networkIds: list[str] = None, serials: list[str] = None,
                                   metrics: list[str] = None, perPage: int = 100):
        await verify_api_key(key)
        return gen.generate_sensor_readings(state, per_page=perPage)

    @app.get("/api/v1/organizations/{org_id}/apiRequests")
    async def get_api_requests(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                t0: str = None, t1: str = None, timespan: int = 86400,
                                perPage: int = 100, adminIds: list[str] = None,
                                paths: list[str] = None, methods: list[str] = None,
                                responseCodes: list[int] = None, sourceAddresses: list[str] = None):
        await verify_api_key(key)
        return gen.generate_api_requests(state)

    @app.get("/api/v1/organizations/{org_id}/webhooks/logs")
    async def get_webhook_logs(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                t0: str = None, t1: str = None, timespan: int = 86400,
                                perPage: int = 100, startingAfter: str = None, endingBefore: str = None,
                                url: str = None):
        await verify_api_key(key)
        return gen.generate_webhook_logs(state)

    @app.get("/api/v1/organizations/{org_id}/actionBatches")
    async def get_action_batches(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                  status: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/configTemplates")
    async def get_config_templates(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                    perPage: int = 1000, startingAfter: str = None, endingBefore: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/admins")
    async def get_admins(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return [
            {
                "id": "admin_001",
                "name": "Network Admin",
                "email": "admin@acme.com",
                "orgAccess": "full",
                "networks": [],
                "tags": [],
            }
        ]

    @app.get("/api/v1/organizations/{org_id}/snmp")
    async def get_snmp_settings(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {
            "v2cEnabled": True,
            "v3Enabled": False,
            "v2cCommunity": "public",
        }

    @app.get("/api/v1/organizations/{org_id}/openapiSpec")
    async def get_openapi_spec(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        """Organization OpenAPI document.

        The Splunk Meraki add-on fetches this to discover endpoints that are not
        in its bundled SDK catalog — which is how the two topology operations
        become selectable as Custom API inputs.
        """
        await verify_api_key(key)
        return topo.generate_openapi_spec(state)

    @app.get("/api/v1/organizations/{org_id}/firmwareUpgrades")
    async def get_firmware_upgrades(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     t0: str = None, timespan: int = 604800, perPage: int = 100,
                                     productTypes: list[str] = None):
        await verify_api_key(key)
        return gen.generate_firmware_upgrades(state)

    @app.get("/api/v1/organizations/{org_id}/licenses")
    async def get_licenses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                            perPage: int = 1000, startingAfter: str = None, endingBefore: str = None,
                            deviceSerial: str = None):
        await verify_api_key(key)
        return gen.generate_licenses(state)

    @app.get("/api/v1/organizations/{org_id}/overview/clients/usage")
    async def get_clients_usage_overview(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                          t0: str = None, timespan: int = 86400):
        await verify_api_key(key)
        total_sent = sum(c.sent for c in state.clients.values())
        total_recv = sum(c.recv for c in state.clients.values())
        return {
            "usageOverview": {
                "sent": total_sent,
                "recv": total_recv,
                "total": total_sent + total_recv,
            },
        }

    @app.get("/api/v1/networks/{network_id}")
    async def get_network(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        net = state.get_network(network_id)
        if not net:
            raise HTTPException(status_code=404, detail="Network not found")
        return {
            "id": net.id,
            "organizationId": state.organization.get("id", "ORG_001"),
            "name": net.name,
            "productTypes": net.product_types,
            "tags": net.tags,
            "timeZone": net.timezone,
            "url": f"https://n1.meraki.com/{net.id}/manage",
        }

    @app.get("/api/v1/networks/{network_id}/devices")
    async def get_network_devices(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   perPage: int = 1000):
        await verify_api_key(key)
        return gen.generate_devices_response(state, network_id=network_id, per_page=perPage)

    @app.get("/api/v1/networks/{network_id}/events")
    async def get_network_events(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                  perPage: int = 50, startingAfter: str = None, endingBefore: str = None,
                                  includedEventTypes: list[str] = None, deviceSerial: str = None,
                                  deviceMac: str = None, clientMac: str = None, clientIp: str = None):
        await verify_api_key(key)
        return gen.generate_network_events(state, network_id, per_page=perPage,
                                            event_types=includedEventTypes)

    @app.get("/api/v1/networks/{network_id}/clients")
    async def get_network_clients(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   t0: str = None, timespan: int = 86400, perPage: int = 1000,
                                   startingAfter: str = None, endingBefore: str = None,
                                   statuses: list[str] = None, ip: str = None, ip6: str = None,
                                   ip6Local: str = None, mac: str = None, os: str = None,
                                   psk: int = None, vlan: int = None, namedVlan: str = None):
        await verify_api_key(key)
        return gen.generate_client_usage(state, network_id=network_id)

    @app.get("/api/v1/networks/{network_id}/wireless/airMarshal")
    async def get_air_marshal(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                               t0: str = None, timespan: int = 86400):
        await verify_api_key(key)
        return gen.generate_air_marshal(state, network_id)

    @app.get("/api/v1/devices/{serial}")
    async def get_device(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        device = state.get_device(serial)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return gen.generate_device_response(device, state)

    @app.get("/api/v1/devices/{serial}/uplink")
    async def get_device_uplink(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                 t0: str = None, timespan: int = 3600):
        await verify_api_key(key)
        device = state.get_device(serial)
        if not device or not device.uplink:
            raise HTTPException(status_code=404, detail="Device or uplink not found")
        return {
            "wan1": {
                "ip": device.uplink.wan_ip or device.uplink.ip,
                "gateway": device.uplink.gateway or "0.0.0.0",
                "interface": "wan1",
                "status": "Active" if device.status != "offline" else "Failed",
            }
        }

    @app.get("/api/v1/devices/{serial}/lldpCdp")
    async def get_lldp_cdp(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                            timespan: int = 86400):
        await verify_api_key(key)
        device = state.get_device(serial)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return topo.generate_device_lldp_cdp(state, serial)

    # -----------------------------------------------------------------------
    # Topology endpoints. These are what Splunk Network Intelligence consumes
    # to build its graph (nodes + L2 links). Without them NI renders nothing.
    # -----------------------------------------------------------------------
    @app.get("/api/v1/organizations/{org_id}/devices/topology/nodes/discovered")
    async def get_topology_nodes_discovered(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                            perPage: int = 1000, startingAfter: str = None,
                                            endingBefore: str = None):
        await verify_api_key(key)
        return topo.generate_topology_nodes_discovered(state, per_page=perPage)

    @app.get("/api/v1/organizations/{org_id}/devices/topology/l2/links")
    async def get_topology_l2_links(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                    perPage: int = 1000, startingAfter: str = None,
                                    endingBefore: str = None):
        await verify_api_key(key)
        return topo.generate_topology_l2_links(state, per_page=perPage)

    @app.get("/api/v1/networks/{network_id}/topology/linkLayer")
    async def get_link_layer_topology(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        network = state.get_network(network_id)
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")
        return topo.generate_link_layer_topology(state, network_id)

    @app.get("/api/v1/devices/{serial}/lossAndLatencyHistory")
    async def get_loss_latency_history(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                        t0: str = None, t1: str = None, timespan: int = 3600,
                                        ip: str = None, resolution: int = 60):
        await verify_api_key(key)
        device = state.get_device(serial)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return []

    @app.get("/api/v1/devices/{serial}/switch/ports/statuses")
    async def get_switch_port_statuses(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return topo.generate_switch_port_statuses(state, serial)

    @app.get("/api/v1/devices/{serial}/switch/ports")
    async def get_switch_ports(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return gen.generate_switch_ports_config(state, serial)

    @app.get("/api/v1/organizations/{org_id}/switch/ports/bySwitch")
    async def get_org_switch_ports(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                    perPage: int = 1000, configurationUpdatedAfter: str = None,
                                    networkIds: list[str] = None, serials: list[str] = None):
        """Bare array, one record per switch with nested ports[].

        NI parents interface vertices to devices via the per-switch `mac` and to
        sites via `network.id`, so the per-switch grouping is required.
        """
        await verify_api_key(key)
        records = topo.generate_switch_ports_by_switch(state)
        if networkIds:
            records = [r for r in records if r["network"]["id"] in networkIds]
        if serials:
            records = [r for r in records if r["serial"] in serials]
        return records[:perPage]

    @app.get("/api/v1/organizations/{org_id}/switch/ports/statuses/bySwitch")
    async def get_org_switch_port_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                            perPage: int = 1000, startingAfter: str = None,
                                            endingBefore: str = None, networkIds: list[str] = None,
                                            serials: list[str] = None):
        """Feeds NI's meraki.interface_status capability."""
        await verify_api_key(key)
        result = topo.generate_switch_port_statuses_by_switch(state, per_page=perPage)
        if networkIds:
            result["items"] = [r for r in result["items"] if r["network"]["id"] in networkIds]
        if serials:
            result["items"] = [r for r in result["items"] if r["serial"] in serials]
        return result

    @app.get("/api/v1/organizations/{org_id}/switch/ports/usage/history/byDevice/byInterval")
    async def get_org_switch_port_usage_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                                 t0: str = None, t1: str = None, timespan: int = 1200,
                                                 networkIds: list[str] = None, serials: list[str] = None,
                                                 portIds: list[str] = None, perPage: int = 1000,
                                                 startingAfter: str = None, endingBefore: str = None):
        """Feeds NI's meraki.interface_throughput and meraki.interface_power."""
        await verify_api_key(key)
        result = topo.generate_switch_ports_usage_history(state, timespan=timespan, per_page=perPage)
        if networkIds:
            result["items"] = [r for r in result["items"] if r["network"]["id"] in networkIds]
        if serials:
            result["items"] = [r for r in result["items"] if r["serial"] in serials]
        return result

    @app.get("/api/v1/organizations/{org_id}/devices/uplinks/addresses/byDevice")
    async def get_org_uplink_addresses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                        perPage: int = 1000, startingAfter: str = None,
                                        endingBefore: str = None, networkIds: list[str] = None,
                                        serials: list[str] = None, productTypes: list[str] = None):
        """Feeds NI's uplink interface vertex adapter (parented by mac)."""
        await verify_api_key(key)
        records = topo.generate_uplink_addresses_by_device(state)
        if networkIds:
            records = [r for r in records if r["network"]["id"] in networkIds]
        if serials:
            records = [r for r in records if r["serial"] in serials]
        if productTypes:
            records = [r for r in records if r["productType"] in productTypes]
        return records[:perPage]

    @app.get("/api/v1/organizations/{org_id}/devices/uplinksLossAndLatency")
    async def get_org_uplink_loss_latency(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                           t0: str = None, t1: str = None, timespan: int = 3600,
                                           networkIds: list[str] = None, serials: list[str] = None,
                                           uplinks: list[str] = None, ip: str = None):
        """Feeds NI's meraki.interface_uplink_quality capability.

        Path is /devices/uplinksLossAndLatency — no slash before "Loss".
        """
        await verify_api_key(key)
        records = topo.generate_uplinks_loss_and_latency(state, timespan=timespan)
        if networkIds:
            records = [r for r in records if r["networkId"] in networkIds]
        if serials:
            records = [r for r in records if r["serial"] in serials]
        if uplinks:
            records = [r for r in records if r["uplink"] in uplinks]
        if ip:
            records = [r for r in records if r["ip"] == ip]
        return records

    @app.get("/api/v1/organizations/{org_id}/wireless/devices/wireless/statuses")
    async def get_wireless_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     perPage: int = 1000, networkIds: list[str] = None,
                                     serials: list[str] = None):
        await verify_api_key(key)
        results = []
        for device in state.get_devices_by_model_prefix("MR"):
            if networkIds and device.network_id not in networkIds:
                continue
            if serials and device.serial not in serials:
                continue
            # Channel and power are stable per AP, derived from the serial.
            # A real radio holds its assignment until auto-RF changes it; it
            # does not re-roll on every API poll.
            seed = zlib.crc32(device.serial.encode())
            results.append({
                "serial": device.serial,
                "networkId": device.network_id,
                "status": gen.meraki_availability_status(device),
                "lastReportedAt": gen._ts_iso(device.last_seen),
                "channels": {
                    "2.4ghz": {
                        "channel": _CHANNELS_24[seed % len(_CHANNELS_24)],
                        "power": 5 + seed % 16,
                    },
                    "5ghz": {
                        "channel": _CHANNELS_5[(seed >> 3) % len(_CHANNELS_5)],
                        "power": 5 + (seed >> 5) % 19,
                    },
                },
            })
        return results[:perPage]

    @app.get("/api/v1/organizations/{org_id}/wireless/devices/ethernet/statuses")
    async def get_wireless_ethernet_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                              perPage: int = 1000, networkIds: list[str] = None,
                                              serials: list[str] = None):
        await verify_api_key(key)
        results = []
        for device in state.get_devices_by_model_prefix("MR"):
            results.append({
                "serial": device.serial,
                "networkId": device.network_id,
                "status": "Connected" if device.status.value == "online" else "Disconnected",
                "lastReportedAt": gen._ts_iso(device.last_seen),
                "speed": 1000 if device.status.value == "online" else 0,
                "duplex": "full" if device.status.value == "online" else "none",
            })
        return results

    @app.get("/api/v1/organizations/{org_id}/wireless/devices/wireless/packetLoss")
    async def get_wireless_packet_loss(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                        t0: str = None, t1: str = None, timespan: int = 3600,
                                        networkIds: list[str] = None, serials: list[str] = None,
                                        band: str = None):
        await verify_api_key(key)
        results = []
        for device in state.get_devices_by_model_prefix("MR"):
            results.append({
                "serial": device.serial,
                "networkId": device.network_id,
                "ts": gen._ts_iso(),
                "bands": {
                    "2.4ghz": {"packetLossPercent": round(0.1 + (0 if device.status.value == "online" else 50), 2)},
                    "5ghz": {"packetLossPercent": round(0.05 + (0 if device.status.value == "online" else 50), 2)},
                },
            })
        return results

    @app.get("/api/v1/organizations/{org_id}/wireless/wirelessControllers")
    async def get_wireless_controllers(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                        perPage: int = 1000, networkIds: list[str] = None,
                                        serials: list[str] = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/networks/firmwareUpgrades")
    async def get_network_firmware_upgrades(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"products": {}}

    @app.get("/api/v1/organizations/{org_id}/summary/top/devices/byUsage")
    async def get_top_devices_by_usage(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                        t0: str = None, timespan: int = 86400, networkIds: list[str] = None,
                                        topCount: int = 10):
        await verify_api_key(key)
        devices = state.get_all_devices()
        results = []
        for d in devices[:topCount]:
            results.append({
                "serial": d.serial,
                "name": d.name,
                "networkId": d.network_id,
                "networkName": state.get_network(d.network_id).name if state.get_network(d.network_id) else "",
                "usage": {
                    "total": 0,
                    "sent": 0,
                    "recv": 0,
                },
            })
        return results

    @app.get("/api/v1/organizations/{org_id}/overview/clients/usage/history")
    async def get_clients_usage_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                         t0: str = None, timespan: int = 86400, resolution: int = 3600):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/overview/clients/usage/overview")
    async def get_clients_usage_overview_v2(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                             t0: str = None, timespan: int = 86400):
        await verify_api_key(key)
        total_sent = sum(c.sent for c in state.clients.values())
        total_recv = sum(c.recv for c in state.clients.values())
        return {
            "usageOverview": {
                "sent": total_sent,
                "recv": total_recv,
                "total": total_sent + total_recv,
            },
        }

    @app.get("/api/v1/organizations/{org_id}/overview/devices/health")
    async def get_devices_health_overview(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        devices = state.get_all_devices()
        return {
            "counts": {
                "good": sum(1 for d in devices if d.status.value == "online"),
                "average": sum(1 for d in devices if d.status.value == "degraded"),
                "poor": sum(1 for d in devices if d.status.value == "offline"),
                "unknown": 0,
            },
            "deviceHealthScores": [],
        }

    @app.get("/api/v1/organizations/{org_id}/devices/availabilities/changeHistory")
    async def get_device_availability_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                               serials: list[str] = None, perPage: int = 100,
                                               startingAfter: str = None, endingBefore: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/devices/{serial}/camera/analytics/live")
    async def get_camera_analytics_live(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"zones": []}

    @app.get("/api/v1/devices/{serial}/camera/qualityAndRetention")
    async def get_camera_quality(serial: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {
            "motionBasedRetentionEnabled": True,
            "greyScaleEnabled": False,
            "restrictedBandwidthModeEnabled": False,
            "quality": "Standard",
            "resolution": "1920x1080",
            "fps": 30,
            "bitRate": 384,
            "maxRetentionDays": 30,
        }

    @app.get("/api/v1/organizations/{org_id}/camera/qualityRetentionPolicies")
    async def get_camera_policies(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/networks/{network_id}/switch/routing/interfaces")
    async def get_switch_routing_interfaces(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/networks/{network_id}/appliance/vlan/settings")
    async def get_vlan_settings(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"vlansEnabled": True}

    @app.get("/api/v1/networks/{network_id}/appliance/vlans")
    async def get_vlans(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        if not state.get_network(network_id):
            raise HTTPException(status_code=404, detail="Network not found")
        return topo.generate_vlans(state, network_id)

    @app.get("/api/v1/networks/{network_id}/ssids")
    async def get_ssids(network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        if not state.get_network(network_id):
            raise HTTPException(status_code=404, detail="Network not found")
        return topo.generate_ssids(state, network_id)

    @app.get("/api/v1/organizations/{org_id}/inventoryDevices")
    async def get_inventory_devices(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     perPage: int = 1000, startingAfter: str = None, endingBefore: str = None,
                                     serials: list[str] = None, models: list[str] = None,
                                     tags: list[str] = None, productTypes: list[str] = None,
                                     configurationsApplied: bool = None, networkIds: list[str] = None):
        await verify_api_key(key)
        return gen.generate_devices_response(state, product_types=productTypes, tags=tags, per_page=perPage)

    @app.get("/api/v1/organizations/{org_id}/cellularGateway/connectivityMonitoringDestinations")
    async def get_cellular_monitoring(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"destinations": []}

    @app.get("/api/v1/organizations/{org_id}/alerts/profiles")
    async def get_alert_profiles(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/alerts/history")
    async def get_alerts_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                  t0: str = None, t1: str = None, timespan: int = 86400,
                                  perPage: int = 100, networkIds: list[str] = None,
                                  deviceSerials: list[str] = None, alertTypes: list[str] = None,
                                  severities: list[str] = None, searchedText: str = None,
                                  sortBy: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/alerts/settings")
    async def get_alerts_settings(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   configTemplateId: str = None):
        await verify_api_key(key)
        return {"defaultDestinations": {"emails": [], "httpServerIds": [], "allAdmins": True}}

    @app.get("/api/v1/organizations/{org_id}/adaptivePolicy/overview")
    async def get_adaptive_policy_overview(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"counts": {"applications": 0, "groups": 0, "policies": 0, "whitelisted": 0}}

    @app.get("/api/v1/organizations/{org_id}/traffic")
    async def get_traffic(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                           t0: str = None, timespan: int = 86400, deviceSerial: str = None,
                           uplink: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/networks/{network_id}/traffic")
    async def get_network_traffic(org_id: str, network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   t0: str = None, timespan: int = 86400, deviceSerial: str = None,
                                   uplink: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/switch/routing/interfaces")
    async def get_org_switch_routing_interfaces(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/summary")
    async def get_org_summary(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        devices = state.get_all_devices()
        return {
            "counts": {
                "devices": len(devices),
                "admins": 1,
                "networks": len(state.networks),
            },
        }

    @app.get("/api/v1/organizations/{org_id}/overview")
    async def get_org_overview(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {
            "counts": {
                "devices": len(state.get_all_devices()),
                "networks": len(state.networks),
            },
        }

    @app.get("/api/v1/organizations/{org_id}/firmwareUpgrades/policies")
    async def get_firmware_policies(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/samlRoles")
    async def get_saml_roles(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/earlyAccess/features/optIns")
    async def get_early_access(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/actionBatches")
    async def get_action_batches_v2(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     status: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/camera/diagnostics")
    async def get_camera_diagnostics(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/switch/mtus")
    async def get_switch_mtus(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/cellularGateway/esimProfiles")
    async def get_esim_profiles(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/enterpriseDevices")
    async def get_enterprise_devices(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        devices = state.get_all_devices()
        return {
            "counts": {
                "total": len(devices),
                "online": sum(1 for d in devices if d.status.value == "online"),
                "offline": sum(1 for d in devices if d.status.value == "offline"),
            }
        }

    @app.get("/api/v1/organizations/{org_id}/policyObjects")
    async def get_policy_objects(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/policyObjects/groups")
    async def get_policy_object_groups(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/networks/{network_id}/groupPolicies")
    async def get_group_policies(org_id: str, network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/airMarshal")
    async def get_org_air_marshal(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                   t0: str = None, timespan: int = 86400, networkIds: list[str] = None):
        await verify_api_key(key)
        return {"settings": {"enabled": True}, "devices": [], "wirelessMacFilters": [], "observedAttacks": []}

    @app.get("/api/v1/organizations/{org_id}/wireless/alternateManagementInterface")
    async def get_wireless_alt_mgmt(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"enabled": False}

    @app.get("/api/v1/organizations/{org_id}/wireless/billing")
    async def get_wireless_billing(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"currency": "USD", "plans": []}

    @app.get("/api/v1/organizations/{org_id}/wireless/channelUtilizationHistory")
    async def get_channel_utilization_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                               t0: str = None, t1: str = None, timespan: int = 86400,
                                               networkIds: list[str] = None, serials: list[str] = None,
                                               autoResolution: bool = True, band: str = None,
                                               resolution: int = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/connectionStats")
    async def get_wireless_connection_stats(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                             t0: str = None, t1: str = None, timespan: int = 86400,
                                             band: str = None, ssid: int = None, vlan: int = None,
                                             apTag: str = None, networkIds: list[str] = None,
                                             serials: list[str] = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/dataRateStats")
    async def get_wireless_data_rate_stats(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                            t0: str = None, t1: str = None, timespan: int = 86400,
                                            networkIds: list[str] = None, serials: list[str] = None,
                                            band: str = None, ssid: int = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/failedConnections")
    async def get_wireless_failed_connections(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                               t0: str = None, t1: str = None, timespan: int = 86400,
                                               band: str = None, ssid: int = None, vlan: int = None,
                                               apTag: str = None, serial: str = None,
                                               networkId: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/latencyHistory")
    async def get_wireless_latency_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                            t0: str = None, t1: str = None, timespan: int = 86400,
                                            networkIds: list[str] = None, serials: list[str] = None,
                                            band: str = None, ssid: int = None, accessCategory: str = None,
                                            wifinetworkName: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/signalQualityHistory")
    async def get_wireless_signal_quality(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                           t0: str = None, t1: str = None, timespan: int = 86400,
                                           networkIds: list[str] = None, serials: list[str] = None,
                                           band: str = None, ssid: int = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/stats")
    async def get_wireless_stats(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                  t0: str = None, t1: str = None, timespan: int = 86400,
                                  networkId: str = None, serial: str = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/wireless/usageHistory")
    async def get_wireless_usage_history(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                          t0: str = None, t1: str = None, timespan: int = 86400,
                                          networkIds: list[str] = None, serials: list[str] = None,
                                          band: str = None, ssid: int = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/appliance/uplink/statuses")
    async def get_appliance_uplink_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                             perPage: int = 1000, networkIds: list[str] = None,
                                             serials: list[str] = None):
        await verify_api_key(key)
        results = []
        for device in state.get_devices_by_model_prefix("MX"):
            results.append({
                "serial": device.serial,
                "networkId": device.network_id,
                "wan1": {
                    "status": "Active" if device.status.value == "online" else "Not connected",
                    "ip": device.uplink.wan_ip if device.uplink else "0.0.0.0",
                    "provider": "Meraki Teleworker",
                    "iccid": "",
                    "model": "",
                    "apn": "",
                    "usage": {"sent": 0, "recv": 0},
                    "dns1": "8.8.8.8",
                    "dns2": "8.8.4.4",
                    "connectionType": "ethernet",
                },
            })
        return results

    @app.get("/api/v1/organizations/{org_id}/appliance/thirdParty/vpnPeers")
    async def get_third_party_vpn_peers(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/appliance/staticRoutes")
    async def get_static_routes(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/appliance/vpn/firewallRules")
    async def get_vpn_firewall_rules(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/appliance/vpn/siteToSiteVpn")
    async def get_site_to_site_vpn(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"mode": "hub"}

    @app.get("/api/v1/organizations/{org_id}/switch/switchProfiles")
    async def get_switch_profiles(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/switch/qosRules")
    async def get_qos_rules(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/switch/routing")
    async def get_switch_routing(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {}

    @app.get("/api/v1/organizations/{org_id}/switch/stormControl")
    async def get_storm_control(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return {"broadcastThreshold": 100, "multicastHandling": "forward"}

    @app.get("/api/v1/organizations/{org_id}/switch/topologies")
    async def get_switch_topologies(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     networkIds: list[str] = None):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/webhooks/httpServers")
    async def get_webhook_servers(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/webhooks/payloadTemplates")
    async def get_webhook_templates(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/environmental/ambient")
    async def get_ambient_environmental(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/devices/provisioning/statuses")
    async def get_provisioning_statuses(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/networks/{network_id}/events")
    async def get_network_events_v2(org_id: str, network_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key"),
                                     perPage: int = 50, startingAfter: str = None, endingBefore: str = None,
                                     includedEventTypes: list[str] = None, deviceSerial: str = None):
        await verify_api_key(key)
        return gen.generate_network_events(state, network_id, per_page=perPage,
                                            event_types=includedEventTypes)

    @app.get("/api/v1/organizations/{org_id}/liveTools/ping")
    async def get_live_tools_ping(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/liveTools/pingDevice")
    async def get_live_tools_ping_device(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/api/v1/organizations/{org_id}/liveTools/wakeOnLan")
    async def get_live_tools_wol(org_id: str, key: str = Header(None, alias="X-Cisco-Meraki-API-Key")):
        await verify_api_key(key)
        return []

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "devices": len(state.get_all_devices()), "networks": len(state.networks)}

    return app
