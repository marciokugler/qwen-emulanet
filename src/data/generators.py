"""Generate realistic Meraki API response data."""

from __future__ import annotations

import random
import time
import hashlib
from typing import Optional

from src.topology.models import (
    TopologyState, Device, DeviceStatus, DeviceFamily,
    UplinkStatus, Network,
)


def _ts_iso(ts: float = None) -> str:
    """Convert timestamp to ISO 8601 string."""
    if ts is None:
        ts = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))


def _ts_ms(ts: float = None) -> int:
    """Convert timestamp to milliseconds."""
    if ts is None:
        ts = time.time()
    return int(ts * 1000)


def generate_organization_response(state: TopologyState) -> dict:
    org = state.organization
    return {
        "id": org.get("id", "ORG_001"),
        "name": org.get("name", "Acme Corporation"),
        "url": org.get("url", "https://n1.meraki.com/o/ORG_001/manage"),
        "api": {"enabled": True},
        "licensing": {"model": "co-term"},
    }


def generate_organizations_list(state: TopologyState) -> list[dict]:
    return [generate_organization_response(state)]


def generate_networks_response(state: TopologyState) -> list[dict]:
    """GET /organizations/{orgId}/networks — bare array.

    NI derives site vertices from these records, so id/name/tags all matter.
    """
    org_id = state.organization.get("id", "2947")
    result = []
    for net in state.networks.values():
        # Meraki enrollment strings look like "enroll-x2-<hex>"; derive one
        # deterministically from the network id so repeated polls agree.
        token = hashlib.md5(net.id.encode()).hexdigest()[:6]
        result.append({
            "id": net.id,
            "organizationId": org_id,
            "name": net.name,
            "productTypes": net.product_types,
            "tags": net.tags,
            "enrollmentString": f"enroll-x2-{token}",
            "timeZone": net.timezone,
            "url": f"https://n43.meraki.com/{net.id}/manage",
            "isBoundToConfigTemplate": False,
        })
    return result


def generate_device_response(device: Device, state: TopologyState) -> dict:
    resp = {
        "serial": device.serial,
        "model": device.model,
        "name": device.name,
        "mac": device.mac,
        "lanIp": device.lan_ip,
        "tags": device.tags,
        "networkId": device.network_id,
        "firmware": device.get_firmware(),
        "address": device.address or "",
        "notes": device.notes or "",
        "url": f"https://n1.meraki.com/{device.network_id}/manage/nodes/{device.serial}",
    }

    if device.family == DeviceFamily.MR:
        resp["beaconIdParams"] = {
            "uuid": str(hashlib.md5(device.serial.encode()).hexdigest()[:8]),
            "major": random.randint(1, 100),
            "minor": random.randint(1, 100),
        }

    if device.family in (DeviceFamily.MX, DeviceFamily.MS, DeviceFamily.MR):
        resp["tags"] = device.tags

    return resp


def generate_devices_response(state: TopologyState,
                               network_id: str = None,
                               product_types: list[str] = None,
                               tags: list[str] = None,
                               per_page: int = 1000) -> list[dict]:
    devices = state.get_all_devices()

    if network_id:
        devices = [d for d in devices if d.network_id == network_id]

    if product_types:
        family_map = {
            "switch": DeviceFamily.MS,
            "appliance": DeviceFamily.MX,
            "wireless": DeviceFamily.MR,
            "camera": DeviceFamily.MV,
            "sensor": DeviceFamily.MT,
        }
        families = {family_map.get(pt) for pt in product_types if pt in family_map}
        devices = [d for d in devices if d.family in families]

    if tags:
        filtered = []
        for d in devices:
            for tag in tags:
                if tag in d.tags:
                    filtered.append(d)
                    break
        devices = filtered

    return [generate_device_response(d, state) for d in devices[:per_page]]


# Meraki's documented availability enum is alerting|dormant|offline|online —
# there is no "degraded". NI maps online->ok, offline->critical,
# alerting/dormant->degraded, and anything else to "unknown", so emitting our
# internal "degraded" verbatim would silently score as unknown.
_MERAKI_AVAILABILITY = {
    DeviceStatus.ONLINE: "online",
    DeviceStatus.OFFLINE: "offline",
    DeviceStatus.DEGRADED: "alerting",
}


def meraki_availability_status(device: Device) -> str:
    """Map internal device state onto Meraki's documented status enum."""
    return _MERAKI_AVAILABILITY.get(device.status, "online")


def generate_device_availability(state: TopologyState) -> list[dict]:
    """GET /organizations/{orgId}/devices/availabilities — bare array.

    The documented response carries exactly seven fields: mac, name,
    network.id, productType, serial, status, tags. Feeds NI's
    meraki.device_availability binding, which creates vertex:device keyed on
    serial — so this endpoint is what puts devices on NI's inventory at all.
    """
    return [
        {
            "mac": device.mac,
            "name": device.name,
            "network": {"id": device.network_id},
            "productType": device.device_type,
            "serial": device.serial,
            "status": meraki_availability_status(device),
            "tags": device.tags,
        }
        for device in state.get_all_devices()
    ]


def generate_network_events(state: TopologyState, network_id: str,
                             per_page: int = 50, starting_after: str = None,
                             event_types: list[str] = None) -> dict:
    events = [e for e in state.events if e["networkId"] == network_id]

    if event_types:
        events = [e for e in events if e["eventType"] in event_types]

    events = events[-per_page:]

    result_events = []
    for e in events:
        result_events.append({
            "id": e["id"],
            "occurredAt": _ts_iso(e["occurredAt"]),
            "networkId": network_id,
            "type": e["eventType"],
            "description": e["description"],
            "clientId": "",
            "deviceSerial": e.get("deviceSerial", ""),
            "deviceMac": "",
            "deviceName": "",
            "isPrimary": True,
            "eventData": e.get("details", {}),
        })

    return {
        "events": result_events,
        "pageStartAt": _ts_iso(events[0]["occurredAt"]) if events else _ts_iso(),
        "pageEndAt": _ts_iso(events[-1]["occurredAt"]) if events else _ts_iso(),
        "lastPage": True,
    }


def generate_switch_ports_config(state: TopologyState, serial: str) -> list[dict]:
    device = state.get_device(serial)
    if not device or device.family != DeviceFamily.MS:
        return []

    results = []
    for port in device.ports:
        results.append({
            "portId": port.number,
            "name": port.name,
            "tags": port.tags,
            "enabled": port.enabled,
            "poeEnabled": port.poe_enabled,
            "type": port.type,
            "vlan": port.vlan,
            "voiceVlan": 0,
            "allowedVlans": "all" if port.type == "trunk" else str(port.vlan),
            "isolationEnabled": False,
            "rstpEnabled": port.rstp_enabled,
            "stpGuard": port.stp_guard,
            "linkNegotiation": port.link_negotiation,
            "portScheduleId": port.port_schedule_id,
            "accessPolicyType": "Open",
            "adaptivePolicyGroupId": "",
            "flexibleSticky": {},
            "daiStatic": {"enabled": False},
        })

    return results


def generate_vpn_stats(state: TopologyState) -> list[dict]:
    results = []
    for peer in state.vpn_peers:
        device = state.get_device(peer.serial)
        if not device:
            continue

        stats_entry = {
            "networkId": peer.network_id,
            "deviceSerial": peer.serial,
            "deviceName": device.name,
            "uploadBandwidth": random.randint(10000, 100000),
            "downloadBandwidth": random.randint(10000, 100000),
            "numActiveStreams": random.randint(1, 10),
            "wanUplink": "wan1",
        }

        peer_vpn_stats = []
        for other_peer in state.vpn_peers:
            if other_peer.serial == peer.serial:
                continue
            other_device = state.get_device(other_peer.serial)
            if not other_device:
                continue

            vpn_status = "active"
            if device.status == DeviceStatus.OFFLINE or other_device.status == DeviceStatus.OFFLINE:
                vpn_status = "disconnected"

            peer_vpn_stats.append({
                "vpnMode": "auto",
                "publicIp": other_peer.public_ip,
                "network": f"{other_device.name}-LAN",
                "reachable": vpn_status == "active",
                "status": vpn_status,
                "percentUsage": random.randint(5, 85),
                "latency": round(random.uniform(5.0, 150.0), 1) if vpn_status == "active" else -1,
                "loss": round(random.uniform(0.0, 2.0), 2) if vpn_status == "active" else 100.0,
            })

        stats_entry["vpnPeers"] = peer_vpn_stats
        results.append(stats_entry)

    return results


def generate_vpn_statuses(state: TopologyState) -> list[dict]:
    results = []
    for peer in state.vpn_peers:
        device = state.get_device(peer.serial)
        if not device:
            continue

        entry = {
            "networkId": peer.network_id,
            "deviceSerial": peer.serial,
            "deviceName": device.name,
            "deviceStatus": device.status.value,
            "vpnMode": "auto",
            "exportedSubnets": [],
            "merakiVpnPeers": [],
            "thirdPartyVpnPeers": [],
        }

        for other_peer in state.vpn_peers:
            if other_peer.serial == peer.serial:
                continue
            other_device = state.get_device(other_peer.serial)
            if not other_device:
                continue

            reachable = (device.status != DeviceStatus.OFFLINE and
                        other_device.status != DeviceStatus.OFFLINE)

            entry["merakiVpnPeers"].append({
                "networkId": other_peer.network_id,
                "networkName": other_device.name,
                "reachable": reachable,
                "usingSdwan": True,
                "vpnMode": "auto",
                "publicIp": other_peer.public_ip,
            })

        results.append(entry)

    return results


def generate_top_clients_by_usage(state: TopologyState,
                                    top_count: int = 10) -> list[dict]:
    clients = list(state.clients.values())
    clients.sort(key=lambda c: c.sent + c.recv, reverse=True)

    results = []
    for client in clients[:top_count]:
        device = state.get_device(client.device_serial)
        results.append({
            "name": client.hostname,
            "mac": client.mac,
            "usage": {
                "total": client.sent + client.recv,
                "sent": client.sent,
                "recv": client.recv,
            },
            "ip": client.ip,
            "networkId": client.network_id,
            "networkName": state.get_network(client.network_id).name if state.get_network(client.network_id) else "",
            "serial": client.device_serial,
            "deviceName": device.name if device else "",
            "ssidName": "",
            "clientMac": client.mac,
        })

    return results


def generate_top_appliances_by_utilization(state: TopologyState,
                                             top_count: int = 10) -> list[dict]:
    mx_devices = state.get_devices_by_model_prefix("MX")
    results = []
    for device in mx_devices[:top_count]:
        utilization = random.randint(10, 85)
        if device.status == DeviceStatus.DEGRADED:
            utilization = random.randint(80, 99)

        results.append({
            "serial": device.serial,
            "name": device.name,
            "networkId": device.network_id,
            "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
            "utilization": utilization,
            "wanStatus": {
                "wan1": {
                    "status": "Connected",
                    "latency": round(random.uniform(5, 50), 1),
                    "lossPercent": round(random.uniform(0, 2), 2),
                }
            },
        })

    return results


def generate_top_switches_by_energy(state: TopologyState,
                                     top_count: int = 10) -> list[dict]:
    ms_devices = state.get_devices_by_model_prefix("MS")
    results = []
    for device in ms_devices[:top_count]:
        energy = round(random.uniform(50.0, 500.0), 1)
        results.append({
            "serial": device.serial,
            "name": device.name,
            "networkId": device.network_id,
            "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
            "energyUsage": energy,
            "poeUsage": round(energy * random.uniform(0.3, 0.7), 1),
        })

    return results


def generate_uplink_loss_latency(state: TopologyState) -> list[dict]:
    results = []
    for device in state.get_all_devices():
        if device.family not in (DeviceFamily.MX, DeviceFamily.MS, DeviceFamily.MR):
            continue
        if not device.uplink:
            continue

        latency = round(random.uniform(5.0, 30.0), 1)
        loss = round(random.uniform(0.0, 1.0), 2)

        if device.status == DeviceStatus.DEGRADED:
            latency = round(random.uniform(100.0, 500.0), 1)
            loss = round(random.uniform(5.0, 20.0), 2)
        elif device.status == DeviceStatus.OFFLINE:
            latency = -1
            loss = 100.0

        results.append({
            "serial": device.serial,
            "networkId": device.network_id,
            "ts": _ts_iso(),
            "wan1": {
                "latencyMs": latency,
                "lossPercent": loss,
                "ip": device.uplink.wan_ip or device.uplink.ip,
            },
        })

    return results


def generate_security_events(state: TopologyState,
                              per_page: int = 100) -> list[dict]:
    events = state.security_events[-per_page:]
    results = []
    for e in events:
        results.append({
            "ts": _ts_iso(e["ts"]),
            "eventId": e["eventId"],
            "eventType": e["eventType"],
            "srcIp": e["srcIp"],
            "srcPort": random.randint(1024, 65535),
            "destIp": e["destIp"],
            "destPort": e["port"],
            "protocol": e["protocol"],
            "count": e["count"],
            "deviceSerial": e["deviceSerial"],
        })
    return results


def generate_sensor_readings(state: TopologyState,
                              per_page: int = 100) -> list[dict]:
    readings = state.sensor_readings[-per_page:]
    results = []
    for r in readings:
        results.append({
            "ts": _ts_iso(r["ts"]),
            "serial": r["serial"],
            "networkId": r["networkId"],
            "temperature": {
                "celsius": r["temperature"],
                "fahrenheit": round(r["temperature"] * 9/5 + 32, 1),
            },
            "humidity": {
                "relativePercent": r["humidity"],
            },
        })

    mt_devices = state.get_devices_by_model_prefix("MT")
    for device in mt_devices:
        has_reading = any(r["serial"] == device.serial for r in readings)
        if not has_reading:
            temp = round(random.uniform(20.0, 26.0), 1)
            humidity = round(random.uniform(40.0, 60.0), 1)
            results.append({
                "ts": _ts_iso(),
                "serial": device.serial,
                "networkId": device.network_id,
                "temperature": {
                    "celsius": temp,
                    "fahrenheit": round(temp * 9/5 + 32, 1),
                },
                "humidity": {
                    "relativePercent": humidity,
                },
            })

    return results


def generate_air_marshal(state: TopologyState, network_id: str) -> dict:
    return {
        "settings": {
            "enabled": True,
            "policy": "quarantine",
        },
        "devices": [],
        "wirelessMacFilters": [],
        "observedAttacks": [],
    }


def generate_audit_logs(state: TopologyState) -> list[dict]:
    logs = state.audit_logs[-100:]
    results = []
    for log in logs:
        results.append({
            "ts": _ts_iso(log["ts"]),
            "adminName": log.get("adminName", "system"),
            "adminEmail": log.get("adminEmail", "system@acme.com"),
            "adminId": log.get("adminId", "admin_001"),
            "page": log.get("page", ""),
            "label": log.get("label", ""),
            "oldValue": log.get("oldValue", ""),
            "newValue": log.get("newValue", ""),
            "networkId": log.get("networkId", ""),
            "networkName": log.get("networkName", ""),
        })
    return results


def generate_firmware_upgrades(state: TopologyState) -> list[dict]:
    upgrades = state.firmware_upgrades[-50:]
    results = []
    for u in upgrades:
        results.append({
            "ts": _ts_iso(u["ts"]),
            "serial": u["serial"],
            "networkId": u["networkId"],
            "deviceName": u.get("deviceName", ""),
            "fromVersion": u["fromVersion"],
            "toVersion": u["toVersion"],
            "status": u.get("status", "completed"),
        })
    return results


def generate_api_requests(state: TopologyState) -> list[dict]:
    methods = ["GET", "POST", "PUT", "DELETE"]
    endpoints = [
        "/api/v1/organizations",
        "/api/v1/networks",
        "/api/v1/devices",
        "/api/v1/clients",
    ]
    results = []
    for _ in range(20):
        ts = time.time() - random.randint(0, 86400)
        results.append({
            "ts": _ts_iso(ts),
            "method": random.choice(methods),
            "host": "api.meraki.com",
            "url": random.choice(endpoints),
            "statusCode": random.choice([200, 200, 200, 200, 201, 400, 404]),
            "path": random.choice(endpoints),
            "adminName": "system",
            "adminEmail": "system@acme.com",
            "adminId": "admin_001",
        })
    return results


def generate_webhook_logs(state: TopologyState) -> list[dict]:
    logs = state.webhook_logs[-100:]
    results = []
    for log in logs:
        results.append({
            "id": log.get("id", ""),
            "url": log.get("url", ""),
            "status": log.get("status", "delivered"),
            "attemptedAt": _ts_iso(log.get("ts", time.time())),
            "respondedAt": _ts_iso(log.get("ts", time.time()) + 0.5),
            "responseCode": log.get("responseCode", 200),
            "responseBody": log.get("responseBody", ""),
        })
    return results


def generate_client_usage(state: TopologyState, network_id: str = None) -> list[dict]:
    clients = list(state.clients.values())
    if network_id:
        clients = [c for c in clients if c.network_id == network_id]

    results = []
    for client in clients:
        device = state.get_device(client.device_serial)
        results.append({
            "mac": client.mac,
            "description": client.description,
            "dhcpHostname": client.hostname,
            "ip": client.ip,
            "user": "",
            "vlan": client.vlan,
            "namedVlan": "",
            "networkId": client.network_id,
            "ssid": "",
            "usage": {
                "sent": client.sent,
                "recv": client.recv,
                "total": client.sent + client.recv,
            },
            "deviceSerial": client.device_serial,
            "deviceName": device.name if device else "",
            "deviceMac": device.mac if device else "",
            "mdnsName": client.hostname + ".local",
            # notes is a real Meraki client field — carries business context.
            "notes": client.business_function,
            "authorizations": [],
            "pskGroup": "",
            "groupPolicy8021x": "",
            "ip6": "",
            "ip6Local": "",
            "switchedAt": _ts_iso(client.last_seen),
            "lastSeen": _ts_iso(client.last_seen),
        })

    return results


def generate_device_statuses(state: TopologyState) -> dict:
    devices = state.get_all_devices()
    online = sum(1 for d in devices if d.status == DeviceStatus.ONLINE)
    offline = sum(1 for d in devices if d.status == DeviceStatus.OFFLINE)
    return {
        "counts": {
            "online": online,
            "offline": offline,
        },
        "deviceStatuses": [
            {
                "serial": d.serial,
                "status": d.status.value,
                "lastReportedAt": _ts_iso(d.last_seen),
                "productType": d.device_type,
            }
            for d in devices
        ],
    }


def generate_licenses(state: TopologyState) -> dict:
    total_devices = len(state.get_all_devices())
    return {
        "coTermLicenses": [
            {
                "id": "LIC_001",
                "@type": "coTermLicense",
                "counts": {
                    "devices": total_devices,
                },
                "claimKey": "XXXX-YYYY-ZZZZ",
                "mode": "coTerm",
                "expirationDate": "2028-12-31T23:59:59Z",
                "status": "active",
            }
        ],
        "subscriptionEntitlements": [],
        "totalLicenses": {
            "seats": total_devices,
            "seatsInUse": total_devices,
        },
        "coTermLicenseOverview": {
            "status": "OK",
            "deviceCount": total_devices,
            "expirationDate": "2028-12-31T23:59:59Z",
        },
    }
