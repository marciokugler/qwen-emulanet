"""Topology generators.

These produce the exact response shapes Splunk Network Intelligence consumes to
build its topology graph. Per Splunk's docs, NI does not discover anything
itself — it normalizes what the Meraki add-on ingests from:
  - meraki:custom -> devices_topology_nodes_discovered   (graph nodes)
  - meraki:custom -> devices_topology_l2_links           (graph links)
  - switch_ports_statuses_by_switch                      (port state)
Schemas verified against developer.cisco.com/meraki/api-v1.
"""

from __future__ import annotations

import time
from typing import Optional

from src.topology.models import (
    TopologyState, Device, DeviceFamily, DeviceStatus, Link,
)

# Meraki system descriptions as they appear in LLDP advertisements.
SYSTEM_DESCRIPTIONS = {
    "MX": "Meraki MX Cloud Managed Security Appliance",
    "MS": "Meraki MS Cloud Managed Switch",
    "MR": "Meraki MR Cloud Managed Access Point",
    "MV": "Meraki MV Cloud Managed Camera",
    "MT": "Meraki MT Cloud Managed Sensor",
}

LLDP_CAPABILITIES = {
    "mx": "Router",
    "ms": "S-VLAN Component of a VLAN Bridge",
    "mr": "WLAN Access Point",
    "mv": "Station Only",
    "mt": "Station Only",
}

CDP_CAPABILITIES = {
    "mx": "Router",
    "ms": "Switch",
    "mr": "WLAN Access Point",
    "mv": "Host",
    "mt": "Host",
}


def _ts_iso(ts: float = None) -> str:
    if ts is None:
        ts = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))


def _derived_id(mac: str) -> str:
    """Meraki derivedId is the MAC in Cisco dotted-hex form: a03d.6f98.e26e."""
    hex_digits = mac.replace(":", "").lower()
    return ".".join(hex_digits[i:i + 4] for i in range(0, 12, 4))


def _system_description(device: Device) -> str:
    # DeviceFamily.value is lowercase ("ms"); SYSTEM_DESCRIPTIONS is keyed uppercase.
    return SYSTEM_DESCRIPTIONS.get(device.family.value.upper(),
                                   "Meraki Cloud Managed Device")


def _port_description(device: Device, port_id: str) -> str:
    if device.family == DeviceFamily.MS:
        if port_id.isdigit() and int(port_id) >= 49:
            return f"TenGigabitEthernet1/0/{int(port_id) - 48}"
        return f"GigabitEthernet1/0/{port_id}"
    if device.family == DeviceFamily.MX:
        return port_id.replace("internet", "WAN").replace("port", "LAN").strip()
    return port_id


def _management_vlan(device: Device) -> int:
    """Management VLAN per the site taxonomy — 99 for Management."""
    return 99


def _neighbors(state: TopologyState, serial: str) -> list[tuple[Link, Device, str, str]]:
    """Return (link, peer_device, local_port, peer_port) for a device."""
    device = state.get_device(serial)
    if not device:
        return []

    out = []
    for link in state.get_links_for_device(serial):
        if link.source_serial == serial:
            peer_serial, local_port, peer_port = link.target_serial, link.source_port, link.target_port
        else:
            peer_serial, local_port, peer_port = link.source_serial, link.target_port, link.source_port

        peer = state.get_device(peer_serial)
        if peer:
            out.append((link, peer, local_port, peer_port))
    return out


# ---------------------------------------------------------------------------
# GET /devices/{serial}/lldpCdp
# ---------------------------------------------------------------------------
def generate_device_lldp_cdp(state: TopologyState, serial: str) -> dict:
    device = state.get_device(serial)
    if not device:
        return {"sourceMac": "", "ports": {}}

    ports: dict = {}
    for link, peer, local_port, peer_port in _neighbors(state, serial):
        if not link.is_up:
            continue

        peer_family = peer.family.value
        ports[local_port] = {
            "lldp": {
                "systemName": peer.name,
                "systemDescription": _system_description(peer),
                "portId": peer_port,
                "chassisId": peer.mac,
                "managementVlan": _management_vlan(peer),
                "portVlan": link.vlan or _management_vlan(peer),
                "managementAddress": peer.lan_ip or "",
                "portDescription": _port_description(peer, peer_port),
                "systemCapabilities": LLDP_CAPABILITIES.get(peer_family, "Station Only"),
                "sourcePort": local_port,
            },
            "cdp": {
                "platform": peer.model,
                "deviceId": peer.name,
                "model": f"cisco {peer.model}",
                "version": peer.get_firmware(),
                "portId": f"Port {peer_port}" if peer_port.isdigit() else peer_port,
                "nativeVlan": 1 if link.is_trunk else (link.vlan or 1),
                "vtpManagementDomain": "northwind",
                "capabilities": CDP_CAPABILITIES.get(peer_family, "Host"),
                "address": peer.lan_ip or "",
                "sourcePort": local_port,
            },
            "deviceMac": peer.mac,
            "device": {
                "url": f"https://n43.meraki.com/{peer.network_id}/manage/nodes/{peer.serial}",
            },
        }

    return {"sourceMac": device.mac, "ports": ports}


# ---------------------------------------------------------------------------
# GET /organizations/{orgId}/devices/topology/nodes/discovered
# ---------------------------------------------------------------------------
def generate_topology_nodes_discovered(state: TopologyState, per_page: int = 1000) -> dict:
    items = []
    errors = []

    for link in state.get_all_links():
        source = state.get_device(link.source_serial)
        target = state.get_device(link.target_serial)
        if not source or not target:
            continue

        if not link.is_up:
            continue

        # LLDP discovery is bidirectional: each end reports the other as a
        # neighbour. Emitting only downstream would drop the gateway from the
        # graph and leave Splunk NI unable to reach it from the switch side.
        for reporter, peer, local_port, peer_port in (
            (source, target, link.source_port, link.target_port),
            (target, source, link.target_port, link.source_port),
        ):
            if reporter.status == DeviceStatus.OFFLINE:
                errors.append({
                    "type": "deviceUnreachable",
                    "message": f"Device {reporter.serial} could not be queried.",
                })
                continue

            items.append({
                "protocol": "LLDP" if peer.family in (DeviceFamily.MS, DeviceFamily.MX) else "CDP",
                "reporter": {
                    "id": reporter.serial,
                    "interface": {
                        "id": local_port,
                        "status": "connected",
                    },
                },
                "discovered": {
                    "derivedId": _derived_id(peer.mac),
                    "system": {
                        "name": peer.name,
                        "description": _system_description(peer),
                        "platform": peer.model,
                        "capabilities": _capability_list(peer),
                    },
                    "chassis": {"id": peer.mac},
                    "port": {"id": peer_port},
                    "mac": peer.mac,
                    "addresses": [a for a in [peer.lan_ip, peer.public_ip] if a],
                },
            })

    # Deduplicate: a device pair can share more than one physical link.
    seen = set()
    unique = []
    for item in items:
        key = (item["reporter"]["id"], item["reporter"]["interface"]["id"],
               item["discovered"]["derivedId"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    # Error list can contain duplicates when a device has several links down.
    unique_errors = []
    seen_errors = set()
    for err in errors:
        if err["message"] not in seen_errors:
            seen_errors.add(err["message"])
            unique_errors.append(err)

    return {
        "items": unique[:per_page],
        "meta": {"counts": {"items": {"total": len(unique),
                                      "remaining": max(0, len(unique) - per_page)}}},
        "errors": unique_errors[:20],
    }


def _capability_list(device: Device) -> list[str]:
    """Lowercase capability values, per the API enum."""
    family = device.family.value
    if family == "mx":
        return ["router"]
    if family == "ms":
        return ["switch", "mac bridge", "s-vlan component of a vlan bridge"]
    if family == "mr":
        return ["wlan access point"]
    return ["station only"]


# ---------------------------------------------------------------------------
# GET /organizations/{orgId}/devices/topology/l2/links
# ---------------------------------------------------------------------------
def generate_topology_l2_links(state: TopologyState, per_page: int = 1000) -> dict:
    items = []
    errors = []

    for link in state.get_all_links():
        source = state.get_device(link.source_serial)
        target = state.get_device(link.target_serial)
        if not source or not target:
            continue

        if source.status == DeviceStatus.OFFLINE and target.status == DeviceStatus.OFFLINE:
            errors.append({
                "type": "deviceUnreachable",
                "message": f"Device {link.source_serial} could not be queried.",
            })
            continue

        items.append({
            "linkId": link.link_id,
            "isStpDisabled": link.is_stp_disabled,
            "site": {"resource": {"id": link.network_id, "type": "network"}},
            "source": {
                "device": {
                    "id": link.source_serial,
                    "port": {"id": link.source_port},
                }
            },
            "target": {
                "device": {
                    "id": link.target_serial,
                    "port": {"id": link.target_port},
                }
            },
        })

    return {
        "items": items[:per_page],
        "meta": {"counts": {"items": {"total": len(items), "remaining": max(0, len(items) - per_page)}}},
        "errors": errors[:20],
    }


# ---------------------------------------------------------------------------
# GET /networks/{networkId}/topology/linkLayer
# ---------------------------------------------------------------------------
def generate_link_layer_topology(state: TopologyState, network_id: str) -> dict:
    network = state.get_network(network_id)
    if not network:
        return {"nodes": [], "links": [], "errors": []}

    # Requires at least one MX or MS in the network.
    has_infra = any(d.family in (DeviceFamily.MX, DeviceFamily.MS) for d in network.devices)
    if not has_infra:
        return {"nodes": [], "links": [], "errors": []}

    links = state.get_links_by_network(network_id)
    root_serial = _find_root(network.devices)

    nodes = []
    for device in network.devices:
        client_count = sum(1 for c in state.clients.values()
                           if c.device_serial == device.serial)

        node = {
            "derivedId": _derived_id(device.mac),
            "mac": device.mac,
            "type": "device",
            "root": device.serial == root_serial,
            "device": {
                "serial": device.serial,
                "name": device.name,
                "model": device.model,
                "productType": device.device_type,
                "status": device.status.value,
                "lastReportedAt": _ts_iso(device.last_seen),
                "clients": {"counts": {"total": client_count}},
                "uplinks": [{"vlanId": _uplink_vlan(state, device)}],
            },
        }
        nodes.append(node)

    out_links = []
    for link in links:
        source = state.get_device(link.source_serial)
        target = state.get_device(link.target_serial)
        if not source or not target:
            continue

        out_links.append({
            "ends": [
                {
                    "node": {"derivedId": _derived_id(source.mac), "type": "device"},
                    "device": {"serial": source.serial, "name": source.name},
                    "discovered": {
                        "lldp": {
                            "portId": link.source_port,
                            "portDescription": _port_description(source, link.source_port),
                        },
                        "cdp": {
                            "portId": link.source_port,
                            "nativeVlan": 1 if link.is_trunk else (link.vlan or 1),
                        },
                    },
                },
                {
                    "node": {"derivedId": _derived_id(target.mac), "type": "device"},
                    "device": {"serial": target.serial, "name": target.name},
                    "discovered": {
                        "lldp": {
                            "portId": link.target_port,
                            "portDescription": _port_description(target, link.target_port),
                        },
                        "cdp": {
                            "portId": link.target_port,
                            "nativeVlan": 1 if link.is_trunk else (link.vlan or 1),
                        },
                    },
                },
            ],
            "lastReportedAt": _ts_iso(link.last_reported_at),
        })

    errors = []
    offline = [d.serial for d in network.devices if d.status == DeviceStatus.OFFLINE]
    if offline:
        errors.append(f"Topology may be incomplete: {len(offline)} device(s) unreachable.")

    return {"nodes": nodes, "links": out_links, "errors": errors}


def _find_root(devices: list[Device]) -> Optional[str]:
    """The topology root is the SD-WAN gateway (hub preferred)."""
    for device in devices:
        if device.family == DeviceFamily.MX and "sdwan-hub" in device.tags:
            return device.serial
    for device in devices:
        if device.family == DeviceFamily.MX and "ha-primary" in device.tags:
            return device.serial
    for device in devices:
        if device.family == DeviceFamily.MX:
            return device.serial
    return devices[0].serial if devices else None


def _uplink_vlan(state: TopologyState, device: Device) -> int:
    """Management VLAN carried on the device's uplink."""
    if device.family in (DeviceFamily.MX, DeviceFamily.MS):
        return 99
    for link in state.get_links_for_device(device.serial):
        if link.vlan:
            return link.vlan
    return 1


# ---------------------------------------------------------------------------
# Switch port statuses — feeds switch_ports_statuses_by_switch
# ---------------------------------------------------------------------------
def generate_switch_port_statuses(state: TopologyState, serial: str) -> list[dict]:
    device = state.get_device(serial)
    if not device or device.family != DeviceFamily.MS:
        return []

    results = []
    for port in device.ports:
        results.append({
            "portId": port.number,
            "enabled": port.enabled and port.is_up,
            "status": "Connected" if port.is_up and port.enabled else "Not connected",
            "isUplink": port.type == "trunk",
            "speed": 10000 if port.number.isdigit() and int(port.number) >= 49 else
                     (1000 if port.is_up else 0),
            "duplex": "full" if port.is_up else "none",
            "macWhitelist": [],
            "tags": port.tags,
            "portScheduleId": "",
            "clientCount": port.client_count if port.is_up else 0,
            "usageInKb": {
                "total": _deterministic_usage(device.serial, port.number, 5_000_000),
                "sent": _deterministic_usage(device.serial, port.number, 2_500_000),
                "recv": _deterministic_usage(device.serial, port.number, 2_500_000),
            },
            "powerUsageInWh": round(6.5 + _deterministic_usage(device.serial, port.number, 200) / 20, 2)
                              if port.poe_enabled and port.is_up else 0.0,
            "securePort": {"enabled": False},
            "clientMacList": [],
            # Business context: what is actually cabled into this port.
            "connectedDeviceSerial": port.connected_serial or "",
            "vlan": port.vlan,
        })

    return results


def _deterministic_usage(serial: str, port: str, modulus: int) -> int:
    """Stable pseudo-random usage so repeated polls do not jitter wildly."""
    return (hash(f"{serial}:{port}") % modulus) if modulus else 0


# ---------------------------------------------------------------------------
# VLANs and SSIDs — where retail business function is actually expressed
# ---------------------------------------------------------------------------
def generate_vlans(state: TopologyState, network_id: str) -> list[dict]:
    network = state.get_network(network_id)
    if not network:
        return []

    return [
        {
            "id": str(vlan.id),
            "name": vlan.name,
            "subnet": vlan.subnet,
            "applianceIp": vlan.appliance_ip,
            "dhcpHandling": vlan.dhcp_handling,
            "dhcpLeaseTime": "1 day",
            "mandatoryDhcpEnabled": vlan.id in (30, 60, 70),
            "fixedIpAssignments": {},
            "reservedIpRanges": [],
            "vpnNatSubnet": vlan.subnet,
            "templateVlanType": "same",
            # Business purpose surfaced for Splunk correlation.
            "description": vlan.purpose,
        }
        for vlan in network.vlans
    ]


def generate_ssids(state: TopologyState, network_id: str) -> list[dict]:
    network = state.get_network(network_id)
    if not network:
        return []

    results = []
    for ssid in network.ssids:
        entry = {
            "number": ssid.number,
            "name": ssid.name,
            "enabled": ssid.enabled,
            "visible": ssid.visible,
            "vlanId": ssid.vlan_id,
            "defaultVlanId": ssid.vlan_id,
            "availableOnAllAps": True,
            "bandSelection": "5 GHz band only" if ssid.number != 1 else "Dual band operation",
            "minBitrate": 12,
            "ipAssignmentMode": "Bridge mode",
            "useVlanTagging": True,
            "adminSplashAccess": False,
            "authMode": ssid.auth_mode,
        }

        if ssid.auth_mode == "open-with-splash":
            entry["splashPage"] = {
                "splashAccessType": "Click-through",
                "useSplashUrl": False,
                "splashTimeout": 1440,
                "splashImageUrl": "",
                "welcomeMessage": "Welcome to Northwind Retail — free customer WiFi",
                "theme": "northwind-guest",
            }
        elif ssid.auth_mode == "802.1x-radius":
            entry["enterpriseAdminAccess"] = "access enabled"
            entry["radiusServers"] = [{"host": "10.10.99.5", "port": 1812}]
        else:
            entry["encryptionMode"] = "wpa"
            entry["wpaEncryptionMode"] = "WPA3 Transition Mode"

        results.append(entry)

    return results
