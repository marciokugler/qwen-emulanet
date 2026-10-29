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
import zlib
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
# Port field helpers — values must match the documented Meraki enums exactly.
# Splunk NI lowercases and string-matches these, so a near-miss silently
# degrades to "unknown" instead of surfacing as a fault.
# ---------------------------------------------------------------------------
def port_status_str(port) -> str:
    """Meraki enum: Connected | Disabled | Disconnected."""
    if not port.enabled:
        return "Disabled"
    return "Connected" if port.is_up else "Disconnected"


def port_speed_str(port) -> str:
    """Meraki enum: "" | "1 Gbps" | "10 Gbps" | ... (a string, never an int).

    NI parses this with match(lower(speed), "^[0-9.]+ gbps$"), so an integer
    such as 10000 yields a null speed_bps.
    """
    if not port.is_up:
        return ""
    # SFP+ uplinks on the 48-port MS350 models are ports 49/50.
    if port.number.isdigit() and int(port.number) >= 49:
        return "10 Gbps"
    return "1 Gbps"


def _port_status_object(port) -> dict:
    """The port object shared by both status endpoints.

    errors[] and warnings[] drive NI's grading: actionable_error_count>0 is
    "critical", warning_count>0 is "degraded". NI filters out the strings
    "port disconnected" and "port disabled", so those alone never raise a fault.
    """
    errors = list(port.errors)
    if not port.is_up and port.enabled:
        errors.append("Port disconnected")

    return {
        "portId": port.number,
        "enabled": port.enabled,
        "status": port_status_str(port),
        "isUplink": port.type == "trunk",
        "errors": errors,
        "warnings": list(port.warnings),
        "speed": port_speed_str(port),
        "duplex": "full" if port.is_up else "",
        "spanningTree": {
            "statuses": ["Forwarding"] if port.is_up and port.rstp_enabled else [],
        },
        "poe": {"isAllocated": bool(port.poe_enabled and port.is_up)},
        "securePort": {
            "active": False,
            "authenticationStatus": "Disabled",
        },
    }


def generate_switch_port_statuses(state: TopologyState, serial: str) -> list[dict]:
    """GET /devices/{serial}/switch/ports/statuses — bare array of ports."""
    device = state.get_device(serial)
    if not device or device.family != DeviceFamily.MS:
        return []

    results = []
    for port in device.ports:
        entry = _port_status_object(port)
        # Per-device extras this endpoint adds over the bySwitch variant.
        entry.update({
            "macWhitelist": [],
            "tags": port.tags,
            "portScheduleId": port.port_schedule_id,
            "clientCount": port.client_count if port.is_up else 0,
            "usageInKb": {
                "total": _deterministic_usage(device.serial, port.number, 5_000_000),
                "sent": _deterministic_usage(device.serial, port.number, 2_500_000),
                "recv": _deterministic_usage(device.serial, port.number, 2_500_000),
            },
            "powerUsageInWh": round(6.5 + _deterministic_usage(device.serial, port.number, 200) / 20, 2)
                              if port.poe_enabled and port.is_up else 0.0,
            "clientMacList": [],
            # Business context: what is actually cabled into this port.
            "connectedDeviceSerial": port.connected_serial or "",
            "vlan": port.vlan,
        })
        results.append(entry)

    return results


def generate_switch_port_statuses_by_switch(state: TopologyState,
                                            per_page: int = 1000) -> dict:
    """GET /organizations/{orgId}/switch/ports/statuses/bySwitch

    Enveloped, one record per switch with a nested ports[] array. Feeds NI's
    meraki.interface_status capability (endpoint_name=switch_ports_statuses_by_switch).
    """
    items = []
    for device in state.get_devices_by_model_prefix("MS"):
        network = state.get_network(device.network_id)
        items.append({
            "name": device.name,
            "serial": device.serial,
            "mac": device.mac,
            "network": {
                "name": network.name if network else "",
                "id": device.network_id,
            },
            "model": device.model,
            "ports": [_port_status_object(p) for p in device.ports],
        })

    return {
        "items": items[:per_page],
        "meta": {"counts": {"items": {
            "total": len(items),
            "remaining": max(0, len(items) - per_page),
        }}},
    }


def generate_switch_ports_by_switch(state: TopologyState) -> list[dict]:
    """GET /organizations/{orgId}/switch/ports/bySwitch — bare array.

    Feeds NI's meraki.switchportsbyswitch graph adapter, which parents each
    interface vertex to a device via lower(replace(trim(mac),"-",":")) and to a
    site via coalesce('network.id', networkId). The per-switch mac and
    network.id are therefore load-bearing, not decorative.
    """
    results = []
    for device in state.get_devices_by_model_prefix("MS"):
        network = state.get_network(device.network_id)
        ports = []
        for port in device.ports:
            ports.append({
                "portId": port.number,
                "name": port.name or None,
                "tags": port.tags,
                "enabled": port.enabled,
                "poeEnabled": port.poe_enabled,
                "perpetualPoe": {"enabled": False},
                "fastPoe": {"enabled": False},
                "type": port.type,
                "vlan": port.vlan if port.type == "access" else 1,
                "voiceVlan": 20 if port.vlan == 10 else None,
                "allowedVlans": "all" if port.type == "trunk" else str(port.vlan),
                "rstpEnabled": port.rstp_enabled,
                "stpGuard": port.stp_guard,
                "linkNegotiation": port.link_negotiation,
                "accessPolicyType": "MAC allow list" if port.vlan == 30 else "Open",
            })
            # POS ports are locked to an allow list — PCI DSS requirement 1.
            if port.vlan == 30:
                ports[-1]["stickyMacAllowList"] = []
                ports[-1]["stickyMacAllowListLimit"] = 4

        results.append({
            "name": device.name,
            "serial": device.serial,
            "mac": device.mac,
            "network": {
                "name": network.name if network else "",
                "id": device.network_id,
            },
            "model": device.model,
            "ports": ports,
        })

    return results


def generate_switch_ports_usage_history(state: TopologyState,
                                        timespan: int = 1200,
                                        per_page: int = 1000) -> dict:
    """GET /organizations/{orgId}/switch/ports/usage/history/byDevice/byInterval

    Enveloped. Feeds NI's meraki.interface_throughput and meraki.interface_power.
    data.usage is kilobytes (int), bandwidth.usage is kilobits/sec (float),
    energy.usage is watt-hours (float).
    """
    now = int(time.time())
    start = now - timespan

    items = []
    for device in state.get_devices_by_model_prefix("MS"):
        network = state.get_network(device.network_id)
        ports = []
        for port in device.ports:
            if not port.is_up:
                continue
            total_kb = _deterministic_usage(device.serial, port.number, 4_000_000)
            up_kb = total_kb // 2
            down_kb = total_kb - up_kb
            seconds = max(timespan, 1)
            ports.append({
                "portId": port.number,
                "intervals": [{
                    "startTs": _ts_iso(start),
                    "endTs": _ts_iso(now),
                    "data": {"usage": {
                        "total": total_kb,
                        "upstream": up_kb,
                        "downstream": down_kb,
                    }},
                    "bandwidth": {"usage": {
                        # kilobytes over the interval -> average kilobits/sec
                        "total": round(total_kb * 8 / seconds, 2),
                        "upstream": round(up_kb * 8 / seconds, 2),
                        "downstream": round(down_kb * 8 / seconds, 2),
                    }},
                    "energy": {"usage": {
                        "total": round(6.5 + _deterministic_usage(
                            device.serial, port.number, 200) / 20, 2)
                        if port.poe_enabled else 0.0,
                    }},
                }],
            })

        items.append({
            "name": device.name,
            "serial": device.serial,
            "mac": device.mac,
            "network": {
                "name": network.name if network else "",
                "id": device.network_id,
            },
            "model": device.model,
            "ports": ports,
        })

    return {
        "items": items[:per_page],
        "meta": {"counts": {"items": {
            "total": len(items),
            "remaining": max(0, len(items) - per_page),
        }}},
    }


def generate_uplink_addresses_by_device(state: TopologyState) -> list[dict]:
    """GET /organizations/{orgId}/devices/uplinks/addresses/byDevice — bare array.

    Feeds NI's meraki.devicesuplinksaddressesbydevice adapter, which creates WAN
    and management interface vertices parented by mac. The interface value must
    come from the documented enum: wan1, wan2, man1, man2, cellular.
    """
    results = []
    for device in state.get_all_devices():
        if not device.uplink:
            continue

        addresses = [{
            "protocol": "ipv4",
            "assignmentMode": "static",
            "address": device.uplink.wan_ip or device.uplink.ip,
            "gateway": device.uplink.gateway or "",
            "nameservers": {"addresses": ["8.8.8.8", "1.1.1.1"]},
            "public": {"address": device.uplink.public_ip or device.uplink.wan_ip},
            "vlan": {"id": "99"},
        }]

        results.append({
            "mac": device.mac,
            "name": device.name,
            "network": {"id": device.network_id},
            "productType": device.device_type,
            "serial": device.serial,
            "tags": device.tags,
            "uplinks": [{
                "interface": "wan1",
                "addresses": addresses,
            }],
        })

    return results


def generate_uplinks_loss_and_latency(state: TopologyState,
                                      timespan: int = 3600) -> list[dict]:
    """GET /organizations/{orgId}/devices/uplinksLossAndLatency — bare array.

    Note the path has no slash before "Loss". Feeds NI's
    meraki.interface_uplink_quality, which expands timeSeries{} and grades
    critical at loss>=20 or latency>=300, degraded at loss>=5 or latency>=150.
    """
    now = int(time.time())
    results = []

    for device in state.get_all_devices():
        if not device.uplink:
            continue

        # Sample every 5 minutes across the window, capped for payload size.
        step = 300
        points = max(1, min(timespan // step, 24))
        series = []
        for i in range(points):
            ts = now - (points - 1 - i) * step
            loss, latency = _uplink_sample(device, ts)
            series.append({
                "ts": _ts_iso(ts),
                "lossPercent": loss,
                "latencyMs": latency,
            })

        results.append({
            "networkId": device.network_id,
            "serial": device.serial,
            "uplink": "wan1",
            "ip": device.uplink.wan_ip or device.uplink.ip,
            "timeSeries": series,
        })

    return results


def _uplink_sample(device: Device, ts: int) -> tuple[float, float]:
    """Loss/latency for one sample, honouring the device's current health."""
    if device.status == DeviceStatus.OFFLINE:
        return 100.0, 0.0
    if device.status == DeviceStatus.DEGRADED:
        # Cross NI's critical threshold (loss>=20 or latency>=300) so the
        # scenario actually surfaces as a fault rather than "ok".
        return round(device.uplink.loss_percent, 2), round(device.uplink.latency_ms, 1)

    # Healthy links jitter slightly but stay well inside the "ok" band.
    jitter = (zlib.crc32(f"{device.serial}:{ts}".encode()) % 100) / 100.0
    return round(min(device.uplink.loss_percent, 0.4) * jitter, 2), \
        round(device.uplink.latency_ms * (0.9 + 0.2 * jitter), 1)


def _deterministic_usage(serial: str, port: str, modulus: int) -> int:
    """Stable pseudo-random usage so repeated polls do not jitter wildly.

    Uses crc32 rather than the builtin hash(), which is salted per process and
    would reshuffle every port's counters on each emulator restart.
    """
    if not modulus:
        return 0
    return zlib.crc32(f"{serial}:{port}".encode()) % modulus


# ---------------------------------------------------------------------------
# Organization OpenAPI document — GET /organizations/{orgId}/openapiSpec
#
# The Splunk Meraki add-on is catalog-constrained: it will only poll endpoints
# from its bundled SDK catalog, or ones it discovers from this document. The
# two topology endpoints NI needs are not in the bundled catalog, so they must
# appear here or they can never be selected in the add-on UI.
#
# Discovery rules enforced by the add-on (cisco_meraki_catalog_refresh.py):
#   - path under /organizations/{organizationId}, organizationId the ONLY placeholder
#   - operationId starts with "get", <= 256 chars
#   - tags are strings, none in the blocked set
#   - no requestBody
#   - a 2xx/default response declaring application/json
#   - query param names match [A-Za-z][A-Za-z0-9_]*, type in
#     {string, integer, number, boolean}
#   - "perPage" present => paginated=True, which routes collection through
#     _page_items() and unwraps the {"items": [...]} envelope. Without it the
#     collector emits one event holding the whole envelope and NI finds no edges.
# ---------------------------------------------------------------------------
_ORG_ID_PARAM = {
    "name": "organizationId",
    "in": "path",
    "required": True,
    "description": "Organization ID",
    "schema": {"type": "string"},
}

_PER_PAGE_PARAM = {
    "name": "perPage",
    "in": "query",
    "required": False,
    "description": "The number of entries per page returned.",
    "schema": {"type": "integer", "minimum": 3, "maximum": 1000},
}

_STARTING_AFTER_PARAM = {
    "name": "startingAfter",
    "in": "query",
    "required": False,
    "description": "A token used by pagination indexes for subsequent queries.",
    "schema": {"type": "string"},
}

_ENDING_BEFORE_PARAM = {
    "name": "endingBefore",
    "in": "query",
    "required": False,
    "description": "A token used by pagination indexes for preceding queries.",
    "schema": {"type": "string"},
}

# operationId -> endpoint_name after the add-on strips "getOrganization" and
# snake_cases the remainder. These two strings are exactly what NI's props.conf
# matches on to build connected_to edges.
_DISCOVERABLE_OPERATIONS = [
    {
        "path": "/organizations/{organizationId}/devices/topology/nodes/discovered",
        "operationId": "getOrganizationDevicesTopologyNodesDiscovered",
        "summary": ("List topology nodes discovered by LLDP/CDP from devices in "
                    "an organization, including reported metadata when available"),
        "tags": ["devices", "monitor", "topology"],
    },
    {
        "path": "/organizations/{organizationId}/devices/topology/l2/links",
        "operationId": "getOrganizationDevicesTopologyL2Links",
        "summary": "List layer 2 topology links originating from devices in an organization",
        "tags": ["devices", "monitor", "topology"],
    },
]


def _json_response(description: str) -> dict:
    return {
        "description": description,
        "content": {"application/json": {"schema": {"type": "object"}}},
    }


def generate_openapi_spec(state: TopologyState) -> dict:
    """Build the organization OpenAPI document served to the add-on."""
    paths: dict[str, dict] = {}

    for op in _DISCOVERABLE_OPERATIONS:
        paths[op["path"]] = {
            "get": {
                "operationId": op["operationId"],
                "summary": op["summary"],
                "description": op["summary"],
                "tags": list(op["tags"]),
                "parameters": [
                    _ORG_ID_PARAM,
                    _PER_PAGE_PARAM,
                    _STARTING_AFTER_PARAM,
                    _ENDING_BEFORE_PARAM,
                ],
                "responses": {
                    "200": _json_response("Successful operation"),
                    "400": _json_response("Bad request"),
                    "401": _json_response("Unauthorized"),
                    "429": _json_response("Too many requests"),
                },
            }
        }

    return {
        "openapi": "3.0.1",
        "info": {
            "title": "Meraki Dashboard API",
            "description": "Cisco Meraki Dashboard API v1 (emulated)",
            "version": "1.53.0",
            "contact": {"name": "Cisco Meraki", "url": "https://developer.cisco.com/meraki"},
            "license": {"name": "Cisco End User License Agreement",
                        "url": "https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html"},
        },
        "servers": [{"url": "/api/v1", "description": "Meraki Dashboard API"}],
        "security": [{"bearerAuth": []}, {"apiKeyAuth": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "apiKeyAuth": {"type": "apiKey", "in": "header",
                               "name": "X-Cisco-Meraki-API-Key"},
            },
        },
    }


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
