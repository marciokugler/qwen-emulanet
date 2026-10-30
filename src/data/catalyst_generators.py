"""Catalyst Center (DNAC) API response generators.

Every function returns the exact shape the Cisco Catalyst add-on reads, with
the field names the *controller* uses — the add-on renames them to the
PascalCase event fields Splunk NI consumes, and that renaming is not something
this emulator controls. The authoritative mapping is in the local-only
`notes/catalyst-addon-contract.md`.

Three rules dominate everything here, all of them invisible when broken:

1. **The inventory is immutable.** The add-on brackets each poll with
   `/network-device/count` and aborts the entire collection if the count moves
   (Interface Statistics has zero tolerance). So `lastUpdateTime` is fixed at
   load time rather than refreshed per request, and no scenario may add or
   remove a device.
2. **Counts must agree with rows.** `totalCount` on device-health and on the
   per-device interface query, and `page.count` on assuranceIssues, are
   validated against the actual row count. An over-count makes the collector
   ask for a page that never arrives and then discard everything it already
   had.
3. **One object, not a list.** Physical topology must return `response` as a
   JSON object. The add-on wraps a list body into one event per element, which
   would hand NI a fragment per event and silently produce no edges.
"""

from __future__ import annotations

import random
import time
from typing import Optional

from src.topology.catalyst_models import (
    CatalystDevice, CatalystInterface, CatalystTopologyState, CatalystSite,
    InterfaceOperStatus, Reachability, SiteType,
)

# NI's availability binding grades a device online only when Manageability is
# "managed". The add-on derives that from managementState + collectionStatus:
# "Managed" with collectionStatus absent or "Managed" yields "Managed"; any
# other collectionStatus degrades it to "Managed (With Errors)".
_MANAGEMENT_STATE = "Managed"
_COLLECTION_STATUS = "Managed"

# Platform prefix -> DNAC `series` string.
_SERIES = [
    ("C9500", "Cisco Catalyst 9500 Series Switches"),
    ("C9300", "Cisco Catalyst 9300 Series Switches"),
    ("C9800", "Cisco Catalyst 9800 Series Wireless Controllers"),
    ("C9120", "Cisco Catalyst 9120 Series Access Points"),
    ("IE3400", "Cisco IE3400 Series Industrial Ethernet Switches"),
    ("ISR4431", "Cisco ISR 4400 Series Routers"),
    ("ISR4331", "Cisco ISR 4300 Series Routers"),
    ("ISR4321", "Cisco ISR 4300 Series Routers"),
    ("MS350", "Cisco Meraki MS350 Series Switches"),
    ("MS250", "Cisco Meraki MS250 Series Switches"),
]

_SOFTWARE_TYPE = {
    "Switches and Hubs": "IOS-XE",
    "Routers": "IOS-XE",
    "Wireless Controller": "IOS-XE",
    "Unified AP": "AP-COS",
}

_WIRELESS_FAMILIES = ("Unified AP", "Wireless Controller")


def _series_for(platform_id: str) -> str:
    for prefix, series in _SERIES:
        if platform_id.startswith(prefix):
            return series
    return "Cisco Catalyst Series"


def _device_type_for(device: CatalystDevice) -> str:
    """DNAC's `type` field: a descriptive model string, not the family."""
    if device.family == "Unified AP":
        return "Cisco Catalyst 9120AXI Unified Access Point"
    if device.family == "Wireless Controller":
        return "Cisco Catalyst 9800-80 Wireless Controller"
    if device.family == "Routers":
        return f"Cisco {device.platform_id.split('/')[0]} Router"
    if device.platform_id.startswith("MS"):
        return f"Meraki {device.platform_id} Cloud Managed Switch"
    if device.platform_id.startswith("IE"):
        return "Cisco IE3400 Industrial Ethernet Switch"
    return f"Cisco Catalyst {device.platform_id.split('-')[0]} Series Switch"


def _format_uptime(uptime_ms: int) -> str:
    """DNAC renders uptime as '<days> days, <H>:<M>:<S>.<nanoseconds>'."""
    if uptime_ms <= 0:
        return ""
    total = uptime_ms // 1000
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days} days, {hours}:{minutes:02d}:{seconds:02d}.000000000"
    return f"{hours}:{minutes:02d}:{seconds:02d}.000000000"


# ---------------------------------------------------------------------------
# Version probe
# ---------------------------------------------------------------------------

def generate_dnac_release(state: CatalystTopologyState) -> dict:
    """`GET /dna/intent/api/v1/dnac-release`.

    Non-fatal if wrong, but the version probe runs on every input and a missing
    version just degrades the log metadata, so answer it properly. The value
    must match `^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$` or it is discarded.
    """
    release = state.controller.get("release", "3.1.3.0")
    return {"response": {"installedVersion": release, "version": release}}


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------

def _site_record(site: CatalystSite) -> dict:
    record = {
        "id": site.id,
        "parentId": site.parent_id,
        "name": site.name,
        # NI reads `nameHierarchy` verbatim for site_name_aliases and
        # display_name; the add-on never synthesizes it. The other two keys are
        # the fallbacks its own hierarchy index accepts.
        "nameHierarchy": site.name_hierarchy,
        "siteNameHierarchy": site.name_hierarchy,
        "siteHierarchy": site.name_hierarchy,
        "displayName": site.name_hierarchy,
        "groupName": site.name_hierarchy,
        "type": site.site_type.value,
        "siteType": site.site_type.value,
    }
    # Geography only where it exists: a floor has no coordinates, and NI does
    # tonumber(latitude) — a null would simply drop the pin from the map.
    if site.latitude is not None:
        record["latitude"] = site.latitude
    if site.longitude is not None:
        record["longitude"] = site.longitude
    if site.address:
        record["address"] = site.address
    if site.country:
        record["country"] = site.country
    if site.site_type == SiteType.FLOOR:
        record["floorNumber"] = site.floor_number
        if site.rf_model:
            record["rfModel"] = site.rf_model
        record["width"] = site.width
        record["length"] = site.length
        record["height"] = site.height
        record["unitsOfMeasure"] = "feet"
    return record


def generate_sites(state: CatalystTopologyState) -> list[dict]:
    """`GET /dna/intent/api/v1/sites` — the full hierarchy, one flat list."""
    return [_site_record(s) for s in state.sites.values()]


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def _inventory_record(device: CatalystDevice, state: CatalystTopologyState) -> dict:
    """One `/network-device` row.

    Deliberately free of any per-request value. The add-on compares the count
    before and after the page walk and discards everything if it moved, so this
    record must serialize identically on every call for the life of the
    process.
    """
    return {
        "type": _device_type_for(device),
        "family": device.family,
        "id": device.id,
        "instanceUuid": device.id,
        "instanceTenantId": "-1",
        "hostname": device.hostname,
        "platformId": device.platform_id,
        "series": _series_for(device.platform_id),
        "macAddress": device.mac,
        "apEthernetMacAddress": "",
        "serialNumber": device.serial,
        "managementIpAddress": device.management_ip,
        "ipAddress": device.management_ip,
        "dnsResolvedManagementAddress": "",
        "reachabilityStatus": device.reachability.value,
        "managementState": device.management_state.value,
        "collectionStatus": _COLLECTION_STATUS,
        "collectionInterval": "300",
        "role": device.role,
        "softwareVersion": device.software_version,
        "softwareType": _SOFTWARE_TYPE.get(device.family, ""),
        "upTime": _format_uptime(device.uptime_ms),
        "uptimeSeconds": device.uptime_ms // 1000,
        "bootDateTime": "",
        "lastUpdated": str(state.inventory_epoch_ms),
        "lastUpdateTime": state.inventory_epoch_ms,
        # DNAC returns this as a string; the add-on accepts either but compares
        # it with str(...) != "0" when checking bulk coverage.
        "interfaceCount": str(device.interface_count),
        "siteNameHierarchy": device.site_name_hierarchy,
        "locationName": device.site_name_hierarchy,
        "siteName": device.site_name_hierarchy,
        "deviceSupportLevel": "Supported",
        "description": device.notes,
        "vendor": "Cisco Systems, Inc.",
        "errorCode": "",
        "errorDescription": "",
        "lineCardId": "",
        "lineCardName": "",
        "memorySize": "1671889696",
        "waasDeviceMode": "",
        "apManagerIp": "",
        "associatedWlcIp": "",
        "tagCountList": [],
    }


def generate_device_inventory(state: CatalystTopologyState) -> list[dict]:
    """`GET /dna/intent/api/v1/network-device` — every page of the fleet.

    Sorted by id so paging is stable: the add-on rejects a repeated `id` across
    pages and a verbatim-repeated page.
    """
    devices = sorted(state.devices.values(), key=lambda d: d.id)
    return [_inventory_record(d, state) for d in devices]


def generate_device_count(state: CatalystTopologyState) -> dict:
    """`GET /dna/intent/api/v1/network-device/count`.

    Must equal len(generate_device_inventory(...)) exactly. The add-on accepts
    both `{"response":{"count":N}}` and `{"response":N}` but rejects a string,
    a float or a bool.
    """
    return {"response": {"count": len(state.devices)}}


def page_inventory(records: list[dict], offset: int, limit: int) -> list[dict]:
    """Slice an inventory page. DNAC `offset` here is 1-based."""
    start = max(offset - 1, 0)
    return records[start:start + limit]


# ---------------------------------------------------------------------------
# Device health
# ---------------------------------------------------------------------------

def _health_score_pair(utilization: float) -> int:
    """Map a utilization percentage onto DNAC's 0-10 health score.

    NI bands these 0-2 critical, 3-7 degraded, 8-10 ok, so a healthy device
    must land in 8-10 or every vertex renders degraded.
    """
    if utilization >= 90:
        return random.randint(0, 2)
    if utilization >= 75:
        return random.randint(3, 6)
    return random.randint(8, 10)


def _wireless_health(device: CatalystDevice) -> dict:
    """Per-radio health objects. The add-on reads exactly radio0, radio1,
    Ghz24 and Ghz50 — note the vendor's casing on the last two."""
    clients = device.client_count
    return {
        "clientCount": {
            "radio0": clients // 2,
            "radio1": clients - clients // 2,
            "Ghz24": max(clients // 4, 0),
            "Ghz50": clients - max(clients // 4, 0),
        },
        "interferenceHealth": {
            "radio0": random.randint(8, 10), "radio1": random.randint(8, 10),
            "Ghz24": random.randint(8, 10), "Ghz50": random.randint(8, 10),
        },
        "noiseHealth": {
            "radio0": random.randint(8, 10), "radio1": random.randint(8, 10),
            "Ghz24": random.randint(8, 10), "Ghz50": random.randint(8, 10),
        },
        "airQualityHealth": {
            "radio0": random.randint(8, 10), "radio1": random.randint(8, 10),
            "Ghz24": random.randint(8, 10), "Ghz50": random.randint(8, 10),
        },
        "utilizationHealth": {
            "radio0": random.randint(6, 10), "radio1": random.randint(6, 10),
            "Ghz24": random.randint(6, 10), "Ghz50": random.randint(6, 10),
        },
    }


def _device_health_record(device: CatalystDevice) -> dict:
    """One `/device-health` row.

    Unlike the inventory this varies per poll — health is the whole point of
    the route, and the add-on only brackets the *count*, never the values.
    """
    cpu = round(random.uniform(6.0, 42.0), 2) if device.is_up else 0.0
    memory = round(random.uniform(31.0, 68.0), 2) if device.is_up else 0.0
    cpu_health = _health_score_pair(cpu)
    memory_health = _health_score_pair(memory)

    record = {
        "id": device.id,
        "uuid": device.id,
        "deviceId": device.id,
        "name": device.hostname,
        "roles": device.role,
        # `location` is what the add-on emits as Site/Location, and NI resolves
        # it against site vertices with site_id_type="site_name" — so it has to
        # be the full hierarchy string, not the bare floor name.
        "location": device.site_name_hierarchy,
        "siteName": device.site_name_hierarchy,
        "siteHierarchy": device.site_name_hierarchy,
        "macAddress": device.mac,
        "deviceFamily": device.family,
        "deviceType": _device_type_for(device),
        "deviceClassification": device.family,
        "model": device.platform_id,
        "series": _series_for(device.platform_id),
        "osVersion": device.software_version,
        "software": device.software_version,
        "managementIpAddr": device.management_ip,
        "ipAddress": device.management_ip,
        "cpuUtilization": cpu,
        "cpuHealth": cpu_health,
        "memoryUtilization": memory,
        "memoryUtilizationHealth": memory_health,
        "overallHealth": min(cpu_health, memory_health) if device.is_up else 0,
        "issueCount": 0 if device.is_up else 1,
        "interfaceLinkErrHealth": random.randint(8, 10) if device.is_up else 0,
        "interDeviceLinkAvailHealth": 10 if device.is_up else 0,
        "throughputHealth": random.randint(7, 10) if device.is_up else 0,
        "clientHealth": random.randint(7, 10) if device.is_up else 0,
        "meanHealth": random.randint(8, 10) if device.is_up else 0,
        "numberOfClients": device.client_count,
        "uptime": _format_uptime(device.uptime_ms),
        "haStatus": "",
        "stackMember": "",
        "freeMemoryWired": "1204.63" if device.is_up else "",
        "totalMemoryWired": "2048.00" if device.is_up else "",
        "overallHealthTime": int(time.time() * 1000),
        "time": int(time.time() * 1000),
    }

    if device.family in _WIRELESS_FAMILIES:
        record.update(_wireless_health(device))
    else:
        # Present but empty, so HasClientCount is "False" rather than absent.
        record["clientCount"] = {}

    if not device.is_up:
        record["reachabilityHealth"] = 0
    return record


def generate_device_health(state: CatalystTopologyState) -> list[dict]:
    """`GET /dna/intent/api/v1/device-health` — one row per device."""
    return [_device_health_record(d) for d in state.devices.values()]


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

def _interface_values(device: CatalystDevice, iface: CatalystInterface,
                      timestamp_ms: int) -> dict:
    """The nested `values` object of one legacy interface-query row.

    `deviceId` must equal the id in the request path — the collector aborts the
    whole poll with `unexpected_device_identity` otherwise.
    """
    up = iface.oper_status == InterfaceOperStatus.UP
    speed_bps = iface.speed if up else 0

    if not up:
        rx_rate = tx_rate = 0.0
        rx_util = tx_util = 0.0
    else:
        # Access ports carry little; uplinks carry the aggregated traffic.
        ceiling = speed_bps * (0.55 if iface.is_wan else 0.18)
        rx_rate = round(random.uniform(0.01, 1.0) * ceiling, 2)
        tx_rate = round(random.uniform(0.01, 1.0) * ceiling, 2)
        rx_util = round(100.0 * rx_rate / speed_bps, 4) if speed_bps else 0.0
        tx_util = round(100.0 * tx_rate / speed_bps, 4) if speed_bps else 0.0

    return {
        "deviceId": device.id,
        "name": iface.name,
        "description": f"{device.hostname} {iface.name}",
        "operStatus": iface.oper_status.value,
        "adminStatus": iface.admin_status.value,
        # DNAC reports speed as a string of bits per second.
        "speed": str(iface.speed),
        "interfaceType": iface.interface_type,
        "portMode": iface.port_mode,
        "portType": iface.port_type,
        "ipv4Address": "",
        "macAddr": iface.mac_addr,
        "mediaType": "SFP" if iface.speed >= 10_000_000_000 else "",
        "duplexConfig": iface.duplex,
        "duplexOper": "full" if up else "auto",
        "vlanId": str(iface.vlan_id) if iface.vlan_id else "",
        # NI does tostring(tonumber(InterfaceIfIndex)) — must be numeric.
        "interfaceId": str(iface.if_index),
        "ifIndex": iface.if_index,
        # Must fall inside the collector's [startTime, endTime] window or the
        # event is flagged source_time_in_window=false.
        "timestamp": timestamp_ms,
        "rxRate": rx_rate,
        "txRate": tx_rate,
        "rxUtilization": rx_util,
        "txUtilization": tx_util,
        "rxDiscards": round(random.uniform(0.0, 0.02), 4) if up else 0.0,
        "txDiscards": round(random.uniform(0.0, 0.02), 4) if up else 0.0,
        "rxError": round(random.uniform(0.0, 0.01), 4) if up else 0.0,
        "txError": round(random.uniform(0.0, 0.01), 4) if up else 0.0,
        "isWan": iface.is_wan,
        "isL3Interface": iface.is_l3_interface,
        "status": iface.oper_status.value,
    }


def generate_device_interfaces(state: CatalystTopologyState,
                               device: CatalystDevice,
                               start_time_ms: Optional[int] = None,
                               end_time_ms: Optional[int] = None) -> list[dict]:
    """Rows for `POST /dna/intent/api/v2/networkDevices/{id}/interfaces/query`.

    Returns the legacy `[{"id":…, "values":{…}}]` shape. The row `id` is the
    interface UUID and must be unique within and across every page of a poll —
    it is also the `InterfaceID` NI keys interface vertices on, and the value
    physical-topology reports as `startPortID`/`endPortID`.
    """
    now_ms = int(time.time() * 1000)
    # Clamp the sample timestamp into the requested window so the collector's
    # source_time_in_window check passes.
    timestamp_ms = now_ms
    if end_time_ms:
        timestamp_ms = min(timestamp_ms, int(end_time_ms))
    if start_time_ms:
        timestamp_ms = max(timestamp_ms, int(start_time_ms))

    return [
        {"id": iface.id,
         "values": _interface_values(device, iface, timestamp_ms)}
        for iface in device.interfaces
    ]


# ---------------------------------------------------------------------------
# Physical topology
# ---------------------------------------------------------------------------

def _topology_node(device: CatalystDevice) -> dict:
    return {
        "id": device.id,
        "deviceId": device.id,
        "label": device.hostname,
        "platformId": device.platform_id,
        "nodeType": device.family,
        "roles": device.role,
        "deviceFamily": device.family,
        "ip": [device.management_ip],
        "x": 0,
        "y": 0,
        "additionalInfo": {
            "serialNumber": device.serial,
            "macAddress": device.mac,
            "siteNameHierarchy": device.site_name_hierarchy,
        },
    }


def _topology_link(link, index: int) -> dict:
    return {
        "id": link.id,
        # NI maps these four verbatim onto the edge. `source`/`target` are
        # device ids and `startPortID`/`endPortID` are interface ids — mixing
        # them up yields an edge that silently fails to resolve.
        "source": link.source_device_id,
        "target": link.target_device_id,
        "startPortID": link.source_interface_id,
        "endPortID": link.target_interface_id,
        "linkStatus": link.link_status,
        "portUtilization": "",
        "additionalInfo": {"linkIndex": index},
    }


def generate_physical_topology(state: CatalystTopologyState) -> dict:
    """The body of `GET /dna/intent/api/v1/topology/physical-topology`.

    Returns the inner object; the route handler wraps it as
    `{"response": <this>}`. Keeping `response` an object rather than a list is
    what makes the whole topology a single event, which is what NI's `links{}`
    expansion requires.
    """
    devices_in_links = {l.source_device_id for l in state.links.values()} | \
                       {l.target_device_id for l in state.links.values()}
    nodes = [_topology_node(state.devices[d])
             for d in sorted(devices_in_links) if d in state.devices]
    links = [_topology_link(l, i)
             for i, l in enumerate(sorted(state.links.values(),
                                          key=lambda x: x.id), start=1)]
    return {"nodes": nodes, "links": links}


# ---------------------------------------------------------------------------
# Assurance issues
# ---------------------------------------------------------------------------

# NI's alert normalization coalesces src in the order DeviceMACAddress,
# DeviceSerialNumber, DeviceID, DeviceIpAddress, IssueSpecificEntityValue. The
# first two come only from inventory enrichment, which the add-on skips
# entirely when an issue row carries a resolvable device name. So these
# deliberately omit deviceName/hostname: the add-on then enriches from
# /network-device and NI keys the alert on the device MAC, which is what makes
# it attach to the same vertex the rest of the graph uses.
_ISSUE_PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}


def _issue_record(issue, state: CatalystTopologyState) -> dict:
    device = state.get_device(issue.device_id) if issue.device_id else None
    record = {
        "issueId": issue.issue_id,
        "name": issue.name,
        "summary": issue.summary,
        "description": issue.summary,
        "category": issue.category,
        "severity": issue.severity.upper(),
        "priority": _ISSUE_PRIORITY.get(issue.severity.upper(), "P3"),
        "source": "ASSURANCE",
        "entityType": "network_device",
        "entityId": issue.device_id or (device.id if device else ""),
        "deviceId": issue.device_id or (device.id if device else ""),
        "managementIpAddress": issue.device_ip or (device.management_ip if device else ""),
        "ipAddress": issue.device_ip or (device.management_ip if device else ""),
        "deviceRole": device.role if device else "",
        "siteHierarchy": issue.site_name_hierarchy or (device.site_name_hierarchy if device else ""),
        "siteNameHierarchy": issue.site_name_hierarchy or (device.site_name_hierarchy if device else ""),
        "siteName": device.site_name if device else "",
        "status": issue.status,
        "firstOccurredTime": issue.start_time_ms,
        "mostRecentOccurredTime": issue.updated_time_ms,
        "issueOccurrenceCount": issue.occurrence_count,
        "aiDriven": "3.0" if issue.is_ai_driven else "",
        "clientMac": "",
        "macAddress": "",
        "additionalAttributes": {
            "deviceFamily": device.family if device else "",
            "platformId": device.platform_id if device else "",
            "softwareVersion": device.software_version if device else "",
            "siteType": "building" if device else "",
            "issueStatus": issue.status,
        },
        "startTime": issue.start_time_ms,
        "endTime": issue.updated_time_ms,
    }
    return record


def generate_assurance_issues(state: CatalystTopologyState,
                              start_time_ms: Optional[int] = None,
                              end_time_ms: Optional[int] = None) -> list[dict]:
    """`GET /dna/data/api/v1/assuranceIssues`, sorted by firstOccurredTime asc.

    The collector requests `sortBy=firstOccurredTime&order=asc` over a frozen
    24-hour window, so the ordering has to match or its overlap-3 pagination
    walks the wrong rows.
    """
    rows = [_issue_record(i, state) for i in state.issues]
    if start_time_ms is not None:
        rows = [r for r in rows if r["firstOccurredTime"] >= start_time_ms]
    if end_time_ms is not None:
        rows = [r for r in rows if r["firstOccurredTime"] <= end_time_ms]
    rows.sort(key=lambda r: (r["firstOccurredTime"], r["issueId"]))
    return rows


def page_issues(rows: list[dict], offset: int, limit: int) -> list[dict]:
    """Slice an issue page. This route's `offset` is 1-based."""
    start = max(offset - 1, 0)
    return rows[start:start + limit]
