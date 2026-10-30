"""Load the Catalyst Center estate from YAML.

Mirrors ``loader.py`` for the Meraki topology, with two differences that come
from how Splunk NI consumes DNAC data:

1. **Identifiers are derived, not authored.** Device, interface, site and link
   IDs are ``uuid5`` of a stable key, so a poll two hours apart reports the
   same IDs. NI materializes physical-topology edges by matching
   ``startPortID``/``endPortID`` against interface vertices it already holds;
   an ID that drifts silently orphans every edge touching it.

2. **Resolution errors are fatal.** A link naming a device or port that does
   not exist would emit an edge NI drops without any error anywhere, so the
   loader raises instead. Same for a device with an empty MAC — NI's
   device-vertex search filters on ``mac_address=*``, so a MAC-less device
   produces no vertex and every edge touching it is skipped as unresolved.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import yaml

from src.topology.catalyst_models import (
    CatalystDevice, CatalystInterface, CatalystIssue, CatalystLink,
    CatalystSite, CatalystTopologyState, InterfaceAdminStatus,
    InterfaceOperStatus, ManagementState, Reachability, SiteType,
    object_id, site_uuid,
)


class CatalystTopologyError(ValueError):
    """Raised when the YAML cannot produce a self-consistent estate."""


def _parse_namespace(raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError) as exc:
        raise CatalystTopologyError(
            f"controller.uuid_namespace is not a valid UUID: {raw!r}") from exc


def _interface_mac(namespace: uuid.UUID, device_mac: str, device_id: str,
                   if_index: int) -> str:
    """Derive a stable six-octet MAC for one interface of one device.

    Keeps the device's OUI so the address looks like real hardware, and derives
    the low three octets from a hash of the device ID and ifIndex. Real
    Catalyst switches offset the chassis base MAC instead, but offsets collide
    across devices that share an OUI — and a collision would make NI fuse two
    unrelated interfaces into one vertex. Uniqueness is asserted by the caller.
    """
    oui = device_mac.split(":")[:3]
    digest = uuid.uuid5(namespace, f"ifmac:{device_id}:{if_index}").int
    return "{}:{}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        oui[0], oui[1],
        (digest >> 8) & 0xff,
        (digest >> 16) & 0xff,
        (digest >> 24) & 0xff,
        if_index & 0xff,
    )


def _load_sites(state: CatalystTopologyState, namespace: uuid.UUID,
                raw_sites: list[dict]) -> None:
    """Build the site tree and derive each site's nameHierarchy."""
    declared = {s["name"] for s in raw_sites}
    by_name: dict[str, CatalystSite] = {}

    for spec in raw_sites:
        name = spec["name"]
        site_type = SiteType(spec.get("type", "area"))
        parent_name = spec.get("parent", "")
        if parent_name and parent_name not in declared:
            raise CatalystTopologyError(
                f"site {name!r} has unknown parent {parent_name!r}")
        if site_type == SiteType.GLOBAL and parent_name:
            raise CatalystTopologyError(f"global site {name!r} must not have a parent")

        site = CatalystSite(
            name=name,
            site_type=site_type,
            parent_name=parent_name,
            address=spec.get("address", ""),
            country=spec.get("country", ""),
            latitude=spec.get("latitude"),
            longitude=spec.get("longitude"),
            floor_number=spec.get("floor_number"),
            rf_model=spec.get("rf_model", ""),
            width=spec.get("width"),
            length=spec.get("length"),
            height=spec.get("height"),
            id=site_uuid(namespace, f"site:{name}"),
        )
        by_name[name] = site

    # nameHierarchy needs every parent resolved first, so derive it in a
    # second pass rather than inline.
    for site in by_name.values():
        chain = [site.name]
        cursor = site
        seen = {site.name}
        while cursor.parent_name:
            if cursor.parent_name in seen:
                raise CatalystTopologyError(
                    f"site hierarchy cycle at {cursor.parent_name!r}")
            seen.add(cursor.parent_name)
            parent = by_name[cursor.parent_name]
            chain.append(parent.name)
            cursor = parent
        site.parent_id = by_name[site.parent_name].id if site.parent_name else ""
        site.name_hierarchy = "/".join(reversed(chain))

    if len([s for s in by_name.values() if s.site_type == SiteType.GLOBAL]) != 1:
        raise CatalystTopologyError("exactly one global site is required")

    state.sites = {s.id: s for s in by_name.values()}
    state.sites_by_name = by_name


def _expand_interfaces(device: CatalystDevice, profile: list[dict],
                       namespace: uuid.UUID) -> list[CatalystInterface]:
    """Expand a port profile into concrete interfaces with sequential ifIndex.

    Every port on the chassis is created, cabled or not: DNAC reports the full
    port inventory, and reporting only cabled ports would make interfaceCount
    disagree with the interfaces the add-on can page through.
    """
    interfaces: list[CatalystInterface] = []
    if_index = 0

    for group in profile:
        prefix = group["prefix"]
        for offset in range(1, int(group["count"]) + 1):
            if_index += 1
            name = f"{prefix}{offset}"
            interfaces.append(CatalystInterface(
                device_id=device.id,
                name=name,
                if_index=if_index,
                interface_type=group.get("interface_type", "Physical"),
                speed=int(group.get("speed", 1000000000)),
                port_mode=group.get("port_mode", "access"),
                is_wan=bool(group.get("is_wan", False)),
                is_l3_interface=bool(group.get("is_l3", False)),
                mac_addr=_interface_mac(namespace, device.mac, device.id,
                                        if_index),
                admin_status=InterfaceAdminStatus.UP,
                # Down until a declared link attaches a peer.
                oper_status=InterfaceOperStatus.DOWN,
                port_type=group.get("port_type", "network-port"),
                id=object_id(namespace, f"iface:{device.id}:{if_index}"),
            ))

    return interfaces


def _load_devices(state: CatalystTopologyState, namespace: uuid.UUID,
                  profiles: dict[str, list[dict]],
                  raw_devices: list[dict]) -> None:
    seen_serials: dict[str, str] = {}
    seen_macs: dict[str, str] = {}
    seen_hostnames: set[str] = set()
    seen_iface_macs: dict[str, str] = {}

    for spec in raw_devices:
        hostname = spec["hostname"]
        if hostname in seen_hostnames:
            raise CatalystTopologyError(f"duplicate device hostname {hostname!r}")
        seen_hostnames.add(hostname)

        serial = spec["serial"]
        if serial in seen_serials:
            raise CatalystTopologyError(
                f"duplicate serial {serial!r} on {hostname!r} "
                f"and {seen_serials[serial]!r} — NI would fuse them into one vertex")
        seen_serials[serial] = hostname

        mac = (spec.get("mac") or "").strip().lower()
        if not mac:
            raise CatalystTopologyError(
                f"device {hostname!r} has no MAC; NI's device-vertex search "
                f"filters on mac_address=* so it would produce no vertex")
        if len(mac.split(":")) != 6:
            raise CatalystTopologyError(
                f"device {hostname!r} MAC is not six octets: {mac!r}")
        if mac in seen_macs:
            raise CatalystTopologyError(
                f"duplicate MAC {mac!r} on {hostname!r} and {seen_macs[mac]!r}")
        seen_macs[mac] = hostname

        site_name = spec["site"]
        site = state.get_site_by_name(site_name)
        if site is None:
            raise CatalystTopologyError(
                f"device {hostname!r} references unknown site {site_name!r}")
        if not site.is_assignable:
            raise CatalystTopologyError(
                f"device {hostname!r} is assigned to {site_name!r}, a "
                f"{site.site_type.value}; DNAC only assigns devices to "
                f"buildings and floors")

        profile_name = spec["profile"]
        if profile_name not in profiles:
            raise CatalystTopologyError(
                f"device {hostname!r} references unknown port profile {profile_name!r}")

        device = CatalystDevice(
            hostname=hostname,
            platform_id=spec["platform"],
            family=spec["family"],
            role=spec["role"],
            serial=serial,
            mac=mac,
            management_ip=spec.get("management_ip", ""),
            site_name=site_name,
            software_version=spec.get("software_version", ""),
            uptime_ms=int(spec.get("uptime_ms", 0)),
            notes=spec.get("notes", ""),
            profile=profile_name,
            site_id=site.id,
            site_name_hierarchy=site.name_hierarchy,
            reachability=Reachability(spec.get("reachability", Reachability.REACHABLE.value)),
            management_state=ManagementState(
                spec.get("management_state", ManagementState.MANAGED.value)),
            overall_health=int(spec.get("overall_health", 10)),
            client_count=int(spec.get("client_count", 0)),
        )
        device.id = object_id(namespace, f"device:{serial}")
        device.interfaces = _expand_interfaces(device, profiles[profile_name], namespace)
        device.interface_count = len(device.interfaces)

        for iface in device.interfaces:
            if iface.mac_addr in seen_iface_macs:
                raise CatalystTopologyError(
                    f"derived interface MAC collision {iface.mac_addr!r} on "
                    f"{hostname!r}:{iface.name} and {seen_iface_macs[iface.mac_addr]!r}")
            seen_iface_macs[iface.mac_addr] = f"{hostname}:{iface.name}"

        state.devices[device.id] = device
        state.devices_by_serial[device.serial] = device


def _load_links(state: CatalystTopologyState, namespace: uuid.UUID,
                raw_links: list[dict]) -> None:
    """Resolve each declared link to device + interface IDs and mark ports up."""
    seen_pairs: set[frozenset] = set()

    for index, spec in enumerate(raw_links, start=1):
        resolved = []
        for end in ("source", "target"):
            if end not in spec:
                raise CatalystTopologyError(f"link #{index} is missing {end!r}")
            hostname = spec[end]["device"]
            port_name = spec[end]["port"]
            device = state.get_device_by_hostname(hostname)
            if device is None:
                raise CatalystTopologyError(
                    f"link #{index} references unknown device {hostname!r}")
            iface = device.get_interface(port_name)
            if iface is None:
                raise CatalystTopologyError(
                    f"link #{index} references unknown interface "
                    f"{hostname!r}:{port_name!r} — NI would drop this edge "
                    f"because startPortID/endPortID would not match an "
                    f"interface vertex")
            resolved.append((device, iface))

        (src_dev, src_iface), (tgt_dev, tgt_iface) = resolved

        pair = frozenset({src_iface.id, tgt_iface.id})
        if len(pair) != 2:
            raise CatalystTopologyError(
                f"link #{index} connects {src_dev.hostname}:{src_iface.name} to itself")
        if pair in seen_pairs:
            raise CatalystTopologyError(
                f"link #{index} duplicates an earlier link between "
                f"{src_dev.hostname}:{src_iface.name} and "
                f"{tgt_dev.hostname}:{tgt_iface.name}")
        seen_pairs.add(pair)

        if src_iface.is_up or tgt_iface.is_up:
            raise CatalystTopologyError(
                f"link #{index} reuses an already-cabled interface "
                f"({src_dev.hostname}:{src_iface.name} or "
                f"{tgt_dev.hostname}:{tgt_iface.name})")

        link_id = object_id(namespace, f"link:{index}")
        state.links[link_id] = CatalystLink(
            source_device_id=src_dev.id,
            target_device_id=tgt_dev.id,
            source_interface_id=src_iface.id,
            target_interface_id=tgt_iface.id,
            link_status=spec.get("status", "UP"),
            id=link_id,
        )

        for iface in (src_iface, tgt_iface):
            iface.is_up = True
            iface.oper_status = InterfaceOperStatus.UP


def _assert_mac_uniqueness(state: CatalystTopologyState) -> None:
    """No two devices, and no two interfaces, may share a MAC address.

    NI joins device vertices on serial and MAC across source systems. A
    duplicated MAC does not just mislabel one device — it silently merges two
    of them into a single vertex, which is invisible in the graph and
    impossible to trace back from the UI.
    """
    owners: dict[str, str] = {}
    for device in state.devices.values():
        for label, mac in ((f"device {device.hostname}", device.mac),
                           *((f"interface {device.hostname}:{i.name}", i.mac_addr)
                             for i in device.interfaces)):
            if mac in owners:
                raise CatalystTopologyError(
                    f"MAC {mac!r} claimed by both {owners[mac]!r} and {label!r}")
            owners[mac] = label


def _cross_check_meraki(state: CatalystTopologyState,
                        meraki_topology_path: str | Path | None) -> list[str]:
    """Report which Catalyst devices share a serial or MAC with Meraki.

    Informational only — nothing depends on it — but the overlap is the whole
    point of modelling HQ in two systems, so it is worth asserting that the
    intended fusion devices actually fuse.
    """
    if not meraki_topology_path or not Path(meraki_topology_path).is_file():
        return []

    with open(meraki_topology_path, encoding="utf-8") as f:
        meraki = yaml.safe_load(f)

    meraki_ids: dict[str, str] = {}
    for net in meraki.get("networks", []):
        for dev in net.get("devices", []):
            meraki_ids[dev["serial"].lower()] = dev["name"]
            meraki_ids[dev["mac"].lower()] = dev["name"]

    return sorted(
        d.hostname for d in state.devices.values()
        if d.serial.lower() in meraki_ids or d.mac.lower() in meraki_ids
    )


def load_catalyst_topology(config_path: str | Path,
                           meraki_topology_path: str | Path | None = None,
                           ) -> tuple[CatalystTopologyState, list[str]]:
    """Load the DNAC estate and return (state, hostnames shared with Meraki)."""
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    state = CatalystTopologyState()
    state.controller = dict(data.get("controller", {}))
    state.inventory_epoch_ms = int(time.time() * 1000)
    namespace = _parse_namespace(state.controller.get("uuid_namespace", ""))
    state.namespace = namespace

    _load_sites(state, namespace, data.get("sites", []))
    _load_devices(state, namespace, data.get("port_profiles", {}),
                  data.get("devices", []))
    _load_links(state, namespace, data.get("links", []))
    _assert_mac_uniqueness(state)

    # A device assigned to a floor whose building was never declared would
    # produce a hierarchy string that matches no site vertex.
    for device in state.devices.values():
        if not device.site_name_hierarchy.startswith("Global/"):
            raise CatalystTopologyError(
                f"device {device.hostname!r} resolved to site hierarchy "
                f"{device.site_name_hierarchy!r}, which is not rooted at Global")

    return state, _cross_check_meraki(state, meraki_topology_path)


def seed_issues(state: CatalystTopologyState, now_ms: int) -> None:
    """Give the estate a small baseline of assurance issues.

    NI's alert normalization resolves an issue to a graph vertex from the
    first non-empty identifier in a fixed priority order — MAC, then serial,
    then device ID — so every issue is populated with all three wherever the
    device is known. An issue carrying only a DNAC device ID lands in the
    ``source:catalyst_center`` namespace and can fail to attach.

    The add-on suppresses an issue whose content hash is unchanged since the
    last poll, and it excludes first/most-recent timestamps from that hash.
    So a static issue is emitted once and then never again; anything meant to
    keep flowing has to move ``occurrence_count`` or ``status``.
    """
    baseline = [
        ("High memory utilization", "HIGH", "Performance",
         "HQ-C9500-Core-01", "Memory utilization exceeded 85% on the campus core."),
        ("Interface flapping", "MEDIUM", "Availability",
         "DC-IE3400-Warehouse-01", "Warehouse uplink flapped 6 times in 10 minutes."),
        ("High CPU utilization", "MEDIUM", "Performance",
         "CHI-C9300-Access-01", "Sustained CPU above 80% on the Chicago access switch."),
        ("Device unreachable", "CRITICAL", "Availability",
         "DC-C9300-Leaf-03", "Cold storage leaf stopped responding to ICMP."),
    ]

    for offset, (name, severity, category, hostname, summary) in enumerate(baseline):
        device = state.get_device_by_hostname(hostname)
        # Staggered so firstOccurredTime ordering is well defined — the
        # collector pages with sortBy=firstOccurredTime&order=asc.
        started = now_ms - (len(baseline) - offset) * 3_600_000
        state.add_issue(CatalystIssue(
            issue_id="",
            name=name,
            severity=severity,
            category=category,
            summary=summary,
            device_id=device.id if device else "",
            device_name=device.hostname if device else hostname,
            device_serial=device.serial if device else "",
            device_mac=device.mac if device else "",
            device_ip=device.management_ip if device else "",
            site_name_hierarchy=device.site_name_hierarchy if device else "",
            issue_specific_entity_value=device.id if device else "",
            start_time_ms=started,
            updated_time_ms=now_ms - 60_000,
            occurrence_count=1 + offset,
            status="active",
        ))
