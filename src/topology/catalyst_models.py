"""Data models for the Catalyst Center (DNAC) estate.

These mirror ``src/topology/models.py`` but describe the part of the Northwind
network managed by Catalyst Center rather than the Meraki dashboard. The two
models deliberately stay separate: DNAC and Meraki expose different identifiers
for the same physical hardware, and keeping them apart is what lets the loader
give three HQ switches the *same* serial and MAC in both systems so Splunk NI
fuses them into one vertex.

Identifier shapes follow the real controller, because the add-on validates them:

* device and interface ``id`` are 24-character hex ObjectIds;
* site ``id`` is a canonical 8-4-4-4-12 UUID.

Both are derived with ``uuid.uuid5`` from a fixed namespace in the topology
YAML, so they are stable across restarts. Stability matters more than
uniqueness here: NI materializes physical-topology edges by matching
``startPortID``/``endPortID`` against known interface vertices, so an interface
UUID that changed between polls would orphan every edge touching it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SiteType(str, Enum):
    GLOBAL = "global"
    AREA = "area"
    BUILDING = "building"
    FLOOR = "floor"


class Reachability(str, Enum):
    """DNAC's reachabilityStatus values that NI's availability binding matches.

    NI compares case-insensitively against exactly ``unreachable``,
    ``ping reachable`` and ``reachable``. Any other string — including the
    ``Warning``/``Unknown`` a real controller can return — matches none of the
    three and leaves the availability observation without a state.
    """
    REACHABLE = "Reachable"
    PING_REACHABLE = "Ping Reachable"
    UNREACHABLE = "Unreachable"


class ManagementState(str, Enum):
    MANAGED = "Managed"
    UNMANAGED = "Unmanaged"


class InterfaceOperStatus(str, Enum):
    """DNAC's operStatus values. Casing is significant — NI lowercases them
    itself, but the add-on passes them through verbatim."""
    UP = "up"
    DOWN = "down"
    NOT_PRESENT = "notPresent"
    LOWER_LAYER_DOWN = "lowerLayerDown"


class InterfaceAdminStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    TESTING = "testing"


def object_id(namespace: uuid.UUID, key: str) -> str:
    """Deterministic 24-character hex ObjectId for a device or interface."""
    return uuid.uuid5(namespace, key).hex[:24]


def site_uuid(namespace: uuid.UUID, key: str) -> str:
    """Deterministic canonical UUID for a site."""
    return str(uuid.uuid5(namespace, key))


@dataclass
class CatalystSite:
    """A node in the DNAC site hierarchy: global -> area -> building -> floor."""
    name: str
    site_type: SiteType
    parent_name: str = ""
    # Derived by the loader, never authored: "Global/HQ Campus/HQ-Seattle/Floor 1".
    name_hierarchy: str = ""
    address: str = ""
    country: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    floor_number: Optional[int] = None
    rf_model: str = ""
    width: Optional[float] = None
    length: Optional[float] = None
    height: Optional[float] = None
    id: str = ""
    parent_id: str = ""

    @property
    def is_assignable(self) -> bool:
        """Only buildings and floors can hold devices in DNAC."""
        return self.site_type in (SiteType.BUILDING, SiteType.FLOOR)


@dataclass
class CatalystInterface:
    """One physical or logical interface on a Catalyst device.

    ``is_up`` reflects cabling, not configuration: an interface named in the
    topology's ``links`` section is UP, every other port on the chassis is
    administratively up but operationally down. Reporting an uncabled port as
    UP would make NI infer an adjacency that does not exist.
    """
    device_id: str
    name: str
    if_index: int
    interface_type: str = "Physical"
    speed: int = 1000000000
    port_mode: str = "access"
    vlan_id: int = 0
    is_wan: bool = False
    is_l3_interface: bool = False
    mac_addr: str = ""
    admin_status: InterfaceAdminStatus = InterfaceAdminStatus.UP
    oper_status: InterfaceOperStatus = InterfaceOperStatus.DOWN
    port_type: str = "network-port"
    has_interface_stats: bool = True
    duplex: str = "autonegotiate"
    mtu: int = 1500
    # Traffic counters, in bits/bytes per second as DNAC reports them.
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    rx_error: int = 0
    tx_error: int = 0
    rx_discards: int = 0
    tx_discards: int = 0
    last_updated_ms: int = 0
    is_up: bool = False
    id: str = ""

    @property
    def admin_status_str(self) -> str:
        return self.admin_status.value

    @property
    def oper_status_str(self) -> str:
        return self.oper_status.value


@dataclass
class CatalystDevice:
    """A device in the Catalyst Center inventory.

    ``serial`` and ``mac`` are the NI fusion keys. A device sharing either with
    a Meraki device collapses into a single vertex whose ``source_systems``
    lists both — which is the point of modelling HQ in two systems.
    """
    hostname: str
    platform_id: str
    family: str
    role: str
    serial: str
    mac: str
    management_ip: str
    site_name: str
    software_version: str = ""
    uptime_ms: int = 0
    notes: str = ""
    profile: str = ""
    # Set by the loader once the site hierarchy is resolved.
    site_id: str = ""
    site_name_hierarchy: str = ""
    id: str = ""
    interfaces: list[CatalystInterface] = field(default_factory=list)

    # Health state, mutated by the scenario engine so one incident surfaces in
    # both management systems.
    reachability: Reachability = Reachability.REACHABLE
    management_state: ManagementState = ManagementState.MANAGED
    overall_health: int = 10
    cpu_utilization: float = 12.0
    memory_utilization: float = 38.0
    client_count: int = 0
    free_timed_message: str = ""

    # Populated by the loader from the links section.
    interface_count: int = 0

    def get_interface(self, name: str) -> Optional[CatalystInterface]:
        return next((i for i in self.interfaces if i.name == name), None)

    def get_interface_by_id(self, interface_id: str) -> Optional[CatalystInterface]:
        return next((i for i in self.interfaces if i.id == interface_id), None)

    @property
    def is_up(self) -> bool:
        return self.reachability == Reachability.REACHABLE

    @property
    def device_type(self) -> str:
        """DNAC's deviceType string, distinct from `family`."""
        return {
            "Switches and Hubs": "Cisco Catalyst 9300 Series Switch",
            "Routers": "Cisco ASR 1000 Series Aggregation Services Router",
            "Wireless Controller": "Cisco 9800 Series Wireless Controller",
            "Unified AP": "Cisco Catalyst 9120AXI Unified Access Point",
        }.get(self.family, "Cisco Catalyst 9300 Series Switch")


@dataclass
class CatalystLink:
    """A physical-topology link between two interfaces.

    NI expands ``links{}`` from the physical-topology body, reading ``source``
    and ``target`` as device IDs and ``startPortID``/``endPortID`` as interface
    IDs. All four must resolve or the edge is skipped.
    """
    source_device_id: str
    target_device_id: str
    source_interface_id: str
    target_interface_id: str
    link_status: str = "UP"
    id: str = ""


@dataclass
class CatalystIssue:
    """An assurance issue — NI's alert source for Catalyst Center.

    NI resolves the affected entity from the first non-empty identifier in a
    fixed priority order, so ``device_mac`` and ``device_serial`` are set
    wherever known: they resolve to a graph vertex, whereas a bare
    ``device_id`` only resolves within the ``source:catalyst_center``
    namespace and can leave the alert unattached.
    """
    issue_id: str
    name: str
    severity: str
    category: str
    summary: str
    device_id: str = ""
    device_name: str = ""
    device_serial: str = ""
    device_mac: str = ""
    device_ip: str = ""
    site_name_hierarchy: str = ""
    issue_specific_entity_value: str = ""
    start_time_ms: int = 0
    updated_time_ms: int = 0
    occurrence_count: int = 1
    expected_within: str = ""
    status: str = "active"
    is_ai_driven: bool = False
    ai_insights: dict = field(default_factory=dict)


class CatalystTopologyState:
    """Holds the Catalyst Center estate and provides the lookups the API needs."""

    def __init__(self):
        self.controller: dict = {}
        self.namespace: Optional[uuid.UUID] = None
        # Set once at load and never refreshed. The add-on brackets every poll
        # with /network-device/count and aborts the whole collection when the
        # count moves (Interface Statistics has zero tolerance), so the
        # inventory has to be byte-stable for the life of the process.
        self.inventory_epoch_ms: int = 0
        self.sites: dict[str, CatalystSite] = {}          # keyed by site id
        self.sites_by_name: dict[str, CatalystSite] = {}  # keyed by name
        self.devices: dict[str, CatalystDevice] = {}      # keyed by device id
        self.devices_by_serial: dict[str, CatalystDevice] = {}
        self.links: dict[str, CatalystLink] = {}          # keyed by link id
        self.issues: list[CatalystIssue] = []
        self.events: list[dict] = []
        self.audit_logs: list[dict] = []
        self._issue_counter = 0

    # --- sites -------------------------------------------------------------
    def get_site(self, site_id: str) -> Optional[CatalystSite]:
        return self.sites.get(site_id)

    def get_site_by_name(self, name: str) -> Optional[CatalystSite]:
        return self.sites_by_name.get(name)

    def get_sites_by_type(self, site_type: SiteType) -> list[CatalystSite]:
        return [s for s in self.sites.values() if s.site_type == site_type]

    # --- devices -----------------------------------------------------------
    def get_all_devices(self) -> list[CatalystDevice]:
        return list(self.devices.values())

    def get_device(self, device_id: str) -> Optional[CatalystDevice]:
        return self.devices.get(device_id)

    def get_device_by_serial(self, serial: str) -> Optional[CatalystDevice]:
        return self.devices_by_serial.get(serial)

    def get_device_by_hostname(self, hostname: str) -> Optional[CatalystDevice]:
        return next((d for d in self.devices.values()
                     if d.hostname == hostname), None)

    def get_devices_by_site(self, site_name: str) -> list[CatalystDevice]:
        return [d for d in self.devices.values() if d.site_name == site_name]

    def get_devices_by_family(self, family: str) -> list[CatalystDevice]:
        return [d for d in self.devices.values() if d.family == family]

    def get_all_interfaces(self) -> list[CatalystInterface]:
        return [i for d in self.devices.values() for i in d.interfaces]

    def get_interface_by_id(self, interface_id: str) -> Optional[CatalystInterface]:
        for device in self.devices.values():
            found = device.get_interface_by_id(interface_id)
            if found:
                return found
        return None

    # --- links -------------------------------------------------------------
    def get_all_links(self) -> list[CatalystLink]:
        return list(self.links.values())

    def get_links_for_device(self, device_id: str) -> list[CatalystLink]:
        return [l for l in self.links.values()
                if l.source_device_id == device_id
                or l.target_device_id == device_id]

    def get_peer_of(self, device_id: str,
                    interface_id: str) -> Optional[tuple[str, str]]:
        """Given a device+interface, return the (peer_device, peer_interface)."""
        for link in self.links.values():
            if (link.source_device_id == device_id
                    and link.source_interface_id == interface_id):
                return (link.target_device_id, link.target_interface_id)
            if (link.target_device_id == device_id
                    and link.target_interface_id == interface_id):
                return (link.source_device_id, link.source_interface_id)
        return None

    # --- issues ------------------------------------------------------------
    def add_issue(self, issue: CatalystIssue) -> CatalystIssue:
        self._issue_counter += 1
        if not issue.issue_id:
            issue.issue_id = f"AW-{self._issue_counter:08d}"
        self.issues.insert(0, issue)
        if len(self.issues) > 500:
            self.issues = self.issues[:500]
        return issue

    def get_active_issues(self) -> list[CatalystIssue]:
        return [i for i in self.issues if i.status == "active"]

    def summary(self) -> dict:
        """Counts for the dashboard and the verification suites."""
        return {
            "sites": len(self.sites),
            "buildings": len(self.get_sites_by_type(SiteType.BUILDING)),
            "floors": len(self.get_sites_by_type(SiteType.FLOOR)),
            "devices": len(self.devices),
            "interfaces": sum(len(d.interfaces) for d in self.devices.values()),
            "links": len(self.links),
            "issues": len(self.issues),
            "unreachable": sum(1 for d in self.devices.values()
                               if d.reachability != Reachability.REACHABLE),
        }
