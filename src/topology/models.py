"""Data models for the network topology."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"


class DeviceFamily(str, Enum):
    MX = "mx"
    MS = "ms"
    MR = "mr"
    MV = "mv"
    MT = "mt"


class UplinkStatus(str, Enum):
    ACTIVE = "Active"
    READY = "Ready"
    FAILING = "Failing"
    FAILED = "Failed"


class NodeRole(str, Enum):
    """Business role of a device within a site. Drives topology rendering."""
    GATEWAY = "gateway"
    CORE = "core"
    ACCESS = "access"
    WIRELESS = "wireless"
    CAMERA = "camera"
    SENSOR = "sensor"


@dataclass
class SwitchPort:
    number: str
    name: str = ""
    enabled: bool = True
    type: str = "access"
    vlan: int = 1
    poe_enabled: bool = True
    # Down until a declared L2 link attaches a peer — an uncabled port must
    # not report Connected or Splunk NI infers phantom adjacency.
    is_up: bool = False
    client_count: int = 0
    connected_serial: str = ""
    tags: list[str] = field(default_factory=list)
    rstp_enabled: bool = True
    stp_guard: str = "disabled"
    link_negotiation: str = "Auto negotiate"
    port_schedule_id: str = ""


@dataclass
class UplinkInfo:
    ip: str = ""
    wan_ip: str = ""
    gateway: str = ""
    public_ip: str = ""
    interface: str = "internet 1"
    status: UplinkStatus = UplinkStatus.ACTIVE
    latency_ms: float = 10.0
    loss_percent: float = 0.0
    bandwidth_up_kbps: int = 100000
    bandwidth_down_kbps: int = 100000


@dataclass
class Device:
    serial: str
    model: str
    name: str
    mac: str
    network_id: str
    tags: list[str] = field(default_factory=list)
    status: DeviceStatus = DeviceStatus.ONLINE
    uplink: Optional[UplinkInfo] = None
    ports: list[SwitchPort] = field(default_factory=list)
    firmware: str = ""
    lan_ip: str = ""
    gateway: str = ""
    public_ip: str = ""
    address: str = ""
    notes: str = ""

    # Business context — carried only through real Meraki API fields.
    role: NodeRole = NodeRole.ACCESS
    business_function: str = ""

    last_seen: float = field(default_factory=time.time)

    @property
    def family(self) -> DeviceFamily:
        prefix = self.model[:2].upper()
        return {
            "MX": DeviceFamily.MX,
            "MS": DeviceFamily.MS,
            "MR": DeviceFamily.MR,
            "MV": DeviceFamily.MV,
            "MT": DeviceFamily.MT,
        }.get(prefix, DeviceFamily.MS)

    @property
    def device_type(self) -> str:
        """Meraki productType value."""
        return {
            DeviceFamily.MX: "appliance",
            DeviceFamily.MS: "switch",
            DeviceFamily.MR: "wireless",
            DeviceFamily.MV: "camera",
            DeviceFamily.MT: "sensor",
        }[self.family]

    def get_firmware(self) -> str:
        if self.firmware:
            return self.firmware
        firmware_map = {
            "MX": "mx-18.107.22",
            "MS120": "ms-15.53",
            "MS225": "ms-15.53",
            "MS250": "ms-15.53",
            "MS350": "ms-15.53",
            "MR26": "mr-30.7.4",
            "MR36": "mr-30.7.4",
            "MR46": "mr-30.7.4",
            "MR56": "mr-30.7.4",
            "MV": "mc-2.13",
            "MT": "mimik-1.18",
        }
        for prefix, fw in firmware_map.items():
            if self.model.startswith(prefix):
                return fw
        return "unknown"

    def is_pci_scope(self) -> bool:
        return any(t == "pci-scope" for t in self.tags)


@dataclass
class Link:
    """An L2 physical connection between two device ports.

    This is what feeds Splunk NI's topology graph via the Meraki
    devices/topology/l2/links and networks/{id}/topology/linkLayer endpoints.
    """
    source_serial: str
    source_port: str
    target_serial: str
    target_port: str
    network_id: str
    is_trunk: bool = False
    vlan: int = 0
    is_stp_disabled: bool = False
    link_id: str = ""
    is_up: bool = True
    last_reported_at: float = field(default_factory=time.time)


@dataclass
class Vlan:
    id: int
    name: str
    subnet: str = ""
    appliance_ip: str = ""
    dhcp_handling: str = "Run a DHCP server"
    purpose: str = ""


@dataclass
class Ssid:
    number: int
    name: str
    enabled: bool = True
    auth_mode: str = "open"
    vlan_id: int = 0
    purpose: str = ""
    visible: bool = True


@dataclass
class Network:
    id: str
    name: str
    product_types: list[str]
    tags: list[str] = field(default_factory=list)
    site: str = ""
    site_type: str = ""
    timezone: str = "America/Los_Angeles"
    address: str = ""
    headcount: int = 0
    criticality: str = "tier-3"
    notes: str = ""
    devices: list[Device] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    ssids: list[Ssid] = field(default_factory=list)

    @property
    def ip_prefix(self) -> str:
        """Derive 10.<n> from the site's addressing octet."""
        for dev in self.devices:
            if dev.lan_ip and dev.lan_ip.startswith("10."):
                return ".".join(dev.lan_ip.split(".")[:2])
        return "10.0"


@dataclass
class Client:
    mac: str
    hostname: str
    description: str
    ip: str
    vlan: int
    network_id: str
    device_serial: str
    client_type: str = "associate"
    business_function: str = ""
    sent: int = 0
    recv: int = 0
    last_seen: float = field(default_factory=time.time)


@dataclass
class VpnPeer:
    serial: str
    network_id: str
    public_ip: str
    is_hub: bool = False


class TopologyState:
    """Holds the complete topology state and provides mutation methods."""

    def __init__(self):
        self.organization: dict = {}
        self.networks: dict[str, Network] = {}
        self.devices: dict[str, Device] = {}
        self.links: dict[str, Link] = {}
        self.clients: dict[str, Client] = {}
        self.vpn_peers: list[VpnPeer] = []
        self.events: list[dict] = []
        self.security_events: list[dict] = []
        self.sensor_readings: list[dict] = []
        self.webhook_logs: list[dict] = []
        self.audit_logs: list[dict] = []
        self.firmware_upgrades: list[dict] = []
        self._event_counter = 0

    def get_all_devices(self) -> list[Device]:
        return list(self.devices.values())

    def get_all_links(self) -> list[Link]:
        return list(self.links.values())

    def get_devices_by_network(self, network_id: str) -> list[Device]:
        return [d for d in self.devices.values() if d.network_id == network_id]

    def get_links_by_network(self, network_id: str) -> list[Link]:
        return [l for l in self.links.values() if l.network_id == network_id]

    def get_links_for_device(self, serial: str) -> list[Link]:
        return [l for l in self.links.values()
                if l.source_serial == serial or l.target_serial == serial]

    def get_devices_by_model_prefix(self, prefix: str) -> list[Device]:
        return [d for d in self.devices.values() if d.model.startswith(prefix)]

    def get_devices_by_tag(self, tag: str) -> list[Device]:
        return [d for d in self.devices.values() if tag in d.tags]

    def get_device(self, serial: str) -> Optional[Device]:
        return self.devices.get(serial)

    def get_network(self, network_id: str) -> Optional[Network]:
        return self.networks.get(network_id)

    def get_network_for_device(self, serial: str) -> Optional[Network]:
        device = self.devices.get(serial)
        return self.networks.get(device.network_id) if device else None

    def get_peer_of(self, serial: str, port: str) -> Optional[tuple[str, str]]:
        """Given a device+port, return the (peer_serial, peer_port) or None."""
        for link in self.links.values():
            if link.source_serial == serial and link.source_port == port:
                return (link.target_serial, link.target_port)
            if link.target_serial == serial and link.target_port == port:
                return (link.source_serial, link.source_port)
        return None

    def add_event(self, network_id: str, event_type: str, severity: str,
                  description: str, device_serial: str = "", details: dict = None):
        self._event_counter += 1
        event = {
            "id": f"evt_{self._event_counter:08d}",
            "networkId": network_id,
            "occurredAt": time.time(),
            "eventType": event_type,
            "severity": severity,
            "description": description,
            "deviceSerial": device_serial,
            "details": details or {},
        }
        self.events.append(event)
        if len(self.events) > 5000:
            self.events = self.events[-5000:]
        return event

    def add_security_event(self, device_serial: str, event_type: str,
                           source_ip: str, destination_ip: str,
                           protocol: str, port: int, count: int = 1,
                           rule: str = ""):
        event = {
            "ts": time.time(),
            "eventId": f"sec_{random.randint(100000, 999999)}",
            "eventType": event_type,
            "srcIp": source_ip,
            "destIp": destination_ip,
            "protocol": protocol,
            "port": port,
            "count": count,
            "rule": rule,
            "deviceSerial": device_serial,
            "networkId": self.devices[device_serial].network_id if device_serial in self.devices else "",
        }
        self.security_events.append(event)
        if len(self.security_events) > 2000:
            self.security_events = self.security_events[-2000:]
        return event

    def add_sensor_reading(self, device_serial: str, temperature: float,
                           humidity: float, network_id: str):
        reading = {
            "ts": time.time(),
            "serial": device_serial,
            "networkId": network_id,
            "temperature": temperature,
            "humidity": humidity,
        }
        self.sensor_readings.append(reading)
        if len(self.sensor_readings) > 2000:
            self.sensor_readings = self.sensor_readings[-2000:]
        return reading

    def business_summary(self) -> dict:
        """Aggregate counts by business function — powers the dashboard."""
        by_type = {"pos": 0, "scanner": 0, "guest": 0, "associate": 0, "iot": 0, "av-system": 0}
        for client in self.clients.values():
            if client.client_type in by_type:
                by_type[client.client_type] += 1

        sites = {}
        for net in self.networks.values():
            devs = self.get_devices_by_network(net.id)
            sites[net.site] = {
                "name": net.name,
                "site_type": net.site_type,
                "criticality": net.criticality,
                "headcount": net.headcount,
                "device_count": len(devs),
                "online": sum(1 for d in devs if d.status == DeviceStatus.ONLINE),
                "offline": sum(1 for d in devs if d.status == DeviceStatus.OFFLINE),
                "degraded": sum(1 for d in devs if d.status == DeviceStatus.DEGRADED),
                "pci_devices": sum(1 for d in devs if d.is_pci_scope()),
            }
        return {"clients_by_type": by_type, "sites": sites}
