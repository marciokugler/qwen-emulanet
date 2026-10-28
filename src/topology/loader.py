"""Load topology from YAML configuration."""

from __future__ import annotations

import yaml
from pathlib import Path

from src.topology.models import (
    TopologyState, Network, Device, Client, VpnPeer, Link, Vlan, Ssid,
    UplinkInfo, SwitchPort, DeviceStatus, NodeRole, UplinkStatus,
)

# Role -> Meraki serial suffix. Mirrors how chains label store hardware.
ROLE_SERIAL = {
    "gateway": "MX01", "switch": "MS01",
    "ap_sales": "MR01", "ap_back": "MR02",
    "cam_entrance": "MV01", "cam_pos": "MV02", "cam_stock": "MV03",
    "sensor": "MT01",
}

ROLE_NODE = {
    "gateway": NodeRole.GATEWAY, "switch": NodeRole.ACCESS,
    "ap_sales": NodeRole.WIRELESS, "ap_back": NodeRole.WIRELESS,
    "cam_entrance": NodeRole.CAMERA, "cam_pos": NodeRole.CAMERA,
    "cam_stock": NodeRole.CAMERA, "sensor": NodeRole.SENSOR,
}

ROLE_MAC = {
    "gateway": "01:01", "switch": "02:01",
    "ap_sales": "03:01", "ap_back": "03:02",
    "cam_entrance": "04:01", "cam_pos": "04:02", "cam_stock": "04:03",
    "sensor": "05:01",
}

# (link_ports key, source role, target role) for store template cabling.
STORE_LINKS = [
    ("gateway_to_switch", "gateway", "switch"),
    ("switch_to_ap_sales", "switch", "ap_sales"),
    ("switch_to_ap_back", "switch", "ap_back"),
    ("switch_to_cam_entrance", "switch", "cam_entrance"),
    ("switch_to_cam_pos", "switch", "cam_pos"),
    ("switch_to_cam_stock", "switch", "cam_stock"),
    ("switch_to_sensor", "switch", "sensor"),
]

# Port counts derived from Meraki switch models.
SWITCH_PORT_COUNT = {
    "MS120-8": 8, "MS120-24": 24, "MS225-24": 24,
    "MS250-24": 24, "MS250-48": 48, "MS250-48LP": 48,
    "MS350-24": 24, "MS350-48": 48, "MS350-48LP": 48, "MS350-48FP": 48,
    "MS425-32": 32,
}

MX_LAN_PORTS = {"MX68": 5, "MX85": 4, "MX105": 4, "MX450": 4}


def _switch_port_count(model: str) -> int:
    for prefix, count in SWITCH_PORT_COUNT.items():
        if model.startswith(prefix):
            # 48-port MS350 models expose 2 additional SFP+ uplinks (49, 50).
            return count + 2 if count == 48 else count
    return 24


def _build_ports(device: Device) -> list[SwitchPort]:
    """Create the port list appropriate for a device model."""
    family = device.family.value

    if family == "mx":
        ports = [SwitchPort(number="internet 1", name="WAN1", type="trunk"),
                 SwitchPort(number="internet 2", name="WAN2", type="trunk")]
        for i in range(1, MX_LAN_PORTS.get(device.model, 4) + 1):
            ports.append(SwitchPort(number=f"port {i}", name=f"LAN{i}"))
        return ports

    if family == "ms":
        return [SwitchPort(number=str(i), name=f"Port {i}")
                for i in range(1, _switch_port_count(device.model) + 1)]

    if family == "mr":
        return [SwitchPort(number="eth0", name="eth0", poe_enabled=True)]

    if family == "mv":
        return [SwitchPort(number="eth0", name="eth0", poe_enabled=True)]

    return [SwitchPort(number="port 1", name="port 1", poe_enabled=False)]


def _build_vlans(vlan_template: list[dict], ip_prefix: str) -> list[Vlan]:
    return [
        Vlan(
            id=v["id"],
            name=v["name"],
            subnet=f"{ip_prefix}.{v['id']}.0/24",
            appliance_ip=f"{ip_prefix}.{v['id']}.1",
            dhcp_handling="Do not respond to DHCP requests" if v["id"] == 30
                          else "Run a DHCP server",
            purpose=v.get("purpose", ""),
        )
        for v in vlan_template
    ]


def _build_ssids(ssid_template: list[dict]) -> list[Ssid]:
    return [
        Ssid(
            number=s["number"],
            name=s["name"],
            auth_mode=s["auth_mode"],
            vlan_id=s.get("vlan_id", 0),
            purpose=s.get("purpose", ""),
            visible=s.get("visible", True),
        )
        for s in ssid_template
    ]


def _make_device(spec: dict, network_id: str, role: NodeRole) -> Device:
    uplink = None
    if spec.get("wan_ip"):
        uplink = UplinkInfo(
            wan_ip=spec["wan_ip"],
            ip=spec.get("lan_ip", ""),
            gateway=spec.get("gateway", ""),
            public_ip=spec.get("public_ip", spec["wan_ip"]),
            interface=spec.get("uplink_interface", "internet 1"),
            status=UplinkStatus.ACTIVE,
        )

    return Device(
        serial=spec["serial"],
        model=spec["model"],
        name=spec["name"],
        mac=spec["mac"],
        network_id=network_id,
        tags=spec.get("tags", []),
        address=spec.get("address", ""),
        notes=spec.get("notes", ""),
        lan_ip=spec.get("lan_ip", ""),
        public_ip=spec.get("public_ip", ""),
        gateway=spec.get("gateway", ""),
        uplink=uplink,
        role=role,
        business_function=", ".join(spec.get("tags", [])),
    )


def _role_from_tags(model: str, tags: list[str]) -> NodeRole:
    if model.startswith("MX"):
        return NodeRole.GATEWAY
    if model.startswith("MR"):
        return NodeRole.WIRELESS
    if model.startswith("MV"):
        return NodeRole.CAMERA
    if model.startswith("MT"):
        return NodeRole.SENSOR
    if any(t in ("core-switch",) for t in tags):
        return NodeRole.CORE
    return NodeRole.ACCESS


def _load_explicit_network(net_data: dict, vlan_template: list[dict],
                           ssid_template: list[dict]) -> Network:
    devices = []
    for spec in net_data.get("devices", []):
        role = _role_from_tags(spec["model"], spec.get("tags", []))
        devices.append(_make_device(spec, net_data["id"], role))

    ip_prefix = ".".join(devices[0].lan_ip.split(".")[:2]) if devices and devices[0].lan_ip else "10.0"

    network = Network(
        id=net_data["id"],
        name=net_data["name"],
        product_types=net_data.get("product_types", []),
        tags=net_data.get("tags", []),
        site=net_data.get("site", ""),
        site_type=net_data.get("site_type", ""),
        timezone=net_data.get("timezone", "America/Los_Angeles"),
        address=net_data.get("address", ""),
        headcount=net_data.get("headcount", 0),
        criticality=net_data.get("criticality", "tier-3"),
        notes=net_data.get("notes", ""),
        devices=devices,
        vlans=_build_vlans(vlan_template, ip_prefix),
        ssids=_build_ssids(ssid_template),
    )

    for idx, l in enumerate(net_data.get("links", []), start=1):
        network.links.append(Link(
            source_serial=l["source"]["serial"],
            source_port=l["source"]["port"],
            target_serial=l["target"]["serial"],
            target_port=l["target"]["port"],
            network_id=net_data["id"],
            is_trunk=l.get("trunk", False),
            vlan=l.get("vlan", 0),
            is_stp_disabled=l.get("stp_disabled", False),
            link_id=f"LK_{net_data['id'][-6:]}_{idx:03d}",
        ))

    for c in net_data.get("clients", []):
        network.devices  # noqa - clients attached at state level
    return network


def _load_clients(net_data: dict, network_id: str) -> list[Client]:
    return [
        Client(
            mac=c["mac"],
            hostname=c["hostname"],
            description=c.get("description", ""),
            ip=c["ip"],
            vlan=c.get("vlan", 1),
            network_id=network_id,
            device_serial=c["device_serial"],
            client_type=c.get("client_type", "associate"),
            business_function=c.get("business_function", ""),
        )
        for c in net_data.get("clients", [])
    ]


def _expand_store(store: dict, template: dict, vlan_template: list[dict],
                  ssid_template: list[dict], network_id: str) -> tuple[Network, list[Client]]:
    """Expand the store template into a full network for one store."""
    octet = store["ip_octet"]
    octet_hex = f"{octet:02x}"
    prefix = f"10.{octet}"
    store_tag = f"store-{store['store_id']}"
    site = store["site"]
    serial_stem = f"Q2QN-S{store['store_id']}"

    devices: dict[str, Device] = {}
    for spec in template["devices"]:
        role = spec["role"]
        serial = f"{serial_stem}-{ROLE_SERIAL[role]}"
        model = store.get("gateway_model") if role == "gateway" else spec["model"]
        tags = list(spec["tags"]) + [
            store_tag, store["metro"], store["region"],
            f"{store['criticality']}-critical", *store.get("extra_tags", []),
        ]
        devices[role] = Device(
            serial=serial,
            model=model,
            name=f"{site}-{spec['name_suffix']}",
            mac=f"0c:05:{octet_hex}:{ROLE_MAC[role]}",
            network_id=network_id,
            tags=tags,
            address=store["address"],
            notes=spec["notes"],
            lan_ip=f"{prefix}.{spec['ip_suffix']}",
            role=ROLE_NODE[role],
            business_function=", ".join(spec["tags"]),
        )

    gateway = devices["gateway"]
    gateway.uplink = UplinkInfo(
        wan_ip=f"198.18.{store['wan_octet']}.10",
        ip=gateway.lan_ip,
        gateway=f"198.18.{store['wan_octet']}.1",
        public_ip=f"198.18.{store['wan_octet']}.10",
        interface="internet 1",
        status=UplinkStatus.ACTIVE,
    )
    gateway.public_ip = f"198.18.{store['wan_octet']}.10"

    network = Network(
        id=network_id,
        name=store["name"],
        product_types=["appliance", "switch", "wireless", "camera", "sensor"],
        tags=[store["region"], store["metro"], store_tag, store["store_type"],
              "pci-scope", f"{store['criticality']}-critical", *store.get("extra_tags", [])],
        site=site,
        site_type=store["store_type"],
        timezone=store["timezone"],
        address=store["address"],
        headcount=store.get("headcount", 0),
        criticality=store.get("criticality", "tier-3"),
        notes=store.get("notes", ""),
        devices=list(devices.values()),
        vlans=_build_vlans(vlan_template, prefix),
        ssids=_build_ssids(ssid_template),
    )

    link_ports = template["link_ports"]
    for idx, (key, src_role, tgt_role) in enumerate(STORE_LINKS, start=1):
        if src_role not in devices or tgt_role not in devices:
            continue
        p = link_ports[key]
        network.links.append(Link(
            source_serial=devices[src_role].serial,
            source_port=p["source_port"],
            target_serial=devices[tgt_role].serial,
            target_port=p["target_port"],
            network_id=network_id,
            is_trunk=p.get("trunk", False),
            vlan=p.get("vlan", 0),
            link_id=f"LK_{network_id[-6:]}_{idx:03d}",
        ))

    clients: list[Client] = []
    for spec in template["clients"]:
        role = spec["role"]
        attach = devices.get(spec["attach_to"])
        if not attach:
            continue

        variants = store.get("guest_count", 1) if role.startswith("guest") else 1
        for v in range(variants):
            suffix = f"{v + 1:02d}" if variants > 1 else ""
            hostname = spec["hostname_suffix"]
            if not hostname.startswith(("POS", "GUEST")):
                hostname = f"STORE{store['store_id']}-{hostname}"
            if suffix:
                hostname = f"{hostname}-{suffix}"

            ip_host = spec["ip_suffix"].split(".")[-1]
            ip = f"{prefix}.{spec['ip_suffix'].rsplit('.', 1)[0]}.{int(ip_host) + v}"

            clients.append(Client(
                mac=f"{'d8:bb:c1' if spec['client_type'] == 'pos' else 'a4:5e:60'}:{octet_hex}:{v + 1:02x}:{spec['vlan']:02x}:{role[-4:].encode().hex()[:2]}",
                hostname=hostname,
                description=spec["description"],
                ip=ip,
                vlan=spec["vlan"],
                network_id=network_id,
                device_serial=attach.serial,
                client_type=spec["client_type"],
                business_function=spec["business_function"],
            ))

    return network, clients


def _apply_links_to_ports(state: TopologyState):
    """Mark switch ports as connected based on the declared L2 links."""
    for device in state.devices.values():
        device.ports = _build_ports(device)

    port_index = {
        (d.serial, p.number): p
        for d in state.devices.values() for p in d.ports
    }

    for link in state.links.values():
        src = port_index.get((link.source_serial, link.source_port))
        tgt = port_index.get((link.target_serial, link.target_port))

        if src:
            src.is_up = link.is_up
            src.connected_serial = link.target_serial
            src.type = "trunk" if link.is_trunk else "access"
            if link.vlan:
                src.vlan = link.vlan
        if tgt:
            tgt.is_up = link.is_up
            tgt.connected_serial = link.source_serial
            tgt.type = "trunk" if link.is_trunk else "access"
            if link.vlan:
                tgt.vlan = link.vlan


def load_topology(config_path: str | Path) -> TopologyState:
    """Load topology from YAML and return a populated TopologyState."""
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    state = TopologyState()
    state.organization = data.get("organization", {})

    vlan_template = data.get("vlan_template", [])
    ssid_template = data.get("ssid_template", [])

    # Explicitly defined networks: HQ, DC, flagship store.
    for net_data in data.get("networks", []):
        network = _load_explicit_network(net_data, vlan_template, ssid_template)
        state.networks[network.id] = network
        for device in network.devices:
            state.devices[device.serial] = device
        for link in network.links:
            state.links[link.link_id] = link
        for client in _load_clients(net_data, network.id):
            state.clients[client.mac] = client

    # Template-expanded stores.
    template = data.get("store_template")
    if template:
        base_id = 646829496405521106
        for offset, store in enumerate(data.get("stores", []), start=1):
            network_id = f"L_{base_id + offset}"
            network, clients = _expand_store(store, template, vlan_template,
                                             ssid_template, network_id)
            state.networks[network.id] = network
            for device in network.devices:
                state.devices[device.serial] = device
            for link in network.links:
                state.links[link.link_id] = link
            for client in clients:
                state.clients[client.mac] = client

    # SD-WAN peers: declared hubs plus every other MX as a spoke.
    vpn_cfg = data.get("vpn", {})
    hub_serials = set(vpn_cfg.get("hub_serials", []))
    for device in state.get_devices_by_model_prefix("MX"):
        if not device.uplink:
            continue
        state.vpn_peers.append(VpnPeer(
            serial=device.serial,
            network_id=device.network_id,
            public_ip=device.uplink.wan_ip,
            is_hub=device.serial in hub_serials,
        ))

    _apply_links_to_ports(state)
    return state
