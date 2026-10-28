"""Cisco Network Emulator - Main entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
import random
import yaml
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse

from src.topology.loader import load_topology
from src.topology.models import TopologyState, DeviceStatus
from src.api.server import create_api_server
from src.webhooks.sender import SplunkHECSender
from src.data.scenarios import ScenarioEngine
from src.data import generators as gen

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("emulator")


def load_settings(config_path: str = "config/settings.yaml") -> dict:
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _count_by_type(clients) -> dict:
    """Count clients by business type — POS, scanner, guest, associate, iot."""
    counts: dict[str, int] = {}
    for c in clients:
        counts[c.client_type] = counts.get(c.client_type, 0) + 1
    return counts


def create_dashboard_app(state: TopologyState, scenario_engine: ScenarioEngine,
                          settings: dict) -> FastAPI:
    app = FastAPI(title="Cisco Emulator Dashboard")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        web_dir = Path(__file__).parent / "web"
        index_file = web_dir / "index.html"
        if index_file.exists():
            return index_file.read_text(encoding="utf-8")
        return "<h1>Dashboard not found</h1>"

    @app.get("/api/status")
    async def get_status():
        devices = state.get_all_devices()
        online = sum(1 for d in devices if d.status == DeviceStatus.ONLINE)
        offline = sum(1 for d in devices if d.status == DeviceStatus.OFFLINE)
        degraded = sum(1 for d in devices if d.status == DeviceStatus.DEGRADED)

        return {
            "organization": state.organization.get("name", "Unknown"),
            "total_devices": len(devices),
            "devices_online": online,
            "devices_offline": offline,
            "devices_degraded": degraded,
            "total_networks": len(state.networks),
            "total_events": len(state.events),
            "total_security_events": len(state.security_events),
            "total_sensor_readings": len(state.sensor_readings),
            "total_webhook_logs": len(state.webhook_logs),
            "total_clients": len(state.clients),
            "scenario_engine": scenario_engine.get_status(),
            "splunk_hec": {
                "enabled": settings.get("splunk_hec", {}).get("enabled", False),
                "url": settings.get("splunk_hec", {}).get("url", ""),
            },
            "uptime_seconds": int(time.time() - start_time),
        }

    @app.get("/api/devices")
    async def get_devices():
        devices = []
        for d in state.get_all_devices():
            devices.append({
                "serial": d.serial,
                "name": d.name,
                "model": d.model,
                "networkId": d.network_id,
                "networkName": state.get_network(d.network_id).name if state.get_network(d.network_id) else "",
                "site": state.get_network(d.network_id).site if state.get_network(d.network_id) else "",
                "status": d.status.value,
                "tags": d.tags,
                "notes": d.notes,
                "address": d.address,
                "role": d.role.value,
                "pciScope": d.is_pci_scope(),
                "firmware": d.get_firmware(),
                "lanIp": d.lan_ip,
                "publicIp": d.public_ip,
                "uplink": {
                    "status": d.uplink.status.value if d.uplink else "N/A",
                    "latency": round(d.uplink.latency_ms, 1) if d.uplink else 0,
                    "loss": round(d.uplink.loss_percent, 2) if d.uplink else 0,
                } if d.uplink else None,
            })
        return devices

    @app.get("/api/networks")
    async def get_networks():
        networks = []
        for net in state.networks.values():
            devices = state.get_devices_by_network(net.id)
            networks.append({
                "id": net.id,
                "name": net.name,
                "site": net.site,
                "siteType": net.site_type,
                "criticality": net.criticality,
                "headcount": net.headcount,
                "address": net.address,
                "notes": net.notes,
                "productTypes": net.product_types,
                "tags": net.tags,
                "timezone": net.timezone,
                "deviceCount": len(devices),
                "devicesOnline": sum(1 for d in devices if d.status == DeviceStatus.ONLINE),
                "devicesOffline": sum(1 for d in devices if d.status == DeviceStatus.OFFLINE),
                "linkCount": len(state.get_links_by_network(net.id)),
                "clientCount": sum(1 for c in state.clients.values() if c.network_id == net.id),
                "pciDevices": sum(1 for d in devices if d.is_pci_scope()),
            })
        return networks

    @app.get("/api/events")
    async def get_events(limit: int = 100):
        return state.events[-limit:]

    @app.get("/api/security-events")
    async def get_security_events(limit: int = 100):
        return state.security_events[-limit:]

    @app.get("/api/clients")
    async def get_clients():
        clients = []
        for c in state.clients.values():
            device = state.get_device(c.device_serial)
            network = state.get_network(c.network_id)
            vlan_name = ""
            if network:
                match = next((v for v in network.vlans if v.id == c.vlan), None)
                vlan_name = match.name if match else ""
            clients.append({
                "id": c.mac,
                "mac": c.mac,
                "hostname": c.hostname,
                "description": c.description,
                "ip": c.ip,
                "vlan": c.vlan,
                "vlanName": vlan_name,
                "networkId": c.network_id,
                "networkName": network.name if network else "",
                "site": network.site if network else "",
                "deviceSerial": c.device_serial,
                "deviceName": device.name if device else "",
                "clientType": c.client_type,
                "businessFunction": c.business_function,
                "usage": {"sent": c.sent, "recv": c.recv, "total": c.sent + c.recv},
            })
        return clients

    @app.get("/api/business")
    async def get_business_context():
        """Business view of the topology — sites, services, and client mix."""
        summary = state.business_summary()
        sites = []
        for net in state.networks.values():
            devices = state.get_devices_by_network(net.id)
            links = state.get_links_by_network(net.id)
            clients = [c for c in state.clients.values() if c.network_id == net.id]
            sites.append({
                "networkId": net.id,
                "name": net.name,
                "site": net.site,
                "siteType": net.site_type,
                "criticality": net.criticality,
                "headcount": net.headcount,
                "address": net.address,
                "notes": net.notes,
                "tags": net.tags,
                "timezone": net.timezone,
                "deviceCount": len(devices),
                "online": sum(1 for d in devices if d.status == DeviceStatus.ONLINE),
                "offline": sum(1 for d in devices if d.status == DeviceStatus.OFFLINE),
                "degraded": sum(1 for d in devices if d.status == DeviceStatus.DEGRADED),
                "pciDevices": sum(1 for d in devices if d.is_pci_scope()),
                "linkCount": len(links),
                "clientCount": len(clients),
                "vlans": [{"id": v.id, "name": v.name, "purpose": v.purpose} for v in net.vlans],
                "ssids": [{"number": s.number, "name": s.name, "purpose": s.purpose} for s in net.ssids],
                "clientsByType": _count_by_type(clients),
            })
        return {
            "organization": state.organization.get("name", ""),
            "sites": sites,
            "clientsByType": summary["clients_by_type"],
            "totals": {
                "sites": len(sites),
                "devices": len(state.devices),
                "links": len(state.links),
                "clients": len(state.clients),
                "headcount": sum(n.headcount for n in state.networks.values()),
                "pciDevices": sum(1 for d in state.devices.values() if d.is_pci_scope()),
            },
        }

    @app.get("/api/topology")
    async def get_topology():
        """Graph of sites, devices, and L2 links for the topology view."""
        return {
            "nodes": [
                {
                    "serial": d.serial, "name": d.name, "model": d.model,
                    "mac": d.mac, "status": d.status.value,
                    "networkId": d.network_id, "role": d.role.value,
                    "tags": d.tags, "notes": d.notes, "address": d.address,
                    "lanIp": d.lan_ip, "publicIp": d.public_ip,
                    "site": (state.get_network(d.network_id).site
                             if state.get_network(d.network_id) else ""),
                    "uplink": ({
                        "status": d.uplink.status.value,
                        "latency": round(d.uplink.latency_ms, 1),
                        "loss": round(d.uplink.loss_percent, 2),
                        "wanIp": d.uplink.wan_ip,
                    } if d.uplink else None),
                }
                for d in state.get_all_devices()
            ],
            "links": [
                {
                    "id": l.link_id, "networkId": l.network_id,
                    "sourceSerial": l.source_serial, "sourcePort": l.source_port,
                    "targetSerial": l.target_serial, "targetPort": l.target_port,
                    "isTrunk": l.is_trunk, "vlan": l.vlan,
                    "isUp": l.is_up, "isStpDisabled": l.is_stp_disabled,
                }
                for l in state.get_all_links()
            ],
            "sites": [
                {"networkId": n.id, "name": n.name, "site": n.site,
                 "siteType": n.site_type, "criticality": n.criticality,
                 "headcount": n.headcount, "address": n.address,
                 "tags": n.tags, "notes": n.notes}
                for n in state.networks.values()
            ],
            "vpn": [
                {"serial": p.serial, "networkId": p.network_id,
                 "publicIp": p.public_ip, "isHub": p.is_hub}
                for p in state.vpn_peers
            ],
        }

    @app.get("/api/vpn")
    async def get_vpn():
        return gen.generate_vpn_statuses(state)

    @app.post("/api/scenarios/{scenario_name}/trigger")
    async def trigger_scenario(scenario_name: str):
        # Runs detached — the scenario holds its effects for the configured
        # duration, so awaiting it here would block the HTTP response.
        if scenario_engine.trigger_now(scenario_name):
            return {"status": "triggered", "scenario": scenario_name}
        return JSONResponse(status_code=404, content={"error": "Scenario not found"})

    @app.post("/api/scenarios/start")
    async def start_scenarios():
        await scenario_engine.start()
        return {"status": "started"}

    @app.post("/api/scenarios/stop")
    async def stop_scenarios():
        await scenario_engine.stop()
        return {"status": "stopped"}

    @app.post("/api/device/{serial}/status")
    async def set_device_status(serial: str, status: str = "online"):
        device = state.get_device(serial)
        if not device:
            return JSONResponse(status_code=404, content={"error": "Device not found"})
        device.status = DeviceStatus(status)
        device.last_seen = time.time()
        return {"status": "updated", "serial": serial, "new_status": status}

    return app


start_time = time.time()


async def generate_background_data(state: TopologyState, settings: dict):
    """Generate periodic background data (sensor readings, client stats, etc.)."""
    intervals = settings.get("data_generation", {})
    sensor_interval = intervals.get("sensor_readings_interval", 300)
    events_interval = intervals.get("events_interval", 45)

    while True:
        await asyncio.sleep(events_interval)

        for device in state.get_all_devices():
            if device.status == DeviceStatus.ONLINE:
                device.last_seen = time.time()
                if device.uplink:
                    device.uplink.latency_ms = random.uniform(5.0, 35.0)
                    device.uplink.loss_percent = random.uniform(0.0, 0.5)
            elif device.status == DeviceStatus.DEGRADED:
                device.last_seen = time.time()
                if device.uplink:
                    device.uplink.latency_ms = random.uniform(100.0, 500.0)
                    device.uplink.loss_percent = random.uniform(3.0, 15.0)

        for client in state.clients.values():
            # Traffic profile reflects what the client actually does.
            sent, recv = _client_traffic(client.client_type)
            client.sent += sent
            client.recv += recv
            client.last_seen = time.time()

        for device in state.get_devices_by_model_prefix("MT"):
            if device.status != DeviceStatus.ONLINE:
                continue
            temp, humidity = _sensor_reading(device)
            state.add_sensor_reading(device.serial, temp, humidity, device.network_id)

        if random.random() < 0.3:
            _emit_ambient_event(state)


# Traffic profiles in bytes per polling interval, keyed by business type.
_CLIENT_TRAFFIC = {
    # POS terminals send small, frequent authorization exchanges.
    "pos": ((400, 2_000), (600, 3_000)),
    # Scanners push small inventory records steadily.
    "scanner": ((1_000, 8_000), (2_000, 15_000)),
    # Guests stream and browse — bursty and asymmetric toward download.
    "guest": ((50_000, 900_000), (300_000, 4_000_000)),
    # Associates run normal desktop workloads.
    "associate": ((80_000, 700_000), (400_000, 2_500_000)),
    # IoT controllers send tiny periodic telemetry.
    "iot": ((50, 400), (50, 400)),
    # AV systems pull presentation and conferencing media.
    "av-system": ((20_000, 200_000), (200_000, 1_500_000)),
}


def _client_traffic(client_type: str) -> tuple[int, int]:
    (s_lo, s_hi), (r_lo, r_hi) = _CLIENT_TRAFFIC.get(
        client_type, _CLIENT_TRAFFIC["associate"])
    return random.randint(s_lo, s_hi), random.randint(r_lo, r_hi)


def _sensor_reading(device) -> tuple[float, float]:
    """Sensor ranges depend on what the sensor actually monitors."""
    tags = device.tags
    if "cold-chain" in tags:
        # Frozen storage holds at -18C; drift of a few degrees is normal.
        return round(random.uniform(-19.5, -16.0), 1), round(random.uniform(78.0, 88.0), 1)
    if "water-leak" in tags:
        # Leak sensors report ambient conditions; the leak itself is a binary alert.
        return round(random.uniform(19.0, 23.0), 1), round(random.uniform(40.0, 52.0), 1)
    if "server-room" in tags:
        return round(random.uniform(20.5, 24.0), 1), round(random.uniform(42.0, 55.0), 1)
    # Default: retail floor / warehouse ambient.
    return round(random.uniform(19.0, 24.5), 1), round(random.uniform(40.0, 60.0), 1)


# Ambient retail network events. Each names the device that generated it so
# Splunk NI can walk event -> device -> topology.
_AMBIENT_EVENTS = [
    ("client_connected", "info", "New client associated to {ssid}"),
    ("dhcp_lease_renewed", "info", "DHCP lease renewed on VLAN {vlan_name}"),
    ("ap_channel_changed", "info", "Radio auto-tuned to a less congested channel"),
    ("switch_stp_topology_change", "info", "STP topology change on the access switch"),
    ("mx_vpn_peer_up", "info", "Auto VPN peer re-established"),
    ("camera_motion_detected", "info", "Motion detected in the monitored zone"),
]


def _emit_ambient_event(state):
    network = random.choice(list(state.networks.values()))
    if not network.devices:
        return

    # Attribute the event to a device that plausibly generates it.
    event_type, severity, template = random.choice(_AMBIENT_EVENTS)
    candidates = network.devices
    if event_type == "camera_motion_detected":
        candidates = [d for d in network.devices if d.model.startswith("MV")] or candidates
    elif event_type == "ap_channel_changed":
        candidates = [d for d in network.devices if d.model.startswith("MR")] or candidates
    elif event_type == "switch_stp_topology_change":
        candidates = [d for d in network.devices if d.model.startswith("MS")] or candidates
    elif event_type == "mx_vpn_peer_up":
        candidates = [d for d in network.devices if d.model.startswith("MX")] or candidates
    elif event_type == "client_connected":
        candidates = [d for d in network.devices
                      if d.model.startswith(("MR", "MS"))] or candidates

    device = random.choice(candidates)

    ssid = random.choice(network.ssids).name if network.ssids else "Northwind-Corp"
    vlan = random.choice(network.vlans) if network.vlans else None
    description = template.format(
        ssid=ssid,
        vlan_name=vlan.name if vlan else "Corporate",
    )

    state.add_event(network.id, event_type, severity, description, device.serial)


async def main():
    global start_time
    start_time = time.time()

    settings = load_settings()
    state = load_topology("config/topology.yaml")

    logger.info(f"Loaded topology: {len(state.get_all_devices())} devices, "
                f"{len(state.networks)} networks, {len(state.clients)} clients")

    hec_sender = None
    hec_config = settings.get("splunk_hec", {})
    if hec_config.get("enabled", False):
        hec_sender = SplunkHECSender(
            url=hec_config["url"],
            token=hec_config["token"],
            index=hec_config.get("index", "main"),
            verify_ssl=hec_config.get("verify_ssl", False),
        )
        logger.info(f"Splunk HEC enabled: {hec_config['url']}")
    else:
        logger.info("Splunk HEC disabled - webhook data will be generated but not sent")

    scenario_engine = ScenarioEngine(state, "config/scenarios.yaml", hec_sender)

    api_app = create_api_server(state, settings["server"]["api_key"])
    dashboard_app = create_dashboard_app(state, scenario_engine, settings)

    server_config = settings.get("server", {})
    dashboard_config = settings.get("dashboard", {})

    api_host = server_config.get("host", "0.0.0.0")
    api_port = server_config.get("port", 5000)
    dash_host = dashboard_config.get("host", "0.0.0.0")
    dash_port = dashboard_config.get("port", 8080)

    background_task = asyncio.create_task(generate_background_data(state, settings))

    if settings.get("scenarios", {}).get("enabled", True):
        await scenario_engine.start()

    logger.info(f"Starting Meraki API emulator on http://{api_host}:{api_port}")
    logger.info(f"Starting dashboard on http://{dash_host}:{dash_port}")
    logger.info(f"API Key: {settings['server']['api_key']}")
    logger.info(f"Point Meraki Add-on Base URL to: http://<your-ip>:{api_port}/api/v1")

    config_api = uvicorn.Config(api_app, host=api_host, port=api_port, log_level="warning")
    config_dash = uvicorn.Config(dashboard_app, host=dash_host, port=dash_port, log_level="warning")

    server_api = uvicorn.Server(config_api)
    server_dash = uvicorn.Server(config_dash)

    try:
        await asyncio.gather(
            server_api.serve(),
            server_dash.serve(),
        )
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down...")
    finally:
        background_task.cancel()
        await scenario_engine.stop()
        if hec_sender:
            await hec_sender.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nEmulator stopped.")
