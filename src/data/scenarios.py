"""Scenario engine for generating network events."""

from __future__ import annotations

import asyncio
import logging
import random
import time
import yaml
from pathlib import Path
from typing import Optional

from src.topology.models import TopologyState, DeviceStatus, UplinkStatus
from src.webhooks import generator as webhook_gen
from src.webhooks.sender import SplunkHECSender

logger = logging.getLogger(__name__)


class ScenarioEngine:
    """Execute scheduled and random scenarios to generate realistic events."""

    def __init__(self, state: TopologyState, config_path: str,
                 hec_sender: Optional[SplunkHECSender] = None):
        self.state = state
        self.config_path = Path(config_path)
        self.hec_sender = hec_sender
        self.scenarios: list[dict] = []
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._active_effects: dict[str, dict] = {}
        self._load_scenarios()

    def _load_scenarios(self):
        if not self.config_path.exists():
            logger.warning(f"Scenario config not found: {self.config_path}")
            return
        with open(self.config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.scenarios = data.get("scenarios", [])
        logger.info(f"Loaded {len(self.scenarios)} scenarios")

    async def start(self):
        if self._running:
            return
        self._running = True
        logger.info("Scenario engine started")

        for scenario in self.scenarios:
            task = asyncio.create_task(self._run_scenario(scenario))
            self._tasks.append(task)

    async def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self._active_effects.clear()
        self._restore_all_devices()
        logger.info("Scenario engine stopped")

    def trigger_now(self, scenario_name: str) -> bool:
        """Fire a scenario immediately without blocking the caller.

        Actions can sleep for the configured duration (a port flap holds for
        90s), so awaiting them inline would hang the HTTP request. Schedule as
        a tracked background task instead.
        """
        scenario = next((s for s in self.scenarios if s.get("name") == scenario_name), None)
        if scenario is None:
            return False

        task = asyncio.create_task(self._run_triggered(scenario))
        self._tasks.append(task)
        logger.info(f"Scenario '{scenario_name}' triggered manually")
        return True

    async def _run_triggered(self, scenario: dict):
        name = scenario.get("name", "unknown")
        try:
            await self._execute_actions(scenario.get("actions", []))
        except asyncio.CancelledError:
            logger.debug(f"Triggered scenario '{name}' cancelled")
            raise
        except Exception as e:
            logger.error(f"Triggered scenario '{name}' error: {e}")

    def _restore_all_devices(self):
        for device in self.state.get_all_devices():
            device.status = DeviceStatus.ONLINE
            device.last_seen = time.time()
            if device.uplink:
                device.uplink.status = UplinkStatus.ACTIVE
                device.uplink.latency_ms = random.uniform(5.0, 30.0)
                device.uplink.loss_percent = random.uniform(0.0, 1.0)
            for port in device.ports:
                port.is_up = bool(port.connected_serial)

        # Links and ports must come back too, otherwise a stopped mid-flap
        # scenario leaves the topology graph showing a phantom outage.
        for link in self.state.get_all_links():
            link.is_up = True

    async def _run_scenario(self, scenario: dict):
        name = scenario.get("name", "unknown")
        trigger = scenario.get("trigger", "scheduled")

        try:
            if trigger == "scheduled":
                await self._run_scheduled(scenario)
            elif trigger == "random":
                await self._run_random(scenario)
        except asyncio.CancelledError:
            logger.debug(f"Scenario '{name}' cancelled")
        except Exception as e:
            logger.error(f"Scenario '{name}' error: {e}")

    async def _run_scheduled(self, scenario: dict):
        name = scenario.get("name", "unknown")
        schedule = scenario.get("schedule", "0 */6 * * *")
        duration = scenario.get("duration_minutes", 15)

        interval = self._parse_cron_interval(schedule)
        logger.info(f"Scenario '{name}': scheduled every {interval}s, duration {duration}m")

        while self._running:
            await asyncio.sleep(interval)
            if not self._running:
                break

            logger.info(f"Scenario '{name}': executing")
            await self._execute_actions(scenario.get("actions", []))

            await asyncio.sleep(duration * 60)
            if not self._running:
                break

            await self._revert_actions(scenario.get("actions", []))
            logger.info(f"Scenario '{name}': reverted")

    async def _run_random(self, scenario: dict):
        name = scenario.get("name", "unknown")
        probability = scenario.get("probability", 0.1)
        interval = scenario.get("interval_minutes", 60) * 60
        duration = scenario.get("duration_minutes", 15)

        logger.info(f"Scenario '{name}': random, p={probability}, check every {interval}s")

        while self._running:
            await asyncio.sleep(interval)
            if not self._running:
                break

            if random.random() < probability:
                logger.info(f"Scenario '{name}': triggered")
                await self._execute_actions(scenario.get("actions", []))

                await asyncio.sleep(duration * 60)
                if not self._running:
                    break

                await self._revert_actions(scenario.get("actions", []))
                logger.info(f"Scenario '{name}': reverted")

    def _parse_cron_interval(self, cron_expr: str) -> int:
        parts = cron_expr.split()
        if len(parts) < 5:
            return 3600

        minute, hour = parts[0], parts[1]

        if hour.startswith("*/"):
            return int(hour[2:]) * 3600
        elif minute.startswith("*/"):
            return int(minute[2:]) * 60
        elif hour == "*" and minute == "0":
            return 3600
        elif hour == "*" and minute.startswith("*/"):
            return int(minute[2:]) * 60
        else:
            return 14400

    async def _execute_actions(self, actions: list[dict]):
        for action in actions:
            action_type = action.get("type", "")

            if action_type == "set_device_status":
                self._apply_device_status(action)
            elif action_type == "generate_event":
                self._apply_generate_event(action)
            elif action_type == "port_state_change":
                await self._apply_port_state_change(action)
            elif action_type == "security_event":
                self._apply_security_event(action)
            elif action_type == "sensor_reading":
                self._apply_sensor_reading(action)
            elif action_type == "vpn_status_change":
                await self._apply_vpn_status_change(action)
            elif action_type == "firmware_upgrade":
                self._apply_firmware_upgrade(action)
            elif action_type == "client_density":
                self._apply_client_density(action)
            elif action_type == "webhook_alert":
                await self._apply_webhook_alert(action)

    async def _revert_actions(self, actions: list[dict]):
        for action in actions:
            action_type = action.get("type", "")

            if action_type == "set_device_status":
                serial = action.get("device", "")
                device = self.state.get_device(serial)
                if device:
                    device.status = DeviceStatus.ONLINE
                    device.last_seen = time.time()
                    if device.uplink:
                        device.uplink.status = UplinkStatus.ACTIVE
                        device.uplink.latency_ms = random.uniform(5.0, 30.0)
                        device.uplink.loss_percent = random.uniform(0.0, 1.0)

                    webhook_payload = webhook_gen.generate_device_status_webhook(serial, self.state)
                    if self.hec_sender:
                        await self.hec_sender.send_webhook(webhook_payload)

            elif action_type == "port_state_change":
                serial = action.get("device", "")
                port_num = str(action.get("port", ""))
                device = self.state.get_device(serial)
                if device:
                    for port in device.ports:
                        if port.number == port_num:
                            port.is_up = True
                            break

            elif action_type == "sensor_reading":
                serial = action.get("device", "")
                device = self.state.get_device(serial)
                if device:
                    self.state.add_sensor_reading(
                        serial, random.uniform(20.0, 26.0),
                        random.uniform(40.0, 60.0), device.network_id
                    )

    def _apply_device_status(self, action: dict):
        serial = action.get("device", "")
        status_str = action.get("status", "online")
        device = self.state.get_device(serial)
        if not device:
            return

        device.status = DeviceStatus(status_str)
        device.last_seen = time.time()

        if device.uplink:
            if status_str == "degraded":
                device.uplink.status = UplinkStatus.FAILING
                device.uplink.latency_ms = action.get("latency_ms", 250)
                device.uplink.loss_percent = action.get("loss_percent", 8)
            elif status_str == "offline":
                device.uplink.status = UplinkStatus.FAILED
            else:
                device.uplink.status = UplinkStatus.ACTIVE
                device.uplink.latency_ms = random.uniform(5.0, 30.0)
                device.uplink.loss_percent = random.uniform(0.0, 1.0)

        logger.info(f"Device {serial} ({device.name}) status -> {status_str}")

    def _apply_generate_event(self, action: dict):
        network_id = action.get("networkId", "")
        event_type = action.get("eventType", "")
        severity = action.get("severity", "info")
        description = action.get("description", "")

        # Honour an explicit device — Splunk NI correlates event -> device ->
        # topology, so attributing to an arbitrary device would break that.
        device_serial = action.get("device", "")
        if not device_serial:
            for d in self.state.get_all_devices():
                if d.network_id == network_id:
                    device_serial = d.serial
                    break
        elif not network_id:
            device = self.state.get_device(device_serial)
            if device:
                network_id = device.network_id

        if device_serial not in self.state.devices:
            logger.warning(f"Scenario references unknown device {device_serial}")

        self.state.add_event(network_id, event_type, severity, description, device_serial)
        logger.info(f"Event generated: [{severity}] {event_type} on {device_serial or network_id}")

    async def _apply_port_state_change(self, action: dict):
        serial = action.get("device", "")
        port_num = str(action.get("port", ""))
        is_up = action.get("state", "down") == "up"
        duration = action.get("duration_seconds", 30)

        device = self.state.get_device(serial)
        if not device:
            return

        self._set_port_state(serial, port_num, is_up)

        port_status = "up" if is_up else "down"
        logger.info(f"Port {port_num} on {serial} -> {port_status}")

        webhook_payload = webhook_gen.generate_port_status_webhook(serial, port_num, port_status, self.state)
        if self.hec_sender:
            await self.hec_sender.send_webhook(webhook_payload)

        # Recovery is scheduled, not awaited. Blocking here would stall every
        # later action in the scenario — a real flap emits its events instantly
        # and the link comes back later.
        if not is_up and duration > 0:
            task = asyncio.create_task(
                self._restore_port_after(serial, port_num, duration))
            self._tasks.append(task)

    async def _restore_port_after(self, serial: str, port_num: str, delay: int):
        try:
            await asyncio.sleep(delay)
            # Restore regardless of engine state so a stopped scenario cannot
            # leave a port permanently down in the topology.
            self._set_port_state(serial, port_num, True)
            logger.info(f"Port {port_num} on {serial} restored after {delay}s")
        except asyncio.CancelledError:
            raise

    def _set_port_state(self, serial: str, port_num: str, is_up: bool):
        """Flip a port and its L2 link so the topology graph stays truthful."""
        device = self.state.get_device(serial)
        if not device:
            return

        for port in device.ports:
            if port.number == port_num:
                port.is_up = is_up
                break

        for link in self.state.get_links_for_device(serial):
            if link.source_serial == serial and link.source_port == port_num:
                link.is_up = is_up
            elif link.target_serial == serial and link.target_port == port_num:
                link.is_up = is_up

    def _apply_security_event(self, action: dict):
        serial = action.get("device", "")
        event_type = action.get("eventType", "intrusion_attempt")
        source_ip = action.get("source_ip", "0.0.0.0")
        dest_ip = action.get("destination_ip", "0.0.0.0")
        protocol = action.get("protocol", "tcp")
        port = action.get("port", 0)
        count = action.get("count", 1)
        rule = action.get("rule", "")

        self.state.add_security_event(serial, event_type, source_ip, dest_ip,
                                        protocol, port, count, rule)
        logger.info(f"Security event: {event_type} from {source_ip} to {dest_ip}:{port}")

    def _apply_sensor_reading(self, action: dict):
        serial = action.get("device", "")
        temp = action.get("temperature_c", 25.0)
        humidity = action.get("humidity_percent", 50.0)

        device = self.state.get_device(serial)
        if not device:
            return

        self.state.add_sensor_reading(serial, temp, humidity, device.network_id)
        logger.info(f"Sensor reading: {serial} temp={temp}C humidity={humidity}%")

    async def _apply_vpn_status_change(self, action: dict):
        tunnel = action.get("tunnel", {})
        from_serial = tunnel.get("from", "")
        to_serial = tunnel.get("to", "")
        status = action.get("status", "down")
        duration = action.get("duration_seconds", 60)

        webhook_payload = webhook_gen.generate_vpn_status_webhook(
            from_serial, to_serial, status, self.state
        )
        if self.hec_sender:
            await self.hec_sender.send_webhook(webhook_payload)

        from_device = self.state.get_device(from_serial)
        if from_device:
            self.state.add_event(
                from_device.network_id, "vpn_tunnel_down", "critical",
                f"VPN tunnel to {to_serial} is {status}", from_serial
            )

        logger.info(f"VPN tunnel {from_serial} -> {to_serial}: {status}")

    def _apply_firmware_upgrade(self, action: dict):
        devices = action.get("devices", [])
        from_version = action.get("from_version", "")
        to_version = action.get("to_version", "")

        for serial in devices:
            device = self.state.get_device(serial)
            if device:
                upgrade = {
                    "ts": time.time(),
                    "serial": serial,
                    "networkId": device.network_id,
                    "deviceName": device.name,
                    "fromVersion": from_version,
                    "toVersion": to_version,
                    "status": "completed",
                }
                self.state.firmware_upgrades.append(upgrade)
                logger.info(f"Firmware upgrade: {serial} {from_version} -> {to_version}")

    def _apply_client_density(self, action: dict):
        serial = action.get("device", "")
        client_count = action.get("client_count", 50)
        channel_util = action.get("channel_utilization", 70)
        logger.info(f"Client density: {serial} clients={client_count} util={channel_util}%")

    async def _apply_webhook_alert(self, action: dict):
        webhook_type = action.get("webhook_type", "generic")
        network_id = action.get("networkId", "")
        event_type = action.get("eventType", "")
        severity = action.get("severity", "info")
        description = action.get("description", "")
        device_serial = action.get("device", "")

        webhook_payload = webhook_gen.generate_generic_event_webhook(
            network_id, event_type, severity, description, device_serial, self.state
        )
        if self.hec_sender:
            await self.hec_sender.send_webhook(webhook_payload)

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "scenarios_loaded": len(self.scenarios),
            "active_effects": len(self._active_effects),
            "scenarios": [
                {
                    "name": s.get("name"),
                    "trigger": s.get("trigger"),
                    "description": s.get("description", ""),
                    "business_impact": s.get("business_impact", ""),
                    "schedule": s.get("schedule", ""),
                    "interval_minutes": s.get("interval_minutes"),
                    "probability": s.get("probability"),
                    "duration_minutes": s.get("duration_minutes"),
                }
                for s in self.scenarios
            ],
        }
