"""Generate Meraki webhook alert payloads."""

from __future__ import annotations

import json
import time
import random
import hashlib
import hmac
from typing import Optional

from src.topology.models import TopologyState, DeviceStatus, DeviceFamily


def _ts_iso(ts: float = None) -> str:
    if ts is None:
        ts = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))


def generate_device_status_webhook(device_serial: str, state: TopologyState) -> dict:
    device = state.get_device(device_serial)
    if not device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "organizationUrl": state.organization.get("url", ""),
        "networkId": device.network_id,
        "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
        "device": {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
            "url": f"https://n1.meraki.com/{device.network_id}/manage/nodes/{device.serial}",
        },
        "alertType": "Device went down" if device.status == DeviceStatus.OFFLINE else "Device came up",
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "deviceName": device.name,
            "deviceSerial": device.serial,
            "deviceMac": device.mac,
            "occurredAt": _ts_iso(),
            "status": device.status.value,
        },
    }


def generate_vpn_status_webhook(from_serial: str, to_serial: str, status: str,
                                  state: TopologyState) -> dict:
    from_device = state.get_device(from_serial)
    to_device = state.get_device(to_serial)
    if not from_device or not to_device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": from_device.network_id,
        "networkName": state.get_network(from_device.network_id).name if state.get_network(from_device.network_id) else "",
        "device": {
            "serial": from_device.serial,
            "mac": from_device.mac,
            "name": from_device.name,
            "model": from_device.model,
        },
        "alertType": "VPN status changed",
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "vpnPeerSerial": to_serial,
            "vpnPeerName": to_device.name,
            "vpnPeerNetwork": state.get_network(to_device.network_id).name if state.get_network(to_device.network_id) else "",
            "vpnStatus": status,
            "occurredAt": _ts_iso(),
        },
    }


def generate_security_webhook(device_serial: str, event_type: str, source_ip: str,
                                dest_ip: str, port: int, state: TopologyState) -> dict:
    device = state.get_device(device_serial)
    if not device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": device.network_id,
        "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
        "device": {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
        },
        "alertType": "Intrusion attempt detected" if "intrusion" in event_type else "Firewall rule hit",
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "eventType": event_type,
            "sourceIp": source_ip,
            "destinationIp": dest_ip,
            "port": port,
            "protocol": "tcp",
            "occurredAt": _ts_iso(),
        },
    }


def generate_port_status_webhook(device_serial: str, port_number: int, port_status: str,
                                   state: TopologyState) -> dict:
    device = state.get_device(device_serial)
    if not device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": device.network_id,
        "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
        "device": {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
        },
        "alertType": "Switch port status changed",
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "portNumber": port_number,
            "portStatus": port_status,
            "occurredAt": _ts_iso(),
        },
    }


def generate_sensor_alert_webhook(device_serial: str, alert_type: str, value: float,
                                    threshold: float, state: TopologyState) -> dict:
    device = state.get_device(device_serial)
    if not device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": device.network_id,
        "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
        "device": {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
        },
        "alertType": alert_type,
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "metric": alert_type,
            "value": value,
            "threshold": threshold,
            "occurredAt": _ts_iso(),
        },
    }


def generate_client_connectivity_webhook(client_mac: str, device_serial: str,
                                           connected: bool, state: TopologyState) -> dict:
    device = state.get_device(device_serial)
    if not device:
        return {}

    return {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": device.network_id,
        "networkName": state.get_network(device.network_id).name if state.get_network(device.network_id) else "",
        "device": {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
        },
        "alertType": "Client connectivity event",
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "clientMac": client_mac,
            "eventType": "connected" if connected else "disconnected",
            "occurredAt": _ts_iso(),
        },
    }


def generate_generic_event_webhook(network_id: str, event_type: str, severity: str,
                                     description: str, device_serial: str,
                                     state: TopologyState) -> dict:
    device = state.get_device(device_serial) if device_serial else None
    network = state.get_network(network_id)

    webhook = {
        "version": "0.1",
        "sharedSecret": "meraki-webhook-secret-12345",
        "sentAt": _ts_iso(),
        "organizationId": state.organization.get("id", "ORG_001"),
        "organizationName": state.organization.get("name", "Acme Corporation"),
        "networkId": network_id,
        "networkName": network.name if network else "",
        "alertType": event_type,
        "alertId": f"alert_{random.randint(100000, 999999)}",
        "alertData": {
            "eventType": event_type,
            "severity": severity,
            "description": description,
            "occurredAt": _ts_iso(),
        },
    }

    if device:
        webhook["device"] = {
            "serial": device.serial,
            "mac": device.mac,
            "name": device.name,
            "model": device.model,
        }

    return webhook
