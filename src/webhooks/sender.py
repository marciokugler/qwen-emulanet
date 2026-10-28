"""Send webhook payloads to Splunk HEC."""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class SplunkHECSender:
    """Send webhook data to Splunk HTTP Event Collector."""

    def __init__(self, url: str, token: str, index: str = "main",
                 sourcetype: str = "meraki:webhook", verify_ssl: bool = False):
        self.url = url
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0)
        return self._client

    async def send_event(self, event_data: dict, sourcetype: str = None) -> bool:
        if not self.url or not self.token:
            logger.debug("HEC not configured, skipping send")
            return False

        payload = {
            "time": int(time.time()),
            "host": "cisco-meraki-emulator",
            "source": "meraki_emulator",
            "sourcetype": sourcetype or self.sourcetype,
            "index": self.index,
            "event": event_data,
        }

        try:
            client = await self._get_client()
            response = await client.post(
                self.url,
                json=payload,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code == 200:
                logger.debug(f"HEC event sent: {event_data.get('alertType', 'unknown')}")
                return True
            else:
                logger.warning(f"HEC send failed: {response.status_code} {response.text}")
                return False
        except Exception as e:
            logger.error(f"HEC send error: {e}")
            return False

    async def send_webhook(self, webhook_payload: dict) -> bool:
        return await self.send_event(webhook_payload, sourcetype="meraki:webhook")

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
