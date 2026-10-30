"""FastAPI mock of the Cisco Catalyst Center (DNAC) REST API.

Serves the routes the Cisco Catalyst add-on for Splunk polls, so that the
genuine add-on can collect from this emulator exactly as it collects from a
real controller. Field shapes live in ``src/data/catalyst_generators.py``;
the reasoning behind each one is in the local-only
``notes/catalyst-addon-contract.md``.

Authentication mirrors the controller: HTTP Basic against
``POST /dna/system/api/v1/auth/token`` exchanges credentials for an opaque
token that every later call replays as ``X-Auth-Token``. The add-on tracks no
expiry and re-authenticates reactively, exactly once per request, on a 401 —
so an expired or unknown token is recoverable rather than fatal, provided the
credentials still work.
"""

from __future__ import annotations

import base64
import binascii
import logging
import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.data import catalyst_generators as cgen
from src.topology.catalyst_models import CatalystTopologyState

logger = logging.getLogger(__name__)

# DNAC's error envelope. The add-on has no generic parser for it — it
# classifies purely on HTTP status — but returning the real shape keeps a
# failed request legible in the add-on's own logs.
_ERROR_VERSION = "1.0"


def _dnac_error(status_code: int, error_code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"response": {"errorCode": error_code, "message": message},
                 "version": _ERROR_VERSION},
    )


def create_catalyst_server(state: CatalystTopologyState, config: dict) -> FastAPI:
    """Build the Catalyst Center API app.

    ``config`` is the ``catalyst:`` block from settings.yaml: ``username``,
    ``password`` and ``token_ttl_seconds``.
    """
    app = FastAPI(
        title="Cisco Catalyst Center API Emulator",
        description="Mock DNAC intent/data API for Splunk Network Intelligence demos",
        version=state.controller.get("release", "3.1.3.0"),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    username = config.get("username", "")
    password = config.get("password", "")
    token_ttl = int(config.get("token_ttl_seconds", 3600))
    # token -> absolute expiry (epoch seconds)
    tokens: dict[str, float] = {}

    def _prune_tokens(now: float) -> None:
        for stale in [t for t, exp in tokens.items() if exp <= now]:
            tokens.pop(stale, None)

    def require_token(x_auth_token: str | None = Header(None)) -> None:
        """Reject anything that is not a live token with a 401.

        401 specifically, not 403: the add-on's client replays a request once
        after re-authenticating on a 401, and raises on any other 4xx.
        """
        now = time.time()
        _prune_tokens(now)
        if not x_auth_token or tokens.get(x_auth_token, 0.0) <= now:
            logger.warning("Catalyst API rejected a request: bad or expired token")
            raise HTTPException(status_code=401, detail="Token is invalid or expired")

    # ------------------------------------------------------------------
    # Token. Accepts 200/201/202/204/206 on the client side; 200 is the
    # only one that also carries a body, so that is what we return.
    # ------------------------------------------------------------------
    @app.post("/dna/system/api/v1/auth/token")
    async def issue_token(request: Request):
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return _dnac_error(401, "UNAUTHENTICATED",
                               "Authentication is required to access this resource")
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
            supplied_user, _, supplied_pass = decoded.partition(":")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return _dnac_error(401, "UNAUTHENTICATED", "Malformed basic credentials")

        if supplied_user != username or supplied_pass != password:
            logger.warning("Catalyst token request rejected for user %r", supplied_user)
            return _dnac_error(401, "UNAUTHENTICATED", "Invalid username or password")

        token = secrets.token_hex(32)
        tokens[token] = time.time() + token_ttl
        # The client reads this as `.Token` — exact casing. A different key
        # yields None, which requests then omits, and every later call 401s in
        # a loop with no message that points at the real cause.
        return {"Token": token}

    # ------------------------------------------------------------------
    # Version probe. Runs on every input, once per hour per controller.
    # ------------------------------------------------------------------
    @app.get("/dna/intent/api/v1/dnac-release", dependencies=[Depends(require_token)])
    async def dnac_release():
        return cgen.generate_dnac_release(state)

    # ------------------------------------------------------------------
    # Sites — feeds NI's site vertices.
    # ------------------------------------------------------------------
    @app.get("/dna/intent/api/v1/sites", dependencies=[Depends(require_token)])
    async def sites(offset: int = 1, limit: int = 500):
        records = cgen.generate_sites(state)
        # DNAC sites paging is 1-based; the add-on walks until a short page.
        start = max(offset - 1, 0)
        return {"response": records[start:start + limit]}

    # ------------------------------------------------------------------
    # Device health — feeds NI's device vertices and its two Catalyst
    # health capabilities.
    # ------------------------------------------------------------------
    @app.get("/dna/intent/api/v1/device-health", dependencies=[Depends(require_token)])
    async def device_health(startTime: int | None = None, endTime: int | None = None,
                            offset: int = 1, limit: int = 500,
                            siteId: str | None = None, deviceRole: str | None = None,
                            health: str | None = None):
        records = cgen.generate_device_health(state)
        start = max(offset - 1, 0)
        page = records[start:start + limit]
        # totalCount must be a JSON int and consistent across pages, and it is
        # the logical device count — not the length of this page.
        return {"response": page, "totalCount": len(records)}

    # ------------------------------------------------------------------
    # Inventory. Declared before the /{device_id} route so that "count" is
    # not captured as a device identifier.
    # ------------------------------------------------------------------
    @app.get("/dna/intent/api/v1/network-device/count",
             dependencies=[Depends(require_token)])
    async def network_device_count():
        return cgen.generate_device_count(state)

    @app.get("/dna/intent/api/v1/network-device",
             dependencies=[Depends(require_token)])
    async def network_device(limit: int = 500, offset: int = 1,
                             hostname: str | None = None,
                             managementIpAddress: str | None = None,
                             macAddress: str | None = None,
                             serialNumber: str | None = None,
                             family: str | None = None,
                             role: str | None = None,
                             id: str | None = None):
        records = cgen.generate_device_inventory(state)
        if id:
            records = [r for r in records if r["id"] == id]
        return {"response": cgen.page_inventory(records, offset, limit)}

    @app.get("/dna/intent/api/v1/network-device/{device_id}",
             dependencies=[Depends(require_token)])
    async def network_device_by_id(device_id: str):
        records = [r for r in cgen.generate_device_inventory(state)
                   if r["id"] == device_id]
        if not records:
            return _dnac_error(404, "NOT_FOUND",
                               f"No device found with id {device_id}")
        return {"response": records}

    # ------------------------------------------------------------------
    # Interfaces. The legacy per-device query is the path the add-on
    # actually uses; the bulk route below is answered with a real 404 so
    # the collector falls back to it, which is the documented behaviour on
    # controllers that predate the bulk API.
    # ------------------------------------------------------------------
    @app.post("/dna/intent/api/v2/networkDevices/{device_id}/interfaces/query",
              dependencies=[Depends(require_token)])
    async def interfaces_query(device_id: str, request: Request):
        device = state.get_device(device_id)
        if device is None:
            return _dnac_error(404, "NOT_FOUND",
                               f"No device found with id {device_id}")

        try:
            body = await request.json()
        except ValueError:
            body = {}
        page_spec = ((body or {}).get("query") or {}).get("page") or {}
        # This route alone is 0-based, unlike every other paginated route in
        # the add-on. Page size is 1000.
        raw_offset = page_spec.get("offset", 0)
        raw_limit = page_spec.get("limit", 1000)
        try:
            page_offset = max(int(raw_offset), 0)
            page_limit = max(int(raw_limit), 1)
        except (TypeError, ValueError):
            page_offset, page_limit = 0, 1000

        start_ms = body.get("startTime") if isinstance(body, dict) else None
        end_ms = body.get("endTime") if isinstance(body, dict) else None

        rows = cgen.generate_device_interfaces(state, device, start_ms, end_ms)
        window = rows[page_offset:page_offset + page_limit]
        # totalCount is mandatory, must be a JSON int, and must equal the exact
        # number of rows for this device. An over-count makes the collector
        # request a page that never comes and then discard everything.
        return {"response": window, "totalCount": len(rows)}

    @app.get("/dna/data/api/v1/interfaces")
    async def bulk_interfaces(request: Request):
        """Deliberately unavailable.

        The Interface Statistics collector probes this bulk route first in
        `auto` mode and falls back to the legacy per-device query when it is
        absent. Answering it instead would require matching a stricter
        contract (flat rows, `page.count`, `interfaceIfIndex` on every row,
        and an abort if any shard device returns zero rows) for no benefit.

        Must be a 404 and must never be a 3xx: this collector runs with
        `allow_redirects=False`, so a redirect yields an unparseable empty
        body and aborts the poll with `count_or_response_unavailable`.
        """
        return _dnac_error(404, "NOT_FOUND",
                           "Bulk interface collection is not available on this controller")

    # ------------------------------------------------------------------
    # Physical topology — the only source of Catalyst edges in NI.
    # ------------------------------------------------------------------
    @app.get("/dna/intent/api/v1/topology/physical-topology",
             dependencies=[Depends(require_token)])
    async def physical_topology(nodeType: str | None = None):
        # `response` must be an OBJECT. The add-on turns a list body into one
        # event per element, and NI's `links{}` expansion then sees a fragment
        # per event and materializes no edges.
        return {"response": cgen.generate_physical_topology(state)}

    # ------------------------------------------------------------------
    # Assurance issues — NI's Catalyst alert source.
    # ------------------------------------------------------------------
    @app.get("/dna/data/api/v1/assuranceIssues", dependencies=[Depends(require_token)])
    async def assurance_issues(limit: int = 25, offset: int = 1,
                               startTime: int | None = None,
                               endTime: int | None = None,
                               sortBy: str = "firstOccurredTime",
                               order: str = "asc",
                               issueStatus: str | None = None):
        rows = cgen.generate_assurance_issues(state, startTime, endTime)
        page = cgen.page_issues(rows, offset, limit)
        # `page` is mandatory. When `offset`/`limit` are present they must echo
        # the request exactly, or the entire issue poll is discarded.
        return {"response": page,
                "page": {"count": len(rows), "offset": offset, "limit": limit}}

    # ------------------------------------------------------------------
    # Emulator-local, not part of the DNAC contract.
    # ------------------------------------------------------------------
    @app.get("/health")
    async def health():
        summary = state.summary()
        return {"status": "ok", "controller": "catalyst-center",
                "release": state.controller.get("release", ""),
                "devices": summary["devices"], "sites": summary["sites"],
                "links": summary["links"], "interfaces": summary["interfaces"]}

    return app
