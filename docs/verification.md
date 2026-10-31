# Verification

Six suites assert behaviour rather than printing it. `verify_topology.py`,
`verify_addon_contract.py` and `verify_catalyst_contract.py` run offline; the
others need the emulator running and, for `verify_addon_live.py` and
`verify_splunk_e2e.py`, the local Splunk instance.

```bash
python verify_topology.py           # offline
python verify_addon_contract.py     # offline
python verify_catalyst_contract.py  # offline
python verify_addon_live.py       # live: emulator + Splunk container
python verify_scenarios.py        # live: emulator (+ Splunk container)
python verify_splunk_e2e.py       # live: emulator -> HEC -> Splunk search
```

## verify_topology.py — the dataset is self-consistent

- Response shapes match the publicly documented schemas for every endpoint
  family.
- All five device families are discoverable through neighbour discovery.
- Discovery is bidirectional: if A sees B on a port, B sees A on the matching
  port.
- Uncabled ports never report a connected state.
- No silent fallback descriptions: every human-readable string is derived
  from real model data, not a placeholder.
- MAC addresses are valid six-octet and unique across devices and clients.
- Every scenario references a device and network that exist.
- Every generated event is attributed to a specific device.

## verify_addon_contract.py — the integration contract holds

- The organization OpenAPI document passes the collector's discovery policy,
  and the derived endpoint names are exactly the strings the downstream
  analytics expects (see `notes/meraki-addon-contract.md`).
- `perPage` is declared for paginated endpoints so envelope unwrapping works.
- Every consumed route is registered at its documented path, and stale paths
  are gone.
- Each payload matches the field expressions the downstream consumer reads,
  including value-format rules (speeds as strings, disconnect enums).
- Finishes by exercising **all ~110 GET routes** and failing on any 5xx — this
  is what caught two handlers that had returned 500 since they were written.

## verify_catalyst_contract.py — the Catalyst Center contract holds

Builds the Catalyst Center app in-process and calls it through a test client
(see [catalyst.md](catalyst.md) and `notes/catalyst-addon-contract.md`):

- token exchange returns `Token` with exact casing; a wrong password, missing
  credentials, a missing token and an unknown token all get 401, never 403;
- inventory count equals the inventory length; inventory, interface and issue
  paging honour the requested offset and limit, and issues echo them back;
- device health scores sit in the bands the downstream analytics grades as
  healthy, with the exact radio key spellings;
- every interface of every device is returned with estate-unique ids, and the
  bulk interface route returns 404 rather than a redirect;
- physical topology is one object whose 35 links all resolve to known device
  and interface ids, all operationally up;
- issues are sorted by first occurrence and carry every field the collector
  emits;
- serials and MACs are unique, and exactly the three intended HQ switches are
  shared with the Meraki estate;
- every registered route answers without a 5xx.

The endpoint-catalog check reads the locally extracted add-on under
`.ni-inspect/` and is skipped when it is absent.

## verify_addon_live.py — reachable the way the collector reaches it

Every request is issued **from inside the Splunk container** over
`host.docker.internal`, which is the only vantage point that proves the
deployment works:

- container → host reachability on the API port;
- valid key accepted, invalid key rejected with 401, Bearer form accepted;
- the OpenAPI document serves and lists the discoverable operations;
- all ten data-feeding endpoints answer 200 with documented shapes;
- the save-time probe (a bare GET must not 404) passes for the topology
  endpoints;
- topology volume: 140 adjacencies, 70 links, 75 distinct endpoints.

## verify_scenarios.py — faults propagate and grade correctly

- Triggers a live uplink failure and asserts the flap reaches the L2 link
  state, the port enum, and neighbour discovery, and that the event names the
  right device and network.
- Triggers a CRC-error degradation on an access port and asserts the port
  stays link-up while carrying a genuine error string.
- Reproduces the downstream grading rules (see `notes/ni-integration.md`) to
  confirm the first fault grades critical via the uplink rule and the second
  via the error-count rule.
- Regression guard: a healthy access port must grade healthy, because the
  grading rules deliberately treat an unplugged access port as normal.

## verify_splunk_e2e.py — the webhook path

Enables HEC delivery, fires scenarios, and searches Splunk over its REST API
for the resulting webhook events, proving emulator → HEC → indexed event.
Left out of the default demo configuration so that anything appearing in
Splunk during a polling demo provably arrived by polling.
