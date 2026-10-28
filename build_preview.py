"""Build a self-contained static preview of the topology view.

Snapshots the live /api/topology and /api/business payloads and bakes them into
web/topology-preview.html as a body-only fragment, so the artifact renders
without the emulator running.
"""

import json
import re
import sys
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).parent
BASE = "http://localhost:8080"


def get(path):
    return json.loads(urllib.request.urlopen(BASE + path).read().decode("utf-8"))


def main():
    topo = get("/api/topology")
    biz = get("/api/business")
    status = get("/api/status")

    src = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

    # Extract the <style> and <script> bodies from the live dashboard.
    style = re.search(r"<style>(.*?)</style>", src, re.S).group(1)
    script = re.search(r"<script>(.*?)</script>", src, re.S).group(1)
    body = re.search(r"<body>(.*?)<div class=\"tt\" id=\"tt\"></div>", src, re.S).group(1)

    # Swap the live fetch for the baked-in snapshot.
    snapshot = (
        "const __SNAP = { topo: " + json.dumps(topo)
        + ", biz: " + json.dumps(biz)
        + ", status: " + json.dumps(status) + " };\n"
    )
    script = script.replace(
        "const getJSON = async u => (await fetch(u)).json();",
        "const getJSON = async u => {\n"
        "  if (u.startsWith('/api/topology')) return __SNAP.topo;\n"
        "  if (u.startsWith('/api/business')) return __SNAP.biz;\n"
        "  if (u.startsWith('/api/status')) return __SNAP.status;\n"
        "  if (u.startsWith('/api/events')) return [];\n"
        "  if (u.startsWith('/api/security-events')) return [];\n"
        "  return null;\n"
        "};",
    )
    # Static preview: no polling, no scenario POSTs.
    script = script.replace("setInterval(loadDynamic, 8000);", "")
    script = script.replace(
        "async function trigger(name) {\n  await fetch(`/api/scenarios/${encodeURIComponent(name)}/trigger`, { method: 'POST' });\n  setTimeout(loadDynamic, 1200);\n}",
        "async function trigger(name) { alert('Scenario triggers require the live emulator at http://localhost:8080'); }",
    )
    script = script.replace(
        "async function scenCtl(a) { await fetch(`/api/scenarios/${a}`, { method: 'POST' }); loadDynamic(); }",
        "async function scenCtl(a) { alert('Scenario controls require the live emulator at http://localhost:8080'); }",
    )

    frag = (
        "<style>" + style + "</style>\n"
        + body
        + '<div class="tt" id="tt"></div>\n'
        + "<script>\n" + snapshot + script + "\n</script>\n"
    )

    out = ROOT / "web" / "topology-preview.html"
    out.write_text(frag, encoding="utf-8")
    print(f"Wrote {out} ({len(frag):,} bytes)")
    print(f"Snapshot: {len(topo['nodes'])} nodes, {len(topo['links'])} links, "
          f"{len(topo['sites'])} sites, {biz['totals']['clients']} clients")


if __name__ == "__main__":
    main()
