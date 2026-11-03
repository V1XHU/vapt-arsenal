#!/usr/bin/env python3
"""
js_api_map.py - map a single-page app's API surface and risky client-side sinks
from its JavaScript bundles.

It fetches BASE_URL, finds the <script src=...> bundles, downloads them, and reports:
  * API routes the front-end calls (/api/..., fetch/axios/XHR targets)
  * dangerous sinks (dangerouslySetInnerHTML, innerHTML, eval, document.write, ...)

Reads BASE_URL (and optional AUTH_HEADER) from ../config/targets.env, or takes a URL
argument. Authorized testing only. Read-only: it downloads and greps, nothing else.

Usage:
    python3 analysis/js_api_map.py [BASE_URL]
"""
import os
import re
import sys
import urllib.request
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, "..", "config", "targets.env")

API_PATTERNS = [
    re.compile(r"""['"`](/api/[A-Za-z0-9_\-./{}:]+)['"`]"""),
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""url\s*:\s*['"`]([^'"`]+)['"`]"""),
]
SINK_PATTERNS = {
    "dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML"),
    "innerHTML":               re.compile(r"\.innerHTML\s*="),
    "outerHTML":               re.compile(r"\.outerHTML\s*="),
    "eval":                    re.compile(r"\beval\s*\("),
    "Function()":              re.compile(r"\bnew Function\s*\("),
    "document.write":          re.compile(r"document\.write\s*\("),
    "insertAdjacentHTML":      re.compile(r"insertAdjacentHTML"),
    "localStorage":            re.compile(r"localStorage\.(?:get|set)Item"),
}
SCRIPT_SRC = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)


def load_env():
    cfg = {}
    if os.path.isfile(ENV_FILE):
        for line in open(ENV_FILE, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def fetch(url, header=None, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "vapt-arsenal/1.0"})
    if header and ":" in header:
        k, v = header.split(":", 1)
        req.add_header(k.strip(), v.strip())
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (authorized target)
        return r.read().decode("utf-8", "replace")


def main():
    cfg = load_env()
    base = sys.argv[1] if len(sys.argv) > 1 else cfg.get("BASE_URL")
    if not base:
        sys.exit("[!] no BASE_URL - pass a URL argument or set it in config/targets.env")
    header = cfg.get("AUTH_HEADER") or None
    base = base.rstrip("/")

    print(f"[*] fetching {base}")
    try:
        html = fetch(base, header)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"[!] could not fetch {base}: {e}")

    bundles = []
    for src in SCRIPT_SRC.findall(html):
        bundles.append(urllib.parse.urljoin(base + "/", src))
    bundles = sorted(set(bundles))
    print(f"[*] found {len(bundles)} script bundle(s)")

    api, sinks = {}, {}
    for b in bundles:
        try:
            js = fetch(b, header)
        except Exception as e:  # noqa: BLE001
            print(f"    [!] skip {b}: {e}")
            continue
        for pat in API_PATTERNS:
            for m in pat.findall(js):
                if m.startswith("/api") or m.startswith("http") or "/" in m:
                    api.setdefault(m, set()).add(b.rsplit("/", 1)[-1])
        for name, pat in SINK_PATTERNS.items():
            n = len(pat.findall(js))
            if n:
                sinks[name] = sinks.get(name, 0) + n

    print("\n=== API routes / request targets ===")
    for route in sorted(api):
        if route.startswith(("/api", "http")) or route.startswith("/"):
            print(f"  {route}")
    if not api:
        print("  (none detected)")

    print("\n=== client-side sinks (review for XSS / injection) ===")
    for name in sorted(sinks, key=lambda k: -sinks[k]):
        print(f"  {name:24} x{sinks[name]}")
    if not sinks:
        print("  (none detected)")

    print(f"\n[+] {len(api)} route(s), {sum(sinks.values())} sink hit(s) across "
          f"{len(bundles)} bundle(s).")


if __name__ == "__main__":
    main()
