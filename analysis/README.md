# analysis

## `js_api_map.py`

Maps a single-page app's **API surface** and risky **client-side sinks** straight from its
JavaScript bundles — a fast way to learn what endpoints the front-end talks to and where it may
mishandle untrusted data, before you touch Burp.

```bash
python3 analysis/js_api_map.py                 # uses BASE_URL from config/targets.env
python3 analysis/js_api_map.py https://app.example.com
```

It fetches the page, finds every `<script src>` bundle, downloads them, and reports:

- **API routes / request targets** — `/api/...` paths and `fetch`/`axios`/XHR URLs.
- **Client-side sinks** — `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `document.write`,
  `insertAdjacentHTML`, `localStorage`, and similar, with a hit count each.

Standard-library only (no pip installs). Read-only: it downloads and greps, it does not send any
attack traffic. Authorized targets only; set `AUTH_HEADER` in `targets.env` for authenticated apps.
