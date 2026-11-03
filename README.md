# VAPT Arsenal

A reproducible **WSL / Ubuntu toolkit** for web & API penetration testing and bug bounty —
recon, client-side/API analysis, and automated client-ready PDF reporting, wired together so an
assessment runs the same way every time.

Everything is **parameterized** (targets come from an env file, never hardcoded), so the same
scripts work across engagements without edits.

> ⚠️ **Authorized use only.** These tools are for systems you own or have **written permission**
> to test. Unauthorized scanning or exploitation is illegal. The author accepts no liability for
> misuse.

## Modules

| Module | What it does |
|--------|--------------|
| [`recon/`](recon/) | Subdomain → live-host → content-discovery → vuln-template pipeline (`subfinder` → `httpx` → `ffuf` → `nuclei`). |
| [`analysis/`](analysis/) | Pulls a SPA's JavaScript bundles and maps the **API routes** and risky **client-side sinks** they reveal. |
| [`reporting/`](reporting/) | Turns a findings JSON file into a polished, severity-sorted **PDF report** (CVSS table, risk matrix, TOC). |

## Quick start

```bash
git clone https://github.com/V1XHU/vapt-arsenal.git
cd vapt-arsenal

# 1. set your target (this file is gitignored — your scope never gets committed)
cp config/targets.example.env config/targets.env
$EDITOR config/targets.env

# 2. recon
./recon/recon.sh

# 3. map the front-end's API surface
python3 analysis/js_api_map.py

# 4. build a report from your findings
python3 reporting/report_generator.py reporting/findings.example.json
```

## Requirements

- **Recon:** [`subfinder`](https://github.com/projectdiscovery/subfinder),
  [`httpx`](https://github.com/projectdiscovery/httpx),
  [`ffuf`](https://github.com/ffuf/ffuf),
  [`nuclei`](https://github.com/projectdiscovery/nuclei) on `$PATH`
  (each script checks and tells you what's missing).
- **Analysis & reporting:** Python 3.9+. Reporting uses `reportlab`
  (`pip install reportlab`); PDF fonts fall back to built-ins if no TTFs are found.

## Layout

```
vapt-arsenal/
├── config/
│   └── targets.example.env     # copy to targets.env (gitignored) and fill in
├── recon/
│   └── recon.sh                # the recon pipeline
├── analysis/
│   └── js_api_map.py           # JS-bundle → API-route & sink mapper
└── reporting/
    ├── report_generator.py     # findings JSON → PDF
    └── findings.example.json   # sample input
```

## License

MIT — see [LICENSE](LICENSE).
