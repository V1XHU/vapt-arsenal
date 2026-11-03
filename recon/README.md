# recon

A passive-to-active recon pipeline driven entirely by `config/targets.env`.

```bash
cp config/targets.example.env config/targets.env   # set TARGET_DOMAIN, BASE_URL, WORDLIST
./recon/recon.sh
```

Stages:

1. **`subfinder`** — passive subdomain enumeration for `TARGET_DOMAIN`.
2. **`httpx`** — probes the subdomains for live hosts (status, title, tech).
3. **`ffuf`** — content discovery against `BASE_URL`.
4. **`nuclei`** — runs vulnerability templates against the live hosts.

Output is written to `OUT_DIR/<domain>/<timestamp>/` (gitignored). The script checks every tool
is on `$PATH` first and tells you what's missing. Nothing runs against a target you didn't put in
`targets.env`.
