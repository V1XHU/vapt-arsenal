# reporting

## `report_generator.py`

Turns a findings JSON file into a polished, severity-sorted **PDF report** — CVSS table per
finding, proof-of-concept block, remediation, an executive summary, and a findings-by-severity
table.

```bash
pip install reportlab
python3 reporting/report_generator.py reporting/findings.example.json
# -> reporting/findings.example.pdf
```

Input shape — see [`findings.example.json`](findings.example.json):

```json
{
  "org": "Your Security Co.",
  "client": "Example Corp",
  "title": "Web Application Penetration Test Report",
  "project_id": "PT-2026-001",
  "scope": [{ "host": "app.example.com", "desc": "Primary web app (HTTPS)" }],
  "findings": [
    {
      "title": "...", "severity": "High", "cvss": "8.1",
      "description": ["paragraph", "..."],
      "poc": ["step or code line", "..."],
      "recommendations": ["fix", "..."]
    }
  ]
}
```

`severity` is one of `Critical`, `High`, `Medium`, `Low`, `Informational`; findings are sorted
most-severe first. Fonts fall back to reportlab's built-ins if no TTFs are installed, so the same
command produces the same report on any machine.
