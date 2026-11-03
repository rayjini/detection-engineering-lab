# Detection Engineering Lab

A home detection engineering lab with a **detection-as-code** pipeline.

## Architecture

```
Windows VM (Sysmon) ──logs──▶ SIEM (Elastic / Splunk)
        ▲
        └── Atomic Red Team (attack simulation)

GitHub repo (Sigma rules, MITRE ATT&CK mapped)
        └── GitHub Actions: lint ▶ validate ▶ test vs sample logs ▶ convert (pySigma)
```

## Repository layout

| Path | Purpose |
|------|---------|
| `rules/` | Sigma detection rules, organized by platform, tagged with ATT&CK techniques |
| `tests/samples/` | Sample log events (true/false positives) used to test rules |
| `pipeline/` | Scripts for validation, testing, and pySigma conversion |
| `lab/sysmon/` | Sysmon configuration for the Windows VM |
| `lab/atomic-red-team/` | Atomic test notes and execution logs |
| `docs/` | Lab setup guides and write-ups |

## Status

- [ ] Lab: Windows VM + Sysmon
- [ ] SIEM ingestion
- [ ] Atomic Red Team setup
- [ ] Sigma rules + ATT&CK mapping
- [ ] CI: lint & validate
- [ ] CI: test against sample logs
- [ ] CI: pySigma conversion
