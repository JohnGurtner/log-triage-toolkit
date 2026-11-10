# Log Triage Toolkit

> A small Python tool that triages SSH brute-force attempts from a Linux `auth.log`: it counts
> failures per source IP, flags likely brute-force sources, highlights any that **succeeded after**
> failing, and can enrich the worst offenders with AbuseIPDB.

Built from my CNIT 271 **IoT Security lab**, where I ran a Hydra SSH dictionary attack — this is the
blue-team side of that attack: spotting it in the logs.

## What it does

- Parses `Failed password` / `Accepted` lines per source IP
- Flags IPs over a configurable failure threshold
- Counts distinct usernames tried (spraying vs targeting)
- **Prioritizes** any flagged IP that also has a successful login — the real incident
- Optional AbuseIPDB enrichment (score, country, report count)

## Usage

```bash
# no dependencies needed for the core parse
python ssh_triage.py sample_auth.log --threshold 5

# with reputation enrichment (needs a key, see below)
pip install -r requirements.txt
python ssh_triage.py /var/log/auth.log --enrich
```

Example output on the included sample:

```
Parsed sample_auth.log
  unique source IPs with failures : 2
  IPs over threshold (5)          : 1
  successful logins observed      : 2

ip,failed,distinct_users,succeeded_after
203.0.113.5,12,9,1

[!] Priority: 1 brute-forced IP(s) had a SUCCESSFUL login: 203.0.113.5
```

## Secrets handling

The AbuseIPDB key is read from `ABUSEIPDB_KEY` in a local `.env` file (see `.env.example`).
**The `.env` is gitignored and never committed** — leaked API keys are an immediate red flag on any
security portfolio. Copy the example and add your own key:

```bash
cp .env.example .env
# edit .env and paste your key
```

## Files

| File | Purpose |
| --- | --- |
| `ssh_triage.py` | The tool |
| `sample_auth.log` | Safe sample log (documentation IPs) to try it on |
| `.env.example` | Template for your API key |
| `.gitignore` | Keeps `.env` and caches out of git |
| `requirements.txt` | `requests` + `python-dotenv` (only needed for `--enrich`) |

## Skills demonstrated

Python · log parsing (regex) · SSH brute-force detection · secrets hygiene (`.env` + `.gitignore`) ·
threat-intel enrichment · turning an attack into a detection
