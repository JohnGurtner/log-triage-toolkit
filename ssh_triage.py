#!/usr/bin/env python3
"""ssh_triage.py — triage SSH brute-force attempts from a Linux auth log.

Parses /var/log/auth.log (or any file passed in), counts failed and accepted
logins per source IP, flags likely brute-force sources, and — if an AbuseIPDB
API key is present in a .env file — enriches the top offenders with their abuse
score.

Built from my CNIT 271 IoT Security lab, where SSH was brute-forced with Hydra:
this is the detection/triage side of that attack.

Usage:
    python ssh_triage.py /var/log/auth.log
    python ssh_triage.py sample_auth.log --threshold 5 --enrich

Secrets: the AbuseIPDB key is read from ABUSEIPDB_KEY in a .env file.
Never commit the .env — see .gitignore.
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

# Matches lines like:
#   Failed password for invalid user admin from 203.0.113.5 port 55122 ssh2
#   Failed password for root from 203.0.113.5 port 55122 ssh2
#   Accepted password for pi from 203.0.113.9 port 48122 ssh2
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path):
    failed = defaultdict(int)
    accepted = defaultdict(int)
    users_tried = defaultdict(set)
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = FAILED_RE.search(line)
                if m:
                    failed[m["ip"]] += 1
                    users_tried[m["ip"]].add(m["user"])
                    continue
                m = ACCEPTED_RE.search(line)
                if m:
                    accepted[m["ip"]] += 1
    except FileNotFoundError:
        sys.exit(f"error: log file not found: {path}")
    return failed, accepted, users_tried


def enrich(ip):
    """Return AbuseIPDB (score, country, reports) for an IP, or None if no key/err."""
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    try:
        import requests  # imported lazily so the tool runs without it
    except ImportError:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        d = r.json()["data"]
        return d["abuseConfidenceScore"], d["countryCode"], d["totalReports"]
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="Triage SSH brute-force attempts from an auth log.")
    ap.add_argument("logfile", help="path to auth.log")
    ap.add_argument("--threshold", type=int, default=10,
                    help="failed attempts from one IP to flag as brute force (default 10)")
    ap.add_argument("--enrich", action="store_true",
                    help="look up flagged IPs on AbuseIPDB (needs ABUSEIPDB_KEY in .env)")
    args = ap.parse_args()

    # Load .env if python-dotenv is available; otherwise rely on real env vars.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    failed, accepted, users_tried = parse_log(args.logfile)

    flagged = sorted(
        ((ip, n) for ip, n in failed.items() if n >= args.threshold),
        key=lambda x: x[1], reverse=True,
    )

    print(f"\nParsed {args.logfile}")
    print(f"  unique source IPs with failures : {len(failed)}")
    print(f"  IPs over threshold ({args.threshold})       : {len(flagged)}")
    print(f"  successful logins observed       : {sum(accepted.values())}\n")

    writer = csv.writer(sys.stdout)
    header = ["ip", "failed", "distinct_users", "succeeded_after"]
    if args.enrich:
        header += ["abuse_score", "country", "reports"]
    writer.writerow(header)

    for ip, n in flagged:
        row = [ip, n, len(users_tried[ip]), accepted.get(ip, 0)]
        if args.enrich:
            info = enrich(ip)
            row += list(info) if info else ["n/a", "n/a", "n/a"]
        writer.writerow(row)

    # A flagged IP that *also* has a successful login is the one to investigate first.
    followup = [ip for ip, n in flagged if accepted.get(ip, 0) > 0]
    if followup:
        print(f"\n[!] Priority: {len(followup)} brute-forced IP(s) had a SUCCESSFUL login: "
              + ", ".join(followup), file=sys.stderr)


if __name__ == "__main__":
    main()
