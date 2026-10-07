#!/usr/bin/env python3
"""IOC Lookup: check hashes, IPs, domains, and URLs against VirusTotal and AbuseIPDB."""
import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

CACHE_FILE = Path(".ioc_cache.json")
CACHE_TTL = 24 * 3600   # seconds
VT_DELAY = 15           # free tier allows ~4 requests/minute
TIMEOUT = 20

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def refang(value):
    """Turn defanged indicators (hxxp, [.]) back into normal form."""
    value = value.strip().replace("[.]", ".").replace("(.)", ".")
    return re.sub(r"^hxxp", "http", value, flags=re.I)


def detect_type(value):
    if HASH_RE.match(value):
        return "hash"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def ts(epoch):
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------- VirusTotal ----------
def query_virustotal(indicator, itype):
    if not VT_KEY:
        return {"error": "VT_API_KEY not set"}
    if itype == "hash":
        path = f"files/{indicator}"
    elif itype == "ip":
        path = f"ip_addresses/{indicator}"
    elif itype == "domain":
        path = f"domains/{indicator}"
    else:
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        path = f"urls/{url_id}"

    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                         headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}

    if r.status_code == 404:
        return {"found": False}
    if r.status_code == 401:
        return {"error": "invalid VirusTotal API key"}
    if r.status_code == 429:
        return {"error": "VirusTotal rate limit hit, wait and retry"}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}

    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    out = {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "last_analysis": ts(attrs.get("last_analysis_date")),
        "link": f"https://www.virustotal.com/gui/search/{indicator if itype != 'url' else url_id}",
    }
    if itype == "hash":
        out.update({
            "name": attrs.get("meaningful_name"),
            "file_type": attrs.get("type_description"),
            "size_bytes": attrs.get("size"),
            "first_seen": ts(attrs.get("first_submission_date")),
            "threat_label": (attrs.get("popular_threat_classification") or {})
                            .get("suggested_threat_label"),
        })
    elif itype == "ip":
        out.update({"country": attrs.get("country"), "owner": attrs.get("as_owner")})
    elif itype == "domain":
        out.update({"registrar": attrs.get("registrar"),
                    "created": ts(attrs.get("creation_date"))})
    elif itype == "url":
        out.update({"title": attrs.get("title"), "final_url": attrs.get("last_final_url")})
    return out


# ---------- AbuseIPDB ----------
def query_abuseipdb(ip):
    if not ABUSE_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set (optional)"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "abuse_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "last_reported": d.get("lastReportedAt"),
    }


# ---------- Verdict ----------
def compute_verdict(vt, abuse):
    rank = {"CLEAN": 0, "UNKNOWN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
    verdict = "UNKNOWN"
    if vt.get("found"):
        m, s = vt["malicious"], vt["suspicious"]
        verdict = "MALICIOUS" if m >= 5 else "SUSPICIOUS" if (m or s) else "CLEAN"
    score = (abuse or {}).get("abuse_score")
    if isinstance(score, int):
        a = "MALICIOUS" if score >= 75 else "SUSPICIOUS" if score >= 25 else None
        if a and rank[a] > rank[verdict]:
            verdict = a
    return verdict


# ---------- Cache ----------
def load_cache():
    try:
        return json.loads(CACHE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2))


# ---------- Main lookup ----------
def lookup(raw, cache, use_cache=True):
    indicator = refang(raw)
    itype = detect_type(indicator)
    if itype == "unknown":
        return {"indicator": raw, "type": "unknown", "verdict": "INVALID"}, False

    key = indicator.lower() if itype != "url" else indicator
    entry = cache.get(key)
    if use_cache and entry and time.time() - entry["cached_at"] < CACHE_TTL:
        return entry["result"], False

    vt = query_virustotal(indicator, itype)
    abuse = query_abuseipdb(indicator) if itype == "ip" else None
    result = {"indicator": indicator, "type": itype,
              "verdict": compute_verdict(vt, abuse),
              "virustotal": vt, "abuseipdb": abuse}
    if "error" not in vt:   # don't cache failures
        cache[key] = {"cached_at": time.time(), "result": result}
    return result, True


def print_result(res):
    print("=" * 60)
    print(f"Indicator : {res['indicator']}")
    print(f"Type      : {res['type']}")
    print(f"VERDICT   : {res['verdict']}")
    vt = res.get("virustotal")
    if vt:
        print("-" * 60 + "\nVirusTotal")
        if "error" in vt:
            print(f"  error: {vt['error']}")
        elif not vt["found"]:
            print("  Not found in VirusTotal")
        else:
            print(f"  Detections: {vt['malicious']} malicious, {vt['suspicious']} suspicious, "
                  f"{vt['harmless']} harmless, {vt['undetected']} undetected")
            for k, v in vt.items():
                if k in ("found", "malicious", "suspicious", "harmless", "undetected"):
                    continue
                if v not in (None, ""):
                    print(f"  {k.replace('_', ' ').title():<14}: {v}")
    ab = res.get("abuseipdb")
    if ab:
        print("-" * 60 + "\nAbuseIPDB")
        for k, v in ab.items():
            if v not in (None, ""):
                print(f"  {k.replace('_', ' ').title():<14}: {v}")


def write_csv(results, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "type", "verdict", "vt_malicious", "vt_suspicious", "abuse_score"])
        for r in results:
            vt, ab = r.get("virustotal") or {}, r.get("abuseipdb") or {}
            w.writerow([r["indicator"], r["type"], r["verdict"],
                        vt.get("malicious", ""), vt.get("suspicious", ""), ab.get("abuse_score", "")])


def main():
    p = argparse.ArgumentParser(description="Look up hashes, IPs, domains, and URLs.")
    p.add_argument("indicator", nargs="?", help="a hash, IP, domain, or URL")
    p.add_argument("-f", "--file", help="text file with one indicator per line")
    p.add_argument("--csv", help="save results to a CSV file")
    p.add_argument("--json", dest="json_out", help="save full results to a JSON file")
    p.add_argument("--no-cache", action="store_true", help="ignore cached results")
    args = p.parse_args()

    if not args.indicator and not args.file:
        p.error("provide an indicator or --file")
    if not VT_KEY:
        sys.exit("Missing VT_API_KEY. Copy .env.example to .env and add your key.")

    items = []
    if args.indicator:
        items.append(args.indicator)
    if args.file:
        lines = Path(args.file).read_text().splitlines()
        items += [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    items = list(dict.fromkeys(items))  # de-duplicate, keep order

    cache, results, hit_network = load_cache(), [], False
    for i, item in enumerate(items):
        if hit_network and len(items) > 1:
            print(f"(waiting {VT_DELAY}s for VirusTotal rate limit...)")
            time.sleep(VT_DELAY)
        res, hit_network = lookup(item, cache, use_cache=not args.no_cache)
        results.append(res)
        print_result(res)
        save_cache(cache)

    if args.csv:
        write_csv(results, args.csv)
        print(f"\nSaved CSV to {args.csv}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"Saved JSON to {args.json_out}")


if __name__ == "__main__":
    main()
