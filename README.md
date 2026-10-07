# IOC Lookup

A command-line tool that takes an indicator of compromise (IOC), meaning a file hash, IP address, domain, or URL, and returns a consolidated reputation summary from **VirusTotal** and **AbuseIPDB**. It is built for the first step of SOC alert triage: "Is this thing known to be bad?"

New to the command line? See [GETTING_STARTED.md](GETTING_STARTED.md) for a step-by-step walkthrough written for non-technical users.

## Features

- **Automatic indicator typing.** Paste anything; the tool works out whether it is a hash, IP, domain, or URL.
- **Multi-source enrichment.** VirusTotal for all indicator types, AbuseIPDB for IPs (optional).
- **Single combined verdict:** `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`.
- **Bulk mode** from a text file, with automatic rate limiting.
- **Local result cache** (24 h) so repeat lookups cost no API quota.
- **Defang-aware input.** Accepts `hxxps://evil[.]com` as commonly pasted from threat reports.
- **Export** to CSV or JSON.

## How it works

```
 input ──► refang ──► detect type ──► cache hit? ──yes──► print result
                                          │ no
                                          ▼
                              VirusTotal API v3 query
                                          │
                              (IP only) AbuseIPDB query
                                          │
                                          ▼
                                   compute verdict
                                          │
                              write cache ─┴─► print / CSV / JSON
```

### 1. Normalization (`refang`)
Threat reports often defang indicators so they aren't clickable. The tool reverses `[.]`, `(.)`, and a leading `hxxp` before processing.

### 2. Type detection (`detect_type`)
Checked in this order:

| Order | Type | Rule |
|-------|------|------|
| 1 | `hash` | Regex for exactly 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters |
| 2 | `ip` | Parsed with Python's `ipaddress` module (IPv4 and IPv6) |
| 3 | `url` | Starts with `http://` or `https://` |
| 4 | `domain` | Regex for valid dot-separated labels with an alphabetic TLD |
| 5 | `unknown` | Anything else; reported as `INVALID` and no API call is made |

Hashes are tested first so a 32-character hex string is never mistaken for something else. IPs are tested before domains so dotted numbers don't match the domain pattern.

### 3. VirusTotal (API v3)
Each type maps to a different endpoint:

| Type | Endpoint |
|------|----------|
| hash | `GET /api/v3/files/{hash}` |
| ip | `GET /api/v3/ip_addresses/{ip}` |
| domain | `GET /api/v3/domains/{domain}` |
| url | `GET /api/v3/urls/{id}` where `id` is the URL, base64url-encoded with padding stripped |

Authentication is the `x-apikey` header. The tool reads `data.attributes.last_analysis_stats` (malicious / suspicious / harmless / undetected engine counts) and adds type-specific fields:

- **hash:** file name, file type, size, first submission date, suggested threat label
- **ip:** country, AS owner
- **domain:** registrar, creation date
- **url:** page title, final URL after redirects

HTTP errors are handled explicitly: `404` means the indicator is not in VirusTotal (reported as "not found," not as an error), `401` an invalid key, `429` a rate-limit hit.

### 4. AbuseIPDB (IPs only, optional)
Calls `GET /api/v2/check` with `maxAgeInDays=90` and returns the abuse confidence score, report count, country, ISP, usage type, and last-reported time. If no key is configured the step is skipped.

### 5. Verdict logic (`compute_verdict`)
The verdict is a simple, transparent heuristic, deliberately easy to audit and tune.

**From VirusTotal:**
- `malicious >= 5` → `MALICIOUS`
- any `malicious` or `suspicious` detection (but fewer than 5) → `SUSPICIOUS`
- zero detections → `CLEAN`
- not found → `UNKNOWN`

**From AbuseIPDB (can only escalate, never downgrade):**
- score `>= 75` → `MALICIOUS`
- score `>= 25` → `SUSPICIOUS`

The thresholds are constants in the code and should be tuned to your environment. A single engine flagging a file is often a false positive, which is why one detection is only `SUSPICIOUS`.

### 6. Rate limiting
The VirusTotal free tier allows roughly 4 requests per minute. In bulk mode the tool waits `VT_DELAY` (15 s) after any lookup that hit the network. Cached lookups don't trigger a delay.

### 7. Caching
Results are stored in `.ioc_cache.json` in the working directory, keyed by the lowercased indicator (URLs keep their case) with a timestamp. Entries older than 24 hours (`CACHE_TTL`) are ignored. Lookups that failed with an API error are **not** cached, so a rate-limit failure won't be remembered. "Not found" results are cached. Use `--no-cache` to force a fresh query.

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/<your-username>/ioc-lookup.git
cd ioc-lookup
pip install -r requirements.txt
cp .env.example .env      # Windows: copy .env.example .env
```

Edit `.env` and add your keys:

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key   # optional
```

Free keys: [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com).

## Usage

```bash
# Single indicator (type is auto-detected)
python ioc_lookup.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
python ioc_lookup.py 8.8.8.8
python ioc_lookup.py example.com
python ioc_lookup.py "hxxps://example[.]com/login"

# Bulk from a file (one per line, # for comments)
python ioc_lookup.py -f sample_iocs.txt

# Export results
python ioc_lookup.py -f sample_iocs.txt --csv results.csv --json results.json

# Bypass the cache
python ioc_lookup.py 8.8.8.8 --no-cache
```

| Flag | Description |
|------|-------------|
| `indicator` | A hash, IP, domain, or URL |
| `-f`, `--file` | Text file of indicators, one per line |
| `--csv PATH` | Save a summary table to CSV |
| `--json PATH` | Save full results to JSON |
| `--no-cache` | Ignore cached results |

### Example output

Illustrative; actual numbers vary over time.

```
============================================================
Indicator : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Type      : hash
VERDICT   : MALICIOUS
------------------------------------------------------------
VirusTotal
  Detections: 60 malicious, 0 suspicious, 0 harmless, 10 undetected
  File Type     : EICAR virus test files
  First Seen    : 2013-... UTC
```

The example hash is the EICAR test file, a harmless string that antivirus engines flag on purpose.

## Project structure

```
ioc-lookup/
├── ioc_lookup.py       # the tool (single file)
├── requirements.txt    # requests, python-dotenv
├── .env.example        # template for API keys
├── .gitignore          # keeps .env and cache out of Git
├── sample_iocs.txt     # example bulk input
├── README.md
└── GETTING_STARTED.md  # beginner tutorial
```

## Security and privacy notes

- **API keys live in `.env`, which is git-ignored.** Never commit it. If a key is ever exposed, revoke and regenerate it in the provider's dashboard.
- **Lookups send the indicator to third parties.** Don't query internal hostnames, private IPs, or hashes of confidential files, since indicators submitted to VirusTotal and AbuseIPDB may be visible to their communities.
- The tool only **looks up** indicators. It never downloads, uploads, or executes files or visits URLs.

## Limitations

- No automatic retry or backoff on `429` responses; the failed indicator is reported and you re-run later.
- Lookups run sequentially (by design, for the free-tier limit).
- A URL that VirusTotal has never scanned returns "not found"; the tool does not submit new URLs for scanning.
- The verdict is a heuristic. It supports triage decisions but doesn't replace analyst judgment.
- The cache is a single JSON file with no locking, so avoid running several instances at once in the same folder.

## Ideas for extension

- Add sources: AlienVault OTX, URLhaus and MalwareBazaar (abuse.ch), Shodan, GreyNoise
- Retry with exponential backoff on rate-limit errors
- Extract indicators automatically from a pasted email or log excerpt
- Output a formatted report (HTML or PDF) for incident tickets
- Unit tests with mocked API responses

## Disclaimer

For defensive and educational use. Respect the terms of service and rate limits of the APIs you use.
