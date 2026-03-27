# Subdomain Takeover Monitor

CLI tool to identify potential subdomain takeover risks using DNS checks and known service fingerprints.

## Features

- Accepts targets via CLI args and/or input file
- DNS-based checks:
  - CNAME resolution and dangling CNAME detection
  - A/AAAA/NS resolution
  - basic NS parent resolvability check (possible expired domain signal)
- Fingerprint matching for known vulnerable services:
  - GitHub Pages
  - Heroku
  - AWS S3
  - Azure
  - Fastly
  - Shopify
- Outputs both JSON and Markdown reports

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Pass targets directly

```bash
python3 subdomain_takeover.py app.example.com test.example.com
```

### Use file input

```bash
cat > targets.txt <<EOF
app.example.com
staging.example.com
EOF

python3 subdomain_takeover.py -f targets.txt
```

### Custom output paths and options

```bash
python3 subdomain_takeover.py -f targets.txt \
  --json-out reports/takeover.json \
  --md-out reports/takeover.md \
  --workers 40 \
  --timeout 4
```

### Use custom DNS resolvers

```bash
python3 subdomain_takeover.py -f targets.txt --resolver 1.1.1.1 --resolver 8.8.8.8
```

### Disable HTTP fingerprinting

```bash
python3 subdomain_takeover.py -f targets.txt --no-http
```

## Output

### JSON (`scan_results.json` by default)

Contains:
- scan summary (`total`, `potential_takeovers`, `unresolved`)
- detailed findings per target:
  - DNS records
  - HTTP response snippets/headers (if enabled)
  - matched vulnerable services with confidence/reasons
  - notes

### Markdown (`scan_results.md` by default)

Human-readable report with per-target findings.

## Notes

- Potential takeover detection is heuristic and may include false positives.
- Always validate flagged results manually before acting.
- Patterns can be extended in `patterns.json`.

## Pattern Format

Each service entry in `patterns.json` supports:
- `name`
- `cname_suffixes`
- `http_body_regex`
- `http_header_regex`
- `references`

## Example

```bash
python3 subdomain_takeover.py -f targets.txt
```

Expected console output:

```text
Scanned 2 target(s)
Potential takeovers: 1
JSON report: scan_results.json
Markdown report: scan_results.md
```
