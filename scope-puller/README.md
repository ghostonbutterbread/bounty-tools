# Scope Puller

`scope_puller.py` pulls public bug bounty scope details from HackerOne and Bugcrowd.

## Features

- Parses:
  - `https://hackerone.com/programs/<handle>`
  - `https://bugcrowd.com/<handle>/program`
- Fetches scope targets (assets/domains/URLs) where public data is available
- Checks bounty eligibility (best effort)
- Gets recent report statistics (best effort)
- Outputs JSON and Markdown
- Handles rate limiting (`429`) and transient errors with retries/backoff

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scope_puller.py \
  https://hackerone.com/programs/example \
  https://bugcrowd.com/example/program
```

Custom outputs:

```bash
python scope_puller.py \
  https://hackerone.com/programs/example \
  --json-out out.json \
  --md-out out.md
```

Retry/timeout tuning:

```bash
python scope_puller.py \
  https://bugcrowd.com/example/program \
  --timeout 30 \
  --max-retries 8 \
  --backoff 2.0
```

Filter for bounty-eligible targets only:

```bash
python scope_puller.py \
  https://hackerone.com/programs/example \
  --bounty-only
```

## Outputs

- `scope_results.json`
  - `generated_at_epoch`
  - `programs[]`
    - `platform`
    - `program_handle`
    - `program_name`
    - `bounty_eligible`
    - `scope_targets[]`
    - `recent_report_stats`
  - `failures[]`
- `scope_results.md`
  - Human-readable summary and scope tables

## Notes

- Bug bounty platforms can change HTML/API structures over time.
- Some scope/stats are not public without authentication; this script uses public access only.
- Bugcrowd extraction is heuristic and best-effort when no stable public API is exposed.