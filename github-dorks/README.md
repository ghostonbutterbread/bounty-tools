# GitHub Dorks Tool

A Python CLI to run GitHub code search dorks for potential secrets, apply bounty-eligibility heuristics, and export findings to JSON and Markdown.

## Features

- Runs common GitHub dork queries from `dorks.json`
- Supports custom dork queries via CLI
- Marks findings as bounty-eligible using repo owner/topic filters
- Handles GitHub rate limiting (primary/secondary, retry-after)
- Exports reports to JSON and Markdown

## Requirements

- Python 3.9+
- GitHub token with access to code search APIs (`GITHUB_TOKEN`)

## Install

```bash
pip install -r requirements.txt
```

## Usage

Set your token:

```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

Basic scan:

```bash
python github_dorks.py
```

Use custom dork(s):

```bash
python github_dorks.py --dork "\"stripe_secret_key\"" --dork "\"twilio\" \"auth_token\""
```

Mark bounty-eligible repos by owner orgs:

```bash
python github_dorks.py --allowed-orgs "shopify,github,gitlab"
```

Mark bounty-eligible repos by topics:

```bash
python github_dorks.py --bounty-topics "bug-bounty,security,bounty"
```

Combine filters and customize outputs:

```bash
python github_dorks.py \
  --allowed-orgs "shopify,github" \
  --bounty-topics "bug-bounty" \
  --out-json findings.json \
  --out-md findings.md \
  --max-pages 3 \
  --per-page 100 \
  --verbose
```

## Output

- JSON report (`results.json` by default)
- Markdown report (`results.md` by default)

Each finding includes:
- dork query used
- file path and URL
- repository metadata
- eligibility status and reasons

## Notes

- This tool searches public code via GitHub APIs and is subject to API limits.
- Eligibility logic is heuristic. Real bug bounty scope should be validated against program policy.
- Use responsibly and comply with GitHub Terms and target disclosure policies.