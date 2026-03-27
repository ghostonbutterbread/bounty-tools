# Visual Recon

CLI tool to:
1. Read targets (URLs/domains)
2. Capture screenshots with Playwright
3. Brute-force common directories/files
4. Detect technologies via headers
5. Output JSON + Markdown reports
6. Generate a simple HTML screenshot viewer

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
python3 visual_recon.py --targets https://example.com example.org --output output
```

or:

```bash
python3 visual_recon.py --targets-file targets.txt --output output
```

## Outputs

- `output/results.json`
- `output/results.md`
- `output/viewer.html`
- `output/screenshots/*.png`
