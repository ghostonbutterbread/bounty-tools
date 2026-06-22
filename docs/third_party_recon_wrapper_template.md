# Third-Party Recon Wrapper Template

Use this template when adding wrappers for external recon tools such as Corsy.
Wrappers should preserve high-volume tool output as recon artifacts and promote
only high-confidence vulnerability findings into bounty-core.

## Canonical Output

Resolve the program, family, and lane with `recon_storage.recon_bucket()` and
write each run under Ryushe's preferred tool/target/runs/date/run-id layout:

```text
recon/<tool>/<target>/runs/<YYYY-MM-DD>/<run_id>/
```

Each run directory should contain:

```text
command.txt          exact command and environment notes, with secrets redacted
stdout.txt           captured stdout
stderr.txt           captured stderr
raw/                 unmodified tool-native files
parsed/              normalized JSON/JSONL/CSV summaries
manifest.json        run metadata, file inventory, counts, versions, exit code
```

Recommended manifest fields:

```json
{
  "tool": "corsy",
  "target": "https://example.com",
  "program": "acme",
  "family": "web_bounty",
  "lane": "web",
  "run_id": "20260428T120000Z_ab12cd34",
  "started_at": "2026-04-28T12:00:00Z",
  "finished_at": "2026-04-28T12:00:30Z",
  "exit_code": 0,
  "command_file": "command.txt",
  "stdout_file": "stdout.txt",
  "stderr_file": "stderr.txt",
  "raw_files": [],
  "parsed_files": [],
  "counts": {
    "raw_records": 0,
    "parsed_records": 0,
    "promotion_candidates": 0,
    "promoted_findings": 0
  }
}
```

## Promotion Gate

Do not write every recon result to the bounty-core findings ledger. Promote only
findings that pass a wrapper-specific high-confidence gate, such as verified
exploitability, sensitive exposure, or a deterministic security misconfiguration.

Promotion payloads should include:

- `source_tool`, `source_repo`, `program`, `family`, and `lane`
- A precise `asset` and `url`
- A conservative `severity`
- Evidence that explains why the result passed the gate
- A pointer back to the recon run `manifest.json`

Everything else stays in the recon run directory for later manual review.
