# Scan Modes

This page explains how scanner modes affect findings selection, LLM review, and output files.

## Mode Matrix

| Mode | Key Flags | What Gets Scanned | What Goes To LLM | Main Use |
| --- | --- | --- | --- | --- |
| Full scan | `--no-incremental` | All findings from rules + optional Roslyn | Up to `--max-llm` per batch | Baseline reset / full audit |
| Incremental scan (default) | `--incremental` (default) | New or changed findings vs baseline | Only new/changed pending findings | Daily/CI scans |
| Resume queue | `--resume-queue <findings_queue__...json>` | Uses saved queue state | Only pending items in that queue | Continue interrupted run |
| LLM skipped | `--max-llm 0` | Full regex/Roslyn pre-scan pipeline | None | Fast triage without LLM |
| Safe-AI dry-run | `--safe-ai-dry-run` | Normal NFR findings + Safe-AI risk classification | None | Classify external-sharing risk before LLM |
| Safe-AI standalone | `--safe-ai-only --safe-ai-rules ...` | Safe-AI rules only | None | Independent data-sharing risk scan |

## Output Layout

- `--output-layout flat` (default): writes versioned artifacts directly under `reports/`.
- `--output-layout run-folder`: writes versioned artifacts under `reports/runs/<project>__<timestamp>/`.
- In both modes, compatibility pointers remain in `reports/`:
  - `findings.json`, `nfr_digest.md`, `nfr.sarif`, `fallback_findings.json`
  - Safe-AI pointers when generated: `safe_ai_risk.json`, `safe_ai_risk_digest.md`, `safe_ai_risk.sarif`

## Behavior Details

### Full Scan
- Disables incremental filtering.
- Rebuilds outputs for the current run timestamp.
- Updates baseline file for the scan path.

### Incremental Scan
- Uses persisted baseline (`reports/baselines/<project>.json` by default).
- Sends only new/changed findings to LLM.
- Unchanged historical findings are not re-reviewed.

### Resume Queue
- Queue file is source of truth for `pending` vs `reviewed`.
- Continues using the original output file naming for that queue.
- Best for pause/restart workflows across long LLM batches.

### `--max-llm 0` (Regex-Only Final Output)
- Skips LLM requests entirely.
- Final `findings__...json` still contains findings as:
  - `review_status=regex_only`
  - `llm_transport.error_kind=skipped`
- These are retained for manual triage and UI filtering.

Important:
- If you later want LLM-reviewed results for the same code snapshot, run a fresh scan.
- Do not rely on resuming a queue that already completed in regex-only mode.

### Safe-AI Dry-Run
- Runs normal scan pre-processing and writes risk outputs.
- Produces:
  - `safe_ai_risk__<project>__<timestamp>.json`
  - `safe_ai_risk_digest__<project>__<timestamp>.md`
  - `safe_ai_risk__<project>__<timestamp>.sarif`

### Safe-AI Standalone
- Runs Safe-AI rules independently (no NFR queue, no LLM validation).
- Good for policy checks before external provider usage.

## Recommended Commands

Full scan:

```powershell
python nfr_scan.py --path C:\repo --rules rules\all_rules.json --no-incremental
```

Full scan with grouped run folder output:

```powershell
python nfr_scan.py --path C:\repo --rules rules\all_rules.json --no-incremental --output-layout run-folder
```

Incremental (default):

```powershell
python nfr_scan.py --path C:\repo --rules rules\all_rules.json
```

Resume:

```powershell
python nfr_scan.py --resume-queue reports\findings_queue__myproj__YYYYMMDD_HHMMSS.json
```

Regex-only:

```powershell
python nfr_scan.py --path C:\repo --rules rules\all_rules.json --max-llm 0 --no-incremental
```

Safe-AI dry-run:

```powershell
python nfr_scan.py --path C:\repo --rules rules\all_rules.json --safe-ai-dry-run --safe-ai-policy-mode enforce
```

Safe-AI standalone:

```powershell
python nfr_scan.py --path C:\repo --safe-ai-only --safe-ai-rules rules\safe_ai_rules.json
```
