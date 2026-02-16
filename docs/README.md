# NFR Rule Documentation

This folder documents the current regex rule packs used by `nfr_scan.py`.

## Rule Packs

| Pack | Rule Count | Top Level |
| --- | ---:| --- |
| `rules/dotnet_rules.json` | 21 | `dotnet` |
| `rules/frontend_rules.json` | 17 | `front_end` |
| `rules/razor_rules.json` | 6 | `front_end` |
| `rules/rest_api_rules.json` | 17 | `rest_api` |
| `rules/all_rules.json` | 61 | mixed |
| `rules/safe_ai_rules.json` | 10 | `safe_ai` |

## Category Distribution

### Dotnet (`rules/dotnet_rules.json`)
- `concurrency`: 10
- `loading`: 6
- `performance`: 5

### Front End (`rules/frontend_rules.json`)
- `loading`: 8
- `concurrency`: 5
- `performance`: 4

### Razor (`rules/razor_rules.json`)
- `loading`: 4
- `performance`: 1
- `concurrency`: 1

### REST API (`rules/rest_api_rules.json`)
- `loading`: 10
- `concurrency`: 4
- `performance`: 3
- `authentication`: 1

## Rule Metadata Fields

Common fields across packs:
- `id`
- `title`
- `category`
- `top_level_category`
- `sub_category`
- `severity`
- `confidence_hint`
- `pattern`
- `include_globs`
- `exclude_globs`
- `rationale`
- `ignore_comment_lines` (optional)

REST API specific:
- `enforcement_level` (`hard_fail` or `review`)

Safe-AI specific:
- `safe_ai_risk` (`high`/`medium`/`low`)

## Triage Guidance

- Use `top_level_category` for ownership split:
- `dotnet`, `front_end`, `rest_api`
- Use `sub_category` for NFR pivot:
- `concurrency`, `performance`, `loading`
- In CI hard-fail mode, prioritize `enforcement_level=hard_fail` for API rules.
- `--max-llm 0` keeps findings in final output as `regex_only` for manual triage.

## Safe-AI Outputs

Safe-AI dry-run and standalone mode produce:
- `safe_ai_risk__<project>__<timestamp>.json`
- `safe_ai_risk_digest__<project>__<timestamp>.md`
- `safe_ai_risk__<project>__<timestamp>.sarif`

## Run Examples

Run all packs:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\all_rules.json --include-roslyn
```

Run only Dotnet:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\dotnet_rules.json --include-roslyn
```

Run Frontend + Razor together:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\frontend_rules.json rules\razor_rules.json
```

Run REST API only:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\rest_api_rules.json
```

## Detailed Catalog

See `rules_catalog.md`.

## Scan Behavior Reference

See `scan_modes.md` for full vs incremental vs resume behavior, `--max-llm 0` regex-only output semantics, and Safe-AI scan modes.
Use `--output-layout run-folder` to group per-run artifacts under `reports/runs/<project>__<timestamp>/`.
