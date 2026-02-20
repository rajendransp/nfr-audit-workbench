# NFR Rule Documentation

This folder documents the current regex rule packs used by `nfr_scan.py`.

## Rule Packs

| Pack | Rule Count | Top Level |
| --- | ---:| --- |
| `rules/dotnet_rules.json` | 23 | `dotnet` |
| `rules/frontend_rules.json` | 17 | `front_end` |
| `rules/angularjs_migration_rules.json` | 10 | `front_end` |
| `rules/combined_concurrency_db_ruleset.json` | 17 | `dotnet` |
| `rules/razor_rules.json` | 6 | `front_end` |
| `rules/rest_api_rules.json` | 18 | `rest_api` |
| `rules/all_rules.json` | 64 | mixed |
| `rules/safe_ai_rules.json` | 10 | `safe_ai` |

## Category Distribution

### Dotnet (`rules/dotnet_rules.json`)
- `concurrency`: 12
- `loading`: 6
- `performance`: 5

### Front End (`rules/frontend_rules.json`)
- `loading`: 8
- `concurrency`: 5
- `performance`: 4

### Angular Migration (`rules/angularjs_migration_rules.json`)
- `migration`: 10

### Combined Concurrency + DB (`rules/combined_concurrency_db_ruleset.json`)
- `thundering_herd`: 7
- `db_invocation`: 4
- `cache_candidate`: 1
- `cache_stampede`: 1
- `coalescing_candidate`: 1
- `concurrency_limits`: 1
- `file_io_loop`: 1
- `internal_api_invocation`: 1

### Razor (`rules/razor_rules.json`)
- `loading`: 4
- `performance`: 1
- `concurrency`: 1

### REST API (`rules/rest_api_rules.json`)
- `loading`: 9
- `concurrency`: 4
- `performance`: 4
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
- UI supports validation-level triage (`Confirmed Issue` vs `False Positive / Non-Issue`) for reviewed findings.

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

Run AngularJS migration pack:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\angularjs_migration_rules.json
```

Run combined concurrency + DB pack:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\combined_concurrency_db_ruleset.json
```

Run REST API only:

```powershell
python nfr_scan.py --path C:\Development\CodeDocs\boldbi-server --rules rules\rest_api_rules.json
```

## Detailed Catalog

See `rules_catalog.md`.

## Scan Behavior Reference

See `scan_modes.md` for full vs incremental vs resume behavior, `--max-llm 0` regex-only output semantics, and Safe-AI scan modes.
Run-folder output is the default layout (`reports/runs/<project>__<timestamp>/`); use `--output-layout flat` for legacy placement.
