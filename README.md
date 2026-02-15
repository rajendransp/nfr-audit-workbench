# NFR Audit Workbench

NFR Audit Workbench is a standalone personal project for identifyingnon-functional risks in source code and surfacing actionable fixes.

It combines deterministic code scanning with local LLM review so engineeringteams can prioritize reliability, scalability, and performance risks quickly.

## Core workflow

1.  Deterministic pre-scan

-   Regex/ripgrep rules for known risk patterns.
-   Optional Roslyn analyzer ingestion from `dotnet build` SARIF output.

2.  LLM validation (local Ollama)

-   Confirms whether each finding is a real issue.
-   Adds severity, confidence, effort vs benefit, quick-win signal, and fix guidance.

3.  Human-friendly reporting

-   Versioned JSON findings.
-   Markdown digest for stakeholders.
-   SARIF output for security/code-scanning integrations.
-   Interactive web UI for filtering and triage.

## Features

-   Local-first scanning and review.
-   .NET-focused default rule pack.
-   Roslyn + regex combined finding pipeline.
-   Severity, confidence, effort/benefit, and quick-win triage fields.
-   Versioned outputs per run.
-   UI with filters, pagination, resizable split panes, snippet resizing, syntax highlighting, and upload support.

## Requirements

-   Python 3.10+
-   `rg` (ripgrep) recommended for fast pre-scan (fallback mode exists).
-   `dotnet` (optional, only for Roslyn ingestion).
-   Ollama running locally for LLM review.
-   Windows PowerShell or Command Prompt.

## First-time setup (Windows)

Run:

```powershell
.setup_first_time.bat
```

This setup script:

-   Creates `.venv` if missing.
-   Installs required Python packages (`requests`, `python-dotenv`).
-   Attempts to install `rg` via `winget` when `rg` is missing.
-   Creates `reports/` and `reports/.gitkeep` if needed.

Activate the virtual environment:

```powershell
..venvScriptsactivate
```

## Environment variables

-   `NFR_OLLAMA_BASE_URL` (optional)
-   `NFR_OLLAMA_MODEL` (optional)
-   `OLLAMA_BASE_URL` (fallback)
-   `OLLAMA_MODEL` (fallback)

Defaults:

-   Base URL: `http://localhost:11434`
-   Model: `qwen3-coder:30b`

## CLI usage

Run scan:

```powershell
python nfr_scan.py --path C:developmentmy-service
```

Use a specific rule pack:

```powershell
python nfr_scan.py --path C:developmentmy-service --rules rules/dotnet_rules.json
python nfr_scan.py --path C:developmentmy-frontend --rules rules/frontend_rules.json
python nfr_scan.py --path C:developmentmy-api --rules rules/rest_api_rules.json
python nfr_scan.py --path C:developmentmy-ui --rules rules/razor_rules.json
```

Run multiple packs together directly from CLI:

```powershell
python nfr_scan.py --path C:developmentmy-repo --rules rules/rest_api_rules.json rules/frontend_rules.json
```

Run all packs together:

```powershell
python nfr_scan.py --path C:developmentmy-repo --rules rules/all_rules.json
```

Run standalone Safe-AI risk scan (separate ruleset):

```powershell
python nfr_scan.py --path C:developmentmy-repo --safe-ai-only --safe-ai-rules rules/safe_ai_rules.json --max-findings 10000
```

Compare rule deltas between two runs:

```powershell
python scripts/compare_rule_deltas.py --before reports/rule_compare/before/findings_queue__project__timestamp.json --after reports/rule_compare/after/findings_queue__project__timestamp.json
```

Config-driven defaults:

-   The scanner loads `nfr_scan_config.json` by default.
-   You can use another config file with `--config <path>`.
-   Precedence is: `CLI argument` > `config file` > built-in default.

Run all findings through LLM in batches without prompts:

```powershell
python nfr_scan.py --path C:developmentmy-repo --rules rules/all_rules.json --max-llm 60 --auto-continue-batches
```

Ignore folders/files during scan (gitignore-like simple globs):

```powershell
python nfr_scan.py --path C:developmentmy-repo --rules rules/all_rules.json --ignore-file .nfrignore
```

Notes:

-   `.nfrignore` is read from the scan root (`--path`) by default.
-   Supports comments (`#`) and glob-style patterns (for example `node_modules/`, `dist/`, `**/*.min.js`).
-   Negation patterns (`!pattern`) are currently not supported.

LLM batching behavior:

-   `--max-llm` is the LLM batch size (default `60`).
-   `--regex-workers` controls regex rule parallelism (default `1`).
-   `--llm-provider` selects provider (`ollama`, `openai`, `openrouter`, `xai`, `gemini`; default `ollama`).
-   Safe AI policy controls for external providers:
-   `--safe-ai-policy-mode off|warn|enforce` (default `warn`)
-   `--safe-ai-allow-external-high-risk` (default off)
-   `--safe-ai-redact-medium` (default on)
-   `--safe-ai-dry-run` writes `safe_ai_risk__<project>__<timestamp>.json` and skips LLM review.
-   `--safe-ai-only` runs Safe-AI scanning as an independent pipeline (no NFR queue, no LLM validation).
-   `--safe-ai-rules` selects rule file(s) for standalone Safe-AI scanning (default `rules/safe_ai_rules.json`).
-   `--llm-workers` controls parallel LLM requests per batch (default `1`).
-   For local stability, start with `--llm-workers 2` and increase gradually if hardware has headroom.
-   `--prioritize-llm-queue` (default on) sends higher-priority findings first (S1/S2 and higher-confidence hints).
-   `--dedup-before-llm` (default on) clusters similar findings (same file/function/rule/match) and sends representative items to LLM.
-   `--use-llm-cache` (default on) caches LLM decisions across runs in `--llm-cache-file` (default `llm_review_cache.json` under output dir).
-   `--adaptive-llm-workers` (default on) reduces workers on timeout/fallback spikes and slowly increases after stable batches.
-   `--prefer-patch-s1s2` (default on) retries once with a patch-focused prompt when S1/S2 findings return `patch=unknown`.
-   `--prefer-patch-all-severities` (default on) enables patch-focused retry for non-S1/S2 findings when confidence is high enough.
-   `--patch-min-confidence` (default `0.6`) gates non-S1/S2 patch retry and low-confidence patch generation.
-   `--patch-repair-retries` (default `1`) retries with explicit no-op feedback when patch output is a no-op.
-   `--use-patch-template-cache` (default on) and `--patch-template-cache-file` reuse successful patch templates across similar findings.
-   `--fast-high-confidence-routing` enables fast mode: high-confidence regex findings are auto-confirmed without LLM.
-   `--high-confidence-threshold` (default `0.9`) and `--high-confidence-max-severity` (default `S2`) control fast-route eligibility.
-   `--auto-demote-noisy-rules` (default on) uses historical rule quality to demote noisy rules in queue ordering.
-   Rule quality settings: `--rule-quality-file`, `--noisy-rule-min-reviewed`, `--noisy-rule-max-precision`, `--noisy-rule-max-fallback-rate`.
-   Diff/PR mode: `--diff-base <git-ref>` limits scan to changed files/lines vs `--diff-head` (default `HEAD`); add `--diff-files-only` to scan all lines in changed files.
-   CI policy modes: `--ci-mode off|warn|soft-fail|hard-fail` with thresholds by severity (`--ci-threshold-s1..s4`) and overall (`--ci-max-total`).
-   Patch CI thresholds: `--ci-min-patch-generated` and `--ci-max-patch-no-op`.
-   CI trust-tier scoping: `--ci-count-trust-tiers` (comma-separated from `llm_confirmed,fast_routed,fallback,regex_only,roslyn`).
-   API rules support `enforcement_level` (`hard_fail` or `review`) for CI blocking behavior.
-   Rules can optionally set `ignore_comment_lines: true` to suppress comment-only regex matches.
-   `NFR-API-005` caching check is opt-in via `NFR_CACHE_REQUIRED`/`PublicCacheable` markers and skips authorized or user/tenant-specific endpoints.
-   `NFR-DOTNET-003` is tuned to target task-like blocking `.Result` patterns and avoid common `OperationResult<T>.Result` false positives.
-   Frontend XSS rule is split into:
  `NFR-FE-005A` (high-risk dynamic source to raw HTML, S1) and
  `NFR-FE-005B` (generic raw HTML usage, S3 review warning).
-   FE/Razor packs exclude common vendor/minified paths by default to reduce non-actionable noise.
-   LLM patch guard marks no-op diffs as `patch_quality=no_op` and downgrades patch output to `unknown`.
-   S1/S2 findings now bias the LLM prompt toward returning a minimal safe patch where possible.
-   Reports include `summary.patch_metrics` (`generated`, `unknown`, `no_op_dropped`, `valid_quality`, `safe_generated`, `needs_attention_generated`, `template_cache_applied`, `total_reviewed`).
-   Reports include `summary.ai_policy_metrics` (`external_boundary_findings`, `blocked_findings`, `redacted_findings`, `high_risk_findings`, `medium_risk_findings`).
-   UI detail pane always shows patch status and displays a “Patch unavailable” message when patch content is `unknown`.
-   UI detail pane shows patch safety tags (`safe` vs `needs_attention`) and reason.
-   Incremental mode is on by default (`--incremental`): only new/changed findings are sent to LLM versus persisted baseline.
-   Use `--no-incremental` for full scan mode.
-   Baseline persistence defaults to `<output-dir>/<baseline-dir>/<project>.json` where `--baseline-dir` defaults to `baselines`.
-   Timeout/retry controls: `--llm-connect-timeout-seconds` (default `20`), `--llm-read-timeout-seconds` (default `180`), `--llm-retries` (default `2`), `--llm-retry-backoff-seconds` (default `1.5`).
-   Retries are used for retriable failures (timeout, connection errors, HTTP `429`, HTTP `5xx`). Non-retriable failures are logged and fallback review is used.
-   After each batch, interactive runs ask whether to continue with the next batch.
-   Use `--auto-continue-batches` for unattended runs (process all batches automatically).
-   Use `--max-llm 0` to skip LLM review.
-   Provider env wiring:
-   `openai`: `OPENAI_API_KEY`, optional `OPENAI_MODEL`, `OPENAI_BASE_URL`
-   `openrouter`: `OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL`, `OPENROUTER_BASE_URL`
-   `xai`: `XAI_API_KEY`, optional `XAI_MODEL`, `XAI_BASE_URL`
-   `gemini`: `GEMINI_API_KEY`, optional `GEMINI_MODEL`, `GEMINI_BASE_URL`
-   Queue/progress is written to `findings_queue__<project>__<timestamp>.json`.
-   Resume a stopped run with `--resume-queue <path-to-findings_queue__...json>`; pending findings continue in the same output files.
-   When `--resume-queue` is used, the queue state is the source of truth for pending/reviewed items and original output file names.
-   Prompt slimming is automatic: S3/S4 findings send reduced snippet context to LLM; S1/S2 keep full context.
-   Rule pipeline logging now prints per-rule `raw -> unique -> pending -> representatives -> sent_to_llm`.
-   Files in vendor/minified paths are tagged as `action_bucket=dependency_risk` (upgrade/CSP path) instead of app-fix backlog.

Default parameter values (from `nfr_scan_config.json`):

-   `path`: `.`
-   `rules`: `rules/dotnet_rules.json`
-   `output_dir`: `reports`
-   `context_lines`: `20`
-   `max_findings`: `300`
-   `regex_workers`: `1`
-   `max_llm`: `60`
-   `llm_provider`: `ollama`
-   `auto_continue_batches`: `false`
-   `llm_workers`: `1`
-   `llm_retries`: `2`
-   `llm_retry_backoff_seconds`: `1.5`
-   `llm_connect_timeout_seconds`: `20.0`
-   `llm_read_timeout_seconds`: `120.0`
-   `safe_ai_policy_mode`: `warn`
-   `safe_ai_allow_external_high_risk`: `false`
-   `safe_ai_redact_medium`: `true`
-   `safe_ai_dry_run`: `false`
-   `safe_ai_only`: `false`
-   `safe_ai_rules`: `rules/safe_ai_rules.json`
-   `prefer_patch_s1s2`: `true`
-   `prefer_patch_all_severities`: `true`
-   `patch_min_confidence`: `0.6`
-   `patch_repair_retries`: `1`
-   `openai_api_key`: `""`
-   `openai_model`: `""`
-   `openai_base_url`: `""`
-   `openrouter_api_key`: `""`
-   `openrouter_model`: `""`
-   `openrouter_base_url`: `""`
-   `xai_api_key`: `""`
-   `xai_model`: `""`
-   `xai_base_url`: `""`
-   `gemini_api_key`: `""`
-   `gemini_model`: `""`
-   `gemini_base_url`: `""`
-   `llm_cache_file`: `llm_review_cache.json`
-   `use_llm_cache`: `true`
-   `patch_template_cache_file`: `patch_template_cache.json`
-   `use_patch_template_cache`: `true`
-   `dedup_before_llm`: `true`
-   `prioritize_llm_queue`: `true`
-   `adaptive_llm_workers`: `true`
-   `fast_high_confidence_routing`: `false`
-   `high_confidence_threshold`: `0.9`
-   `high_confidence_max_severity`: `S2`
-   `auto_demote_noisy_rules`: `true`
-   `rule_quality_file`: `rule_quality.json`
-   `noisy_rule_min_reviewed`: `20`
-   `noisy_rule_max_precision`: `0.25`
-   `noisy_rule_max_fallback_rate`: `0.2`
-   `resume_queue`: `""`
-   `temperature`: `0.1`
-   `baseline`: `""`
-   `only_new`: `false`
-   `incremental`: `true`
-   `baseline_dir`: `baselines`
-   `include_roslyn`: `false`
-   `dotnet_target`: `""`
-   `dotnet_configuration`: `Debug`
-   `dotnet_timeout_seconds`: `900`
-   `ignore_file`: `.nfrignore`
-   `diff_base`: `""`
-   `diff_head`: `HEAD`
-   `diff_files_only`: `false`
-   `ci_mode`: `off`
-   `ci_max_total`: `-1`
-   `ci_threshold_s1`: `-1`
-   `ci_threshold_s2`: `-1`
-   `ci_threshold_s3`: `-1`
-   `ci_threshold_s4`: `-1`
-   `ci_min_patch_generated`: `-1`
-   `ci_max_patch_no_op`: `-1`
-   `ci_count_trust_tiers`: `llm_confirmed,fast_routed,fallback,regex_only,roslyn`

CI note:

-   In `hard-fail` mode, default blocking scope is `llm_confirmed,fast_routed` unless `--ci-count-trust-tiers` is explicitly provided.
-   `fallback` findings are reported as warn-only in default `hard-fail` behavior.

With Roslyn ingestion:

```powershell
python nfr_scan.py --path C:developmentmy-service --include-roslyn
```

With explicit solution/project target:

```powershell
python nfr_scan.py --path C:developmentmy-service --include-roslyn --dotnet-target C:developmentmy-serviceMyService.sln
```

Only new issues vs baseline:

```powershell
python nfr_scan.py --path C:developmentmy-service --baseline reports/findings.json --only-new
```

## Output artifacts

Each run writes versioned files:

-   `findings__<project>__<timestamp>.json`
-   `nfr_digest__<project>__<timestamp>.md`
-   `nfr__<project>__<timestamp>.sarif`
-   `fallback_findings__<project>__<timestamp>.json`

Compatibility pointers are also updated:

-   `findings.json`
-   `nfr_digest.md`
-   `nfr.sarif`
-   `fallback_findings.json`

Finding objects include:

-   source metadata: `source`, `language`, `file_type`
-   grouping metadata: `top_level_category` (`dotnet`/`front_end`/`rest_api`), `sub_category` (`concurrency`/`performance`/`loading`)
-   triage metadata: `severity`, `confidence`, `effort`, `benefit`, `quick_win`
-   trust metadata: `trust_tier` (`llm_confirmed`/`fast_routed`/`fallback`/`regex_only`/`roslyn`)
-   action metadata: `action_bucket` (`app_code`/`dependency_risk`), `action_hint`
-   reliability metadata: `llm_error_kind`, `llm_attempts`, `llm_retried`
-   fallback governance metadata: `llm_transport.fallback_used`, dedicated fallback report JSON
-   rule quality metadata (`summary.rule_quality`): reviewed, confirmed, precision, fallback rate, timeout-like rate, top false-positive reasons per rule
-   noise metadata: `summary.rule_noise_recommendations` (recommended `monitor`/`demote`/`tune`/`disable` actions)
-   recommendation metadata: `why`, `recommendation`, `testing_notes`, `patch`
-   throughput summary metadata (`summary.throughput`): stage timings (`regex`, `roslyn`, `llm`, `total`) and LLM latency stats (`avg_ms`, `p50_ms`, `p95_ms`)

## UI usage

Start local UI server:

```powershell
python ui/run_ui.py
```

Open:

`http://127.0.0.1:8787/ui/index.html`

UI capabilities:

-   Findings file dropdown for versioned results.
-   Upload findings JSON and explore it (`uploaded__<timestamp>__<name>.json`).
-   Severity/source/quick-win/fallback/search filters.
-   Trust-tier filter and badge (`Regex-only`, `LLM-confirmed`, `Fallback`, `Fast-routed`, `Roslyn`).
-   Top-level and sub-category filters (`dotnet`/`front_end`/`rest_api` and `concurrency`/`performance`/`loading`).
-   Sortable table columns (including top-level/sub-category grouping columns).
-   Flexible grid columns and pagination.
-   Resizable details panel.
-   Syntax-highlighted snippet + patch viewer.
-   Adjustable snippet size.

## Notes and limitations

-   Rule quality drives deterministic signal quality.
-   LLM judgment can still be noisy for ambiguous snippets.
-   Roslyn location data can be incomplete for some diagnostics.
-   Very large repositories should be scanned with tuned limits (`--max-findings`, `--max-llm`).

## Rule Harness Tests

Run rule regression tests:

```powershell
python -m unittest discover -s tests -v
```

These tests validate rule behavior against curated true-positive and false-positive fixtures.

## Repository naming note

-   This repository does not use `nfr_audit/...` path prefixes.

## Suggested roadmap

1.  Add language packs beyond .NET defaults.
2.  Add richer dedup/root-cause grouping.
3.  Add CI mode for PR comments + baseline gate.
4.  Add telemetry correlation mode (p95/p99, timeouts, 5xx) for stronger prioritization.
