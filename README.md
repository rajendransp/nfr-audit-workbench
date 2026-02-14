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

Compatibility pointers are also updated:

-   `findings.json`
-   `nfr_digest.md`
-   `nfr.sarif`

Finding objects include:

-   source metadata: `source`, `language`, `file_type`
-   triage metadata: `severity`, `confidence`, `effort`, `benefit`, `quick_win`
-   recommendation metadata: `why`, `recommendation`, `testing_notes`, `patch`

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
-   Severity/source/quick-win/search filters.
-   Flexible grid columns and pagination.
-   Resizable details panel.
-   Syntax-highlighted snippet + patch viewer.
-   Adjustable snippet size.

## Notes and limitations

-   Rule quality drives deterministic signal quality.
-   LLM judgment can still be noisy for ambiguous snippets.
-   Roslyn location data can be incomplete for some diagnostics.
-   Very large repositories should be scanned with tuned limits (`--max-findings`, `--max-llm`).

## Repository naming note

-   This repository does not use `nfr_audit/...` path prefixes.

## Suggested roadmap

1.  Add language packs beyond .NET defaults.
2.  Add richer dedup/root-cause grouping.
3.  Add CI mode for PR comments + baseline gate.
4.  Add telemetry correlation mode (p95/p99, timeouts, 5xx) for stronger prioritization.