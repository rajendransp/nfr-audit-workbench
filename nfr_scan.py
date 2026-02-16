import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

import requests

try:
    import dotenv
except Exception:  # pragma: no cover
    dotenv = None


SEVERITY_ORDER = {"S1": 0, "S2": 1, "S3": 2, "S4": 3}
SEVERITY_LEVEL = {"S1": "error", "S2": "warning", "S3": "note", "S4": "note"}
ROSLYN_LEVEL_TO_S = {"error": "S1", "warning": "S2", "note": "S3", "none": "S4"}
DEFAULT_CONFIG_PATH = "nfr_scan_config.json"
DEPENDENCY_RISK_HINTS = (
    ".min.js",
    "/vendor/",
    "/vendors/",
    "/lib/",
    "/wwwroot/lib/",
    "/scripts/ej2/",
    "/jquery",
)

SYSTEM_PROMPT = (
    "You are a senior .NET reliability/performance reviewer. "
    "Be evidence-first and conservative: reject weak or mismatched findings. "
    "Return valid JSON only. No markdown. No prose outside JSON."
)

USER_TEMPLATE = """
Evaluate this pre-scan finding. Confirm if this is a real non-functional risk.

Validation policy (mandatory):
1) Use only evidence visible in the provided snippet + rule metadata.
2) If rule title/category does not match the code shown, reject the finding.
3) Ignore matches that are only in comments/docs/strings unless the rule explicitly targets those.
4) If snippet already contains the required mitigation (for example CancellationToken is already propagated), reject.
5) Do not infer missing code outside snippet. If uncertain, reject.

When rejecting:
- set isIssue=false
- keep severity from default context unless clearly lower
- why must briefly explain why this is not a valid issue for this snippet
- recommendation must be "No action needed for this snippet; rule likely false positive or needs tighter pattern."
- patch must be "unknown"
- changed_lines_reason must be ""

Return JSON with exactly these keys:
- isIssue: boolean
- severity: one of S1,S2,S3,S4
- confidence: number 0.0 to 1.0
- title: short title
- why: plain-language impact explanation
- recommendation: minimal, safe fix recommendation
- effort: one of low, medium, high
- benefit: one of low, medium, high
- quick_win: boolean
- testing_notes: array of short test ideas
- patch: unified diff string or \"unknown\" if insufficient context
- changed_lines_reason: short explanation for why changed lines are required (empty string if patch is unknown)

Rule:
{rule_json}

Rule-Specific Guidance:
{rule_guidance}

Patch Guidance:
{patch_guidance}

Patch Playbook:
{patch_playbook}

Semantic Context:
{semantic_context}

File: {file_path}
Line: {line}
Snippet:
{snippet}
""".strip()


def log_progress(message):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def load_env():
    if dotenv:
        dotenv.load_dotenv(override=False)


def parse_args():
    parser = argparse.ArgumentParser(description="NFR Audit Workbench scan + LLM review")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Optional config JSON path (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument("--path", default=".", help="Repository or service path to scan")
    parser.add_argument(
        "--rules",
        nargs="+",
        default=["rules/dotnet_rules.json"],
        help="One or more JSON rules files. Example: --rules rules/rest_api_rules.json rules/frontend_rules.json",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for reports",
    )
    parser.add_argument(
        "--output-layout",
        choices=["flat", "run-folder"],
        default="run-folder",
        help="Report layout: flat (legacy) or run-folder (reports/runs/<project>__<timestamp>).",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=20,
        help="Number of context lines around each match",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=300,
        help="Cap regex pre-scan findings before LLM review",
    )
    parser.add_argument(
        "--regex-workers",
        type=int,
        default=1,
        help="Concurrent workers for regex rule execution (1 keeps sequential behavior).",
    )
    parser.add_argument(
        "--max-llm",
        type=int,
        default=60,
        help="LLM batch size. Use 0 to skip LLM review.",
    )
    parser.add_argument(
        "--llm-provider",
        default="ollama",
        help="LLM provider: ollama|openai|openrouter|xai|gemini.",
    )
    parser.add_argument(
        "--auto-continue-batches",
        action="store_true",
        help="Process all LLM batches without interactive y/n prompts.",
    )
    parser.add_argument(
        "--llm-workers",
        type=int,
        default=1,
        help="Concurrent LLM requests per batch (1 keeps sequential behavior).",
    )
    parser.add_argument(
        "--llm-retries",
        type=int,
        default=2,
        help="Retries for retriable LLM failures (timeout/connection/5xx/429).",
    )
    parser.add_argument(
        "--llm-retry-backoff-seconds",
        type=float,
        default=1.5,
        help="Base backoff seconds for LLM retries (exponential: base, 2x, 4x...).",
    )
    parser.add_argument(
        "--llm-connect-timeout-seconds",
        type=float,
        default=20.0,
        help="Connect timeout for LLM HTTP requests.",
    )
    parser.add_argument(
        "--llm-read-timeout-seconds",
        type=float,
        default=120.0,
        help="Read timeout for LLM HTTP requests.",
    )
    parser.add_argument(
        "--safe-ai-policy-mode",
        default="warn",
        help="Safe AI policy mode for external providers: off|warn|enforce.",
    )
    parser.add_argument(
        "--safe-ai-allow-external-high-risk",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Allow sending high-risk findings to external providers.",
    )
    parser.add_argument(
        "--safe-ai-redact-medium",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Redact medium-risk snippets before sending to external providers.",
    )
    parser.add_argument(
        "--safe-ai-dry-run",
        action="store_true",
        help="Classify safe-AI risk (high/medium/low) and write report without running LLM review.",
    )
    parser.add_argument(
        "--rate-limit-at-gateway",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Suppress NFR-API-011 when rate limiting is enforced upstream (gateway/ingress).",
    )
    parser.add_argument(
        "--safe-ai-only",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Run Safe-AI risk scan independently using safe-ai rules only (skips NFR/LLM pipeline).",
    )
    parser.add_argument(
        "--safe-ai-rules",
        nargs="+",
        default=["rules/safe_ai_rules.json"],
        help="One or more JSON rules files for safe-ai-only mode.",
    )
    parser.add_argument(
        "--prefer-patch-s1s2",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="For S1/S2 findings, retry once with a patch-focused prompt when patch is unknown.",
    )
    parser.add_argument(
        "--prefer-patch-all-severities",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Attempt patch-focused retry for non-S1/S2 findings when confidence is high enough.",
    )
    parser.add_argument(
        "--patch-min-confidence",
        type=float,
        default=0.6,
        help="Minimum confidence threshold to run patch-focused retry for non-S1/S2 findings.",
    )
    parser.add_argument(
        "--patch-repair-retries",
        type=int,
        default=1,
        help="When a generated patch is a no-op, retry with explicit no-op feedback this many times.",
    )
    parser.add_argument(
        "--patch-strict-locality",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Drop generated patches that modify lines outside ±N window of the finding location.",
    )
    parser.add_argument(
        "--patch-locality-window",
        type=int,
        default=12,
        help="Line window N for strict locality gate (±N around finding line).",
    )
    parser.add_argument(
        "--patch-verify-pass",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Run an optional second LLM pass to verify patch correctness against the snippet.",
    )
    parser.add_argument(
        "--openai-api-key",
        default="",
        help="OpenAI API key. If empty, reads OPENAI_API_KEY/NFR_OPENAI_API_KEY from env.",
    )
    parser.add_argument(
        "--openai-model",
        default="",
        help="OpenAI model name. If empty, reads OPENAI_MODEL/NFR_OPENAI_MODEL from env.",
    )
    parser.add_argument(
        "--openai-base-url",
        default="",
        help="OpenAI base URL. Default: https://api.openai.com/v1",
    )
    parser.add_argument("--openrouter-api-key", default="", help="OpenRouter API key (optional when set in env).")
    parser.add_argument("--openrouter-model", default="", help="OpenRouter model (optional when set in env).")
    parser.add_argument("--openrouter-base-url", default="", help="OpenRouter base URL (default: https://openrouter.ai/api/v1).")
    parser.add_argument("--xai-api-key", default="", help="xAI API key (optional when set in env).")
    parser.add_argument("--xai-model", default="", help="xAI model (optional when set in env).")
    parser.add_argument("--xai-base-url", default="", help="xAI base URL (default: https://api.x.ai/v1).")
    parser.add_argument("--gemini-api-key", default="", help="Gemini API key (optional when set in env).")
    parser.add_argument("--gemini-model", default="", help="Gemini model (optional when set in env).")
    parser.add_argument("--gemini-base-url", default="", help="Gemini base URL (default: https://generativelanguage.googleapis.com/v1beta).")
    parser.add_argument(
        "--llm-cache-file",
        default="llm_review_cache.json",
        help="LLM review cache file (relative to output dir unless absolute path).",
    )
    parser.add_argument(
        "--patch-template-cache-file",
        default="patch_template_cache.json",
        help="Patch template cache file (relative to output dir unless absolute path).",
    )
    parser.add_argument(
        "--use-patch-template-cache",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable patch template cache derived from successful LLM patches.",
    )
    parser.add_argument(
        "--use-llm-cache",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable LLM review cache across runs.",
    )
    parser.add_argument(
        "--dedup-before-llm",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Cluster similar findings and send representative items to LLM.",
    )
    parser.add_argument(
        "--prioritize-llm-queue",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Prioritize S1/S2 and higher-confidence findings before S3/S4.",
    )
    parser.add_argument(
        "--adaptive-llm-workers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-tune llm-workers: reduce on timeout spikes, slowly increase when stable.",
    )
    parser.add_argument(
        "--fast-high-confidence-routing",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fast mode: auto-confirm high-confidence regex findings without LLM.",
    )
    parser.add_argument(
        "--high-confidence-threshold",
        type=float,
        default=0.9,
        help="Minimum rule confidence_hint for fast routing.",
    )
    parser.add_argument(
        "--high-confidence-max-severity",
        default="S2",
        help="Highest severity eligible for fast routing (S1/S2/S3/S4).",
    )
    parser.add_argument(
        "--auto-demote-noisy-rules",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Demote noisy rules in LLM prioritization using historical quality stats.",
    )
    parser.add_argument(
        "--rule-quality-file",
        default="rule_quality.json",
        help="Rule quality scoreboard file (relative to output dir unless absolute path).",
    )
    parser.add_argument(
        "--noisy-rule-min-reviewed",
        type=int,
        default=20,
        help="Minimum historical reviewed count before a rule can be auto-demoted.",
    )
    parser.add_argument(
        "--noisy-rule-max-precision",
        type=float,
        default=0.25,
        help="Auto-demote when historical precision is at or below this threshold.",
    )
    parser.add_argument(
        "--noisy-rule-max-fallback-rate",
        type=float,
        default=0.2,
        help="Auto-demote when historical fallback rate is at or above this threshold.",
    )
    parser.add_argument(
        "--resume-queue",
        default="",
        help="Resume an existing run from findings_queue__*.json",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="Ollama temperature (keep low for deterministic output)",
    )
    parser.add_argument(
        "--baseline",
        default="",
        help="Optional baseline findings JSON path (defaults to auto baseline per scan path).",
    )
    parser.add_argument(
        "--only-new",
        action="store_true",
        help="Legacy alias for incremental mode (kept for compatibility).",
    )
    parser.add_argument(
        "--incremental",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Review only new/changed findings against persisted baseline (default on).",
    )
    parser.add_argument(
        "--baseline-dir",
        default="baselines",
        help="Baseline directory under output-dir for per-scan-path baseline persistence.",
    )
    parser.add_argument(
        "--include-roslyn",
        action="store_true",
        help="Run Roslyn analyzers via dotnet build and merge findings",
    )
    parser.add_argument(
        "--dotnet-target",
        default="",
        help="Optional .sln/.csproj to build for analyzer SARIF; auto-detected if omitted",
    )
    parser.add_argument(
        "--dotnet-configuration",
        default="Debug",
        help="dotnet build configuration for analyzer pass",
    )
    parser.add_argument(
        "--dotnet-timeout-seconds",
        type=int,
        default=900,
        help="Timeout for dotnet analyzer build",
    )
    parser.add_argument(
        "--ignore-file",
        default=".nfrignore",
        help="Ignore file path (relative to --path by default). Set empty to disable.",
    )
    parser.add_argument(
        "--diff-base",
        default="",
        help="Optional git base ref for diff/PR mode. When set, only changed files/lines are scanned.",
    )
    parser.add_argument(
        "--diff-head",
        default="HEAD",
        help="Optional git head ref for diff/PR mode (default: HEAD).",
    )
    parser.add_argument(
        "--diff-files-only",
        action="store_true",
        help="Diff mode scans all lines in changed files (instead of changed lines only).",
    )
    parser.add_argument(
        "--ci-mode",
        default="off",
        help="CI policy mode: off|warn|soft-fail|hard-fail",
    )
    parser.add_argument(
        "--ci-max-total",
        type=int,
        default=-1,
        help="CI threshold for confirmed findings count across selected trust tiers (-1 disables).",
    )
    parser.add_argument("--ci-threshold-s1", type=int, default=-1, help="CI threshold for S1 findings (-1 disables).")
    parser.add_argument("--ci-threshold-s2", type=int, default=-1, help="CI threshold for S2 findings (-1 disables).")
    parser.add_argument("--ci-threshold-s3", type=int, default=-1, help="CI threshold for S3 findings (-1 disables).")
    parser.add_argument("--ci-threshold-s4", type=int, default=-1, help="CI threshold for S4 findings (-1 disables).")
    parser.add_argument("--ci-min-patch-generated", type=int, default=-1, help="CI threshold: minimum generated patches required (-1 disables).")
    parser.add_argument("--ci-max-patch-no-op", type=int, default=-1, help="CI threshold: maximum no-op patch count allowed (-1 disables).")
    parser.add_argument(
        "--ci-count-trust-tiers",
        default="llm_confirmed,fast_routed,fallback,regex_only,roslyn",
        help="Comma-separated trust tiers to include in CI counting.",
    )
    args = parser.parse_args()
    config = load_scan_config(args.config)
    passed_flags = get_passed_cli_flags(sys.argv)
    args = apply_config_defaults(args, config, passed_flags)
    setattr(args, "_passed_flags", passed_flags)
    return args


def get_passed_cli_flags(argv):
    passed = set()
    for token in argv[1:]:
        if not token.startswith("--"):
            continue
        key = token.split("=", 1)[0]
        if key.startswith("--no-"):
            passed.add(key[5:].replace("-", "_"))
            continue
        passed.add(key[2:].replace("-", "_"))
    return passed


def load_scan_config(config_path):
    if not config_path:
        return {}
    p = Path(config_path)
    if not p.is_absolute():
        p = Path.cwd() / p
    if not p.exists() or not p.is_file():
        return {}
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(data, dict):
        raise ValueError("Config JSON must be an object")
    return data


def apply_config_defaults(args, config, passed_flags):
    if not config:
        return args
    for key, value in config.items():
        attr = str(key).replace("-", "_")
        if attr in passed_flags:
            continue
        if not hasattr(args, attr):
            continue
        setattr(args, attr, value)
    return args


def _normalize_rule_paths(path_spec):
    if path_spec is None:
        return []
    if isinstance(path_spec, (list, tuple)):
        out = []
        for item in path_spec:
            out.extend(_normalize_rule_paths(item))
        return out
    raw = str(path_spec).strip()
    if not raw:
        return []
    parts = re.split(r"[;,]", raw)
    return [p.strip() for p in parts if p and p.strip()]


def load_rules(path_spec):
    paths = _normalize_rule_paths(path_spec)
    if not paths:
        raise ValueError("At least one rules file is required")
    combined = []
    for path in paths:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"Rules JSON must be a list: {path}")
        combined.extend(data)
    return combined


def _severity_rank(value):
    sev = str(value or "S3").upper()
    return SEVERITY_ORDER.get(sev, SEVERITY_ORDER["S3"])


def _severity_at_or_above(a, b):
    return _severity_rank(a) <= _severity_rank(b)


def _degrade_severity(value):
    sev = str(value or "S3").upper()
    if sev == "S1":
        return "S2"
    if sev == "S2":
        return "S3"
    if sev == "S3":
        return "S4"
    return "S4"


def _coerce_float(value, default):
    try:
        return float(value)
    except Exception:
        return float(default)


def _normalize_ignore_pattern(raw):
    pattern = str(raw or "").strip().replace("\\", "/")
    if not pattern:
        return []
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if pattern.startswith("/"):
        pattern = pattern[1:]

    out = {pattern}
    trimmed = pattern.rstrip("/")

    if pattern.endswith("/"):
        out.add(trimmed)
        out.add(f"{trimmed}/**")

    if "/" not in trimmed:
        out.add(f"**/{trimmed}")
        out.add(f"**/{trimmed}/**")
    else:
        out.add(f"{trimmed}/**")

    return sorted(x for x in out if x and x != ".")


def _is_dependency_risk_path(path):
    text = str(path or "").replace("\\", "/").lower()
    if text.endswith(".min.js"):
        return True
    for hint in DEPENDENCY_RISK_HINTS:
        if hint in text:
            return True
    return False


def load_ignore_globs(scan_path, ignore_file):
    if ignore_file is None:
        return []
    ignore_file = str(ignore_file).strip()
    if not ignore_file:
        return []

    p = Path(ignore_file)
    if not p.is_absolute():
        p = Path(scan_path) / p
    if (not p.exists() or not p.is_file()) and not Path(ignore_file).is_absolute():
        fallback = Path(ignore_file)
        if fallback.exists() and fallback.is_file():
            p = fallback
    if not p.exists() or not p.is_file():
        return []

    globs = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            continue
        globs.extend(_normalize_ignore_pattern(line))
    return sorted(set(globs))


def _is_ignored_path(rel_path, ignore_globs):
    if not ignore_globs:
        return False
    return any(fnmatch(rel_path, g) for g in ignore_globs)


def _normalize_rel_path(path, root):
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except Exception:
        try:
            return Path(path).as_posix()
        except Exception:
            return str(path).replace("\\", "/")


def _parse_added_ranges_from_hunk(line):
    m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
    if not m:
        return []
    start = int(m.group(1))
    count = int(m.group(2) or "1")
    if count <= 0:
        return []
    return list(range(start, start + count))


def load_git_diff_filter(scan_path, diff_base, diff_head="HEAD", files_only=False):
    base = str(diff_base or "").strip()
    if not base:
        return {}
    head = str(diff_head or "HEAD").strip()
    if not shutil.which("git"):
        log_progress("Diff mode requested, but git was not found in PATH. Proceeding with full scan.")
        return {}

    cmd = [
        "git",
        "-C",
        str(scan_path),
        "diff",
        "--unified=0",
        "--no-color",
        "--no-renames",
        f"{base}...{head}",
        "--",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if result.returncode != 0:
        log_progress(
            f"Diff mode requested, but git diff failed for {base}...{head}. "
            f"Proceeding with full scan. Error: {(result.stderr or '').strip()}"
        )
        return {}

    changed = {}
    current_file = None
    for raw in result.stdout.splitlines():
        if raw.startswith("+++ b/"):
            rel = raw[6:].strip().replace("\\", "/")
            if rel == "/dev/null":
                current_file = None
                continue
            current_file = rel
            if current_file not in changed:
                changed[current_file] = set()
            continue
        if current_file is None:
            continue
        if files_only:
            changed[current_file] = set()
            continue
        if raw.startswith("@@"):
            for ln in _parse_added_ranges_from_hunk(raw):
                changed[current_file].add(ln)
    return changed


def _is_comment_only_line(line_text):
    text = str(line_text or "").lstrip()
    if not text:
        return False
    return text.startswith("//") or text.startswith("/*") or text.startswith("*") or text.startswith("*/")


def _is_blocking_dotnet_result_line(line_text):
    text = str(line_text or "")
    if ".Result" not in text:
        return True
    if ".Wait(" in text or "GetAwaiter().GetResult()" in text or "Task.WaitAll(" in text or "Task.WaitAny(" in text:
        return True
    # Only keep .Result usage that is task-like; this avoids OperationResult<T>.Result false positives.
    task_like_result = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(Task|task|ValueTask|valuetask)\s*\.\s*Result\b", text)
    async_call_result = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*Async\s*\([^)]*\)\s*\.\s*Result\b", text)
    return bool(task_like_result or async_call_result)


def _should_skip_match(rule, line_text):
    line = str(line_text or "")
    if "nfr:allow-" in line.lower():
        return True
    if rule.get("ignore_comment_lines", False) and _is_comment_only_line(line_text):
        return True
    if rule.get("id") == "NFR-DOTNET-003" and not _is_blocking_dotnet_result_line(line_text):
        return True
    if rule.get("id") == "NFR-FE-014":
        # If a dependency array is present in the same effect call line, this is not the target case.
        if re.search(r"\buseEffect\s*\([^\n]*,\s*\[", str(line_text or "")):
            return True
    if rule.get("id") == "NFR-FE-004":
        # .then(onFulfilled, onRejected) handles errors without a trailing .catch.
        if re.search(r"\.then\s*\(\s*[^)\n]*,\s*[^)\n]*\)", str(line_text or "")):
            return True
        # Same-line catch/finally chain likely handled.
        if re.search(r"\.then\s*\([^)\n]*\)\s*\.(catch|finally)\s*\(", str(line_text or "")):
            return True
    return False


def _match_in_diff_scope(match_item, scan_root, changed_lines_by_file):
    if not changed_lines_by_file:
        return True
    rel = _normalize_rel_path(match_item.get("file", ""), scan_root)
    if rel not in changed_lines_by_file:
        return False
    touched_lines = changed_lines_by_file.get(rel, set())
    if not touched_lines:
        return True
    return int(match_item.get("line", 1) or 1) in touched_lines


def apply_contextual_overrides(findings, args=None):
    out = []
    for finding in findings:
        item = dict(finding)
        rid = str(item.get("rule_id", ""))
        if rid == "NFR-API-011" and bool(getattr(args, "rate_limit_at_gateway", False)):
            # Explicit opt-out when service uses upstream gateway/ingress throttling.
            continue
        if rid == "NFR-FE-014":
            snippet_l = str(item.get("snippet", "")).lower()
            if "eslint-disable-next-line react-hooks/exhaustive-deps" in snippet_l:
                continue
        if rid != "NFR-DOTNET-013":
            out.append(item)
            continue
        path_l = str(item.get("file", "")).lower().replace("\\", "/")
        likely_helper = any(
            token in path_l
            for token in ("/test/", "/tests/", "/spec/", "/benchmark/", "/samples/", "/example/", "/helpers/", "helper")
        )
        if likely_helper and str(item.get("default_severity", "S3")).upper() in {"S1", "S2"}:
            item["default_severity"] = _degrade_severity(item.get("default_severity", "S2"))
            item["context_override"] = "helper_or_test_path"
            item["context_override_note"] = "Severity lowered in helper/test-like path."
        out.append(item)
    return out


def _resolve_quality_path(rule_quality_file, output_dir):
    p = Path(rule_quality_file or "rule_quality.json")
    if not p.is_absolute():
        p = Path(output_dir) / p
    return p


def _resolve_artifact_output_dir(output_root_dir, project_name, run_version, output_layout):
    root = Path(output_root_dir)
    layout = str(output_layout or "flat").strip().lower()
    if layout == "run-folder":
        return root / "runs" / f"{project_name}__{run_version}"
    return root


def load_rule_quality(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"rules": {}, "meta": {}}
    try:
        payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(payload, dict):
            return {"rules": {}, "meta": {}}
        rules = payload.get("rules", {})
        meta = payload.get("meta", {})
        if not isinstance(rules, dict):
            rules = {}
        if not isinstance(meta, dict):
            meta = {}
        return {"rules": rules, "meta": meta}
    except Exception:
        return {"rules": {}, "meta": {}}


def _extract_false_positive_reason(item):
    review = item.get("llm_review", {}) or {}
    why = str(review.get("why", "") or "").strip()
    if not why:
        return "unspecified"
    first = why.split(".")[0].strip()
    first = re.sub(r"\s+", " ", first)
    if len(first) > 120:
        first = first[:120].rstrip() + "..."
    return first or "unspecified"


def build_rule_quality_scoreboard(reviewed):
    grouped = {}
    for item in reviewed:
        rid = str(item.get("rule_id", "unknown"))
        if rid not in grouped:
            grouped[rid] = {
                "reviewed": 0,
                "confirmed": 0,
                "fallback_count": 0,
                "timeout_like_count": 0,
                "false_positive_reasons": Counter(),
            }
        g = grouped[rid]
        g["reviewed"] += 1
        is_issue = bool((item.get("llm_review", {}) or {}).get("isIssue", False))
        if is_issue:
            g["confirmed"] += 1
        else:
            g["false_positive_reasons"][_extract_false_positive_reason(item)] += 1
        t = item.get("llm_transport", {}) or {}
        if bool(t.get("fallback_used", False)):
            g["fallback_count"] += 1
        kind = str(t.get("error_kind", ""))
        if kind in {"timeout", "connection_error"} or kind.startswith("http_5") or kind == "http_429":
            g["timeout_like_count"] += 1

    scoreboard = {}
    for rid, g in grouped.items():
        reviewed_count = int(g["reviewed"])
        confirmed_count = int(g["confirmed"])
        fallback_count = int(g["fallback_count"])
        timeout_count = int(g["timeout_like_count"])
        precision = (confirmed_count / reviewed_count) if reviewed_count else 0.0
        fallback_rate = (fallback_count / reviewed_count) if reviewed_count else 0.0
        timeout_rate = (timeout_count / reviewed_count) if reviewed_count else 0.0
        top_fp = [
            {"reason": reason, "count": count}
            for reason, count in g["false_positive_reasons"].most_common(5)
        ]
        scoreboard[rid] = {
            "reviewed": reviewed_count,
            "confirmed": confirmed_count,
            "precision": round(precision, 4),
            "fallback_count": fallback_count,
            "fallback_rate": round(fallback_rate, 4),
            "timeout_like_count": timeout_count,
            "timeout_like_rate": round(timeout_rate, 4),
            "top_false_positive_reasons": top_fp,
        }
    return scoreboard


def merge_rule_quality(existing_payload, new_scoreboard):
    existing = dict(existing_payload or {})
    old_rules = existing.get("rules", {}) if isinstance(existing.get("rules", {}), dict) else {}
    merged = {}
    for rid in sorted(set(old_rules.keys()) | set(new_scoreboard.keys())):
        old = old_rules.get(rid, {}) if isinstance(old_rules.get(rid, {}), dict) else {}
        new = new_scoreboard.get(rid, {}) if isinstance(new_scoreboard.get(rid, {}), dict) else {}
        old_reviewed = int(old.get("reviewed", 0) or 0)
        old_confirmed = int(old.get("confirmed", 0) or 0)
        old_fallback = int(old.get("fallback_count", 0) or 0)
        old_timeout = int(old.get("timeout_like_count", 0) or 0)
        new_reviewed = int(new.get("reviewed", 0) or 0)
        new_confirmed = int(new.get("confirmed", 0) or 0)
        new_fallback = int(new.get("fallback_count", 0) or 0)
        new_timeout = int(new.get("timeout_like_count", 0) or 0)
        total_reviewed = old_reviewed + new_reviewed
        total_confirmed = old_confirmed + new_confirmed
        total_fallback = old_fallback + new_fallback
        total_timeout = old_timeout + new_timeout
        fp_counter = Counter()
        for item in old.get("top_false_positive_reasons", []) or []:
            if isinstance(item, dict) and item.get("reason"):
                fp_counter[str(item["reason"])] += int(item.get("count", 0) or 0)
        for item in new.get("top_false_positive_reasons", []) or []:
            if isinstance(item, dict) and item.get("reason"):
                fp_counter[str(item["reason"])] += int(item.get("count", 0) or 0)
        merged[rid] = {
            "reviewed": total_reviewed,
            "confirmed": total_confirmed,
            "precision": round((total_confirmed / total_reviewed) if total_reviewed else 0.0, 4),
            "fallback_count": total_fallback,
            "fallback_rate": round((total_fallback / total_reviewed) if total_reviewed else 0.0, 4),
            "timeout_like_count": total_timeout,
            "timeout_like_rate": round((total_timeout / total_reviewed) if total_reviewed else 0.0, 4),
            "top_false_positive_reasons": [
                {"reason": reason, "count": count}
                for reason, count in fp_counter.most_common(5)
            ],
        }
    return {
        "meta": {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "rule_count": len(merged),
        },
        "rules": merged,
    }


def build_rule_precision_trend(previous_quality_payload, current_run_scoreboard):
    prev_rules = (previous_quality_payload or {}).get("rules", {})
    if not isinstance(prev_rules, dict):
        prev_rules = {}
    out = {}
    for rid, cur in (current_run_scoreboard or {}).items():
        if not isinstance(cur, dict):
            continue
        prev = prev_rules.get(rid, {}) if isinstance(prev_rules.get(rid, {}), dict) else {}
        prev_precision = float(prev.get("precision", 0.0) or 0.0)
        cur_precision = float(cur.get("precision", 0.0) or 0.0)
        delta = round(cur_precision - prev_precision, 4)
        if delta > 0.01:
            trend = "up"
        elif delta < -0.01:
            trend = "down"
        else:
            trend = "stable"
        out[rid] = {
            "previous_precision": round(prev_precision, 4),
            "current_run_precision": round(cur_precision, 4),
            "delta": delta,
            "trend": trend,
            "current_run_reviewed": int(cur.get("reviewed", 0) or 0),
            "current_run_confirmed": int(cur.get("confirmed", 0) or 0),
        }
    return out


def save_rule_quality(path, payload):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def derive_noisy_rules(rule_quality_payload, min_reviewed, max_precision, max_fallback_rate):
    noisy = set()
    rules = (rule_quality_payload or {}).get("rules", {})
    if not isinstance(rules, dict):
        return noisy
    for rid, stats in rules.items():
        if not isinstance(stats, dict):
            continue
        reviewed = int(stats.get("reviewed", 0) or 0)
        if reviewed < int(min_reviewed):
            continue
        precision = float(stats.get("precision", 0.0) or 0.0)
        fallback_rate = float(stats.get("fallback_rate", 0.0) or 0.0)
        if precision <= float(max_precision) or fallback_rate >= float(max_fallback_rate):
            noisy.add(str(rid))
    return noisy


def build_rule_pipeline_stats(pre_scan_rule_stats, pending_findings, rep_queue, reps_to_review):
    stats = {}
    for rid, item in (pre_scan_rule_stats or {}).items():
        stats[rid] = {
            "raw_matches": int(item.get("raw_matches", 0) or 0),
            "unique_findings": int(item.get("unique_findings", 0) or 0),
            "pending_after_filters": 0,
            "representatives": 0,
            "sent_to_llm": 0,
        }
    for f in pending_findings or []:
        rid = str(f.get("rule_id", "unknown"))
        stats.setdefault(rid, {"raw_matches": 0, "unique_findings": 0, "pending_after_filters": 0, "representatives": 0, "sent_to_llm": 0})
        stats[rid]["pending_after_filters"] += 1
    for rep in rep_queue or []:
        rid = str(rep.get("rule_id", "unknown"))
        stats.setdefault(rid, {"raw_matches": 0, "unique_findings": 0, "pending_after_filters": 0, "representatives": 0, "sent_to_llm": 0})
        stats[rid]["representatives"] += 1
    for rep in reps_to_review or []:
        rid = str(rep.get("rule_id", "unknown"))
        stats.setdefault(rid, {"raw_matches": 0, "unique_findings": 0, "pending_after_filters": 0, "representatives": 0, "sent_to_llm": 0})
        stats[rid]["sent_to_llm"] += 1
    return stats


def log_rule_pipeline_stats(stats):
    if not stats:
        return
    active = [(rid, v) for rid, v in stats.items() if any(int(v.get(k, 0) or 0) > 0 for k in ("raw_matches", "unique_findings", "pending_after_filters", "representatives", "sent_to_llm"))]
    active.sort(key=lambda item: (-int(item[1].get("raw_matches", 0)), item[0]))
    log_progress(f"Rule pipeline stats (raw -> unique -> pending -> reps -> sent_to_llm), active_rules={len(active)}")
    for rid, v in active[:30]:
        log_progress(
            f"  {rid}: {int(v.get('raw_matches', 0))} -> {int(v.get('unique_findings', 0))} -> "
            f"{int(v.get('pending_after_filters', 0))} -> {int(v.get('representatives', 0))} -> "
            f"{int(v.get('sent_to_llm', 0))}"
        )


def build_noise_recommendations(rule_quality, min_reviewed=5, max_items=10):
    out = []
    for rid, stats in (rule_quality or {}).items():
        if not isinstance(stats, dict):
            continue
        reviewed = int(stats.get("reviewed", 0) or 0)
        if reviewed < int(min_reviewed):
            continue
        precision = float(stats.get("precision", 0.0) or 0.0)
        fallback_rate = float(stats.get("fallback_rate", 0.0) or 0.0)
        if reviewed >= 30 and precision <= 0.15:
            action = "disable"
        elif precision <= 0.35 or fallback_rate >= 0.4:
            action = "tune"
        elif fallback_rate >= 0.25:
            action = "demote"
        else:
            action = "monitor"
        out.append(
            {
                "rule_id": rid,
                "reviewed": reviewed,
                "precision": round(precision, 4),
                "fallback_rate": round(fallback_rate, 4),
                "recommended_action": action,
            }
        )
    out.sort(key=lambda x: (x["recommended_action"] == "monitor", x["precision"], -x["fallback_rate"], -x["reviewed"], x["rule_id"]))
    return out[:max_items]


def build_fast_routed_review(finding):
    confidence = finding.get("confidence_hint")
    try:
        confidence = float(confidence)
    except Exception:
        confidence = 0.9
    out = dict(finding)
    out["llm_review"] = {
        "isIssue": True,
        "severity": str(finding.get("default_severity", "S3")).upper(),
        "confidence": max(0.0, min(1.0, confidence)),
        "title": f"{finding.get('rule_title', finding.get('rule_id', 'Rule'))} (fast-routed)",
        "why": "Auto-confirmed using high-confidence rule routing.",
        "recommendation": str(finding.get("rationale", "Apply recommended fix for this rule.")),
        "effort": "medium",
        "benefit": "medium",
        "quick_win": False,
        "testing_notes": ["Run targeted tests for impacted code path after applying fix."],
        "patch": "unknown",
    }
    out["llm_transport"] = {
        "attempts": 0,
        "attempts_allowed": 0,
        "fallback_used": False,
        "error_kind": "",
        "from_cache": False,
        "fast_routed": True,
        "recovered_after_retry": False,
        "elapsed_ms": 0.0,
    }
    out["llm_error_kind"] = ""
    out["llm_attempts"] = 0
    out["llm_retried"] = False
    return out


def trust_tier_of(item):
    transport = item.get("llm_transport", {}) or {}
    if bool(transport.get("fallback_used", False)):
        return "fallback"
    if bool(transport.get("fast_routed", False)):
        return "fast_routed"
    has_llm = isinstance(item.get("llm_review"), dict) and bool(item.get("llm_review"))
    if has_llm:
        return "llm_confirmed"
    source = str(item.get("source", "unknown")).lower()
    if source == "regex":
        return "regex_only"
    if source == "roslyn":
        return "roslyn"
    return "unknown"


def _parse_csv_set(text):
    out = set()
    for part in str(text or "").split(","):
        token = part.strip().lower()
        if token:
            out.add(token)
    return out


def _run_rg(path, rule, ignore_globs):
    rg_path = shutil.which("rg")
    if not rg_path:
        return _run_regex_fallback(path, rule, ignore_globs)

    cmd = [
        rg_path,
        "--json",
        "--line-number",
        "--column",
        "--max-columns",
        "240",
        "-P",
        "-e",
        rule["pattern"],
        str(path),
    ]
    for glob in rule.get("include_globs", []):
        cmd.extend(["--glob", glob])
    for glob in rule.get("exclude_globs", []):
        cmd.extend(["--glob", f"!{glob}"])
    for glob in ignore_globs:
        cmd.extend(["--glob", f"!{glob}"])

    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if result.returncode not in (0, 1):
        raise RuntimeError(f"rg failed for {rule['id']}: {result.stderr.strip()}")

    matches = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if entry.get("type") != "match":
            continue
        data = entry["data"]
        line_text = data["lines"]["text"].rstrip("\n")
        if _should_skip_match(rule, line_text):
            continue
        matches.append(
            {
                "file": data["path"]["text"],
                "line": data["line_number"],
                "column": data["submatches"][0]["start"] + 1 if data.get("submatches") else 1,
                "match_text": line_text,
            }
        )
    return matches


def _is_included(rel_path, include_globs, exclude_globs, ignore_globs):
    if _is_ignored_path(rel_path, ignore_globs):
        return False
    include_ok = True
    if include_globs:
        include_ok = any(fnmatch(rel_path, g) for g in include_globs)
    if not include_ok:
        return False
    if exclude_globs and any(fnmatch(rel_path, g) for g in exclude_globs):
        return False
    return True


def _run_regex_fallback(path, rule, ignore_globs):
    pattern = re.compile(rule["pattern"])
    include_globs = rule.get("include_globs", [])
    exclude_globs = rule.get("exclude_globs", [])

    matches = []
    root = Path(path)
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        rel_path = file_path.relative_to(root).as_posix()
        if not _is_included(rel_path, include_globs, exclude_globs, ignore_globs):
            continue

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.start())
            if line_end == -1:
                line_end = len(text)
            line_text = text[line_start:line_end]
            if _should_skip_match(rule, line_text):
                continue
            col = (m.start() - line_start) + 1
            matches.append(
                {
                    "file": str(file_path),
                    "line": line,
                    "column": col,
                    "match_text": line_text.rstrip("\n"),
                }
            )
    return matches


def _snippet(path, line_number, context_lines, cache):
    p = Path(path)
    if path not in cache:
        try:
            cache[path] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            cache[path] = []
    lines = cache[path]
    if not lines:
        return ""
    start = max(1, line_number - context_lines)
    end = min(len(lines), line_number + context_lines)
    out = []
    for i in range(start, end + 1):
        out.append(f"{i:5d}: {lines[i - 1]}")
    return "\n".join(out)


def _normalize_path(raw_path, scan_root):
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            return str(candidate.resolve())
        except Exception:
            return str(candidate)

    from_root = (scan_root / candidate)
    if from_root.exists():
        try:
            return str(from_root.resolve())
        except Exception:
            return str(from_root)

    return str(candidate)


def _file_type(path):
    suffix = Path(path).suffix.lower()
    return suffix[1:] if suffix.startswith(".") else (suffix or "unknown")


def _language_for_file(path):
    ext = Path(path).suffix.lower()
    mapping = {
        ".cs": "csharp",
        ".csproj": "xml",
        ".sln": "plaintext",
        ".json": "json",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".py": "python",
        ".java": "java",
        ".go": "go",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".md": "markdown",
        ".razor": "csharp",
    }
    return mapping.get(ext, "unknown")


def _normalize_effort(value):
    v = str(value or "").strip().lower()
    if v in {"low", "medium", "high"}:
        return v
    return "medium"


def _normalize_benefit(value, severity):
    v = str(value or "").strip().lower()
    if v in {"low", "medium", "high"}:
        return v
    if severity == "S1":
        return "high"
    if severity == "S2":
        return "medium"
    return "low"


def _infer_quick_win(severity, effort, benefit):
    if effort == "low" and benefit in {"medium", "high"}:
        return True
    if severity in {"S1", "S2"} and effort == "low":
        return True
    return False


def _post_llm_false_positive_gate(parsed, finding, fallback_used=False):
    """Demote likely false positives when model text indicates non-applicability."""
    if not isinstance(parsed, dict):
        return parsed
    if fallback_used:
        return parsed
    if not bool(parsed.get("isIssue", False)):
        return parsed

    title = str(parsed.get("title", "") or "").lower()
    why = str(parsed.get("why", "") or "").lower()
    rec = str(parsed.get("recommendation", "") or "").lower()
    text = f"{title}\n{why}\n{rec}"

    already_handled_hints = (
        "already handled",
        "already mitigated",
        "already propagated",
        "already passed",
        "already uses",
        "already has cancellationtoken",
        "cancellationtoken is passed",
        "token is passed",
        "no issue in this snippet",
        "not applicable",
        "rule does not apply",
        "false positive",
        "comment-only",
        "only in comment",
    )
    insufficient_evidence_hints = (
        "insufficient evidence",
        "not enough evidence",
        "insufficient context",
        "not enough context",
        "cannot determine",
        "can't determine",
        "uncertain from snippet",
        "unable to confirm",
        "cannot confirm",
    )
    if not any(h in text for h in already_handled_hints + insufficient_evidence_hints):
        return parsed

    out = dict(parsed)
    out["isIssue"] = False
    try:
        conf = float(out.get("confidence", 0.0) or 0.0)
    except Exception:
        conf = 0.0
    out["confidence"] = min(conf, 0.45)
    out["patch"] = "unknown"
    out["changed_lines_reason"] = ""
    out["recommendation"] = "No action needed for this snippet; rule likely false positive or needs tighter pattern."
    notes = list(out.get("testing_notes", []) or [])
    notes.append(
        f"Post-LLM validity gate demoted this finding as non-actionable for snippet evidence ({finding.get('rule_id', 'unknown')})."
    )
    out["testing_notes"] = notes
    out["post_llm_gate"] = "demoted_false_positive"
    return out


def _safe_name(value):
    cleaned = []
    for ch in str(value or ""):
        if ch.isalnum() or ch in {"-", "_"}:
            cleaned.append(ch)
        else:
            cleaned.append("_")
    name = "".join(cleaned).strip("_")
    return name or "project"


def _project_name_from_scan_path(scan_path):
    p = Path(scan_path)
    if p.is_file():
        base = p.parent.name
    else:
        base = p.name
    return _safe_name(base or "project")


def pre_scan(
    scan_path,
    rules,
    context_lines,
    max_findings,
    ignore_globs,
    regex_workers=1,
    changed_lines_by_file=None,
):
    all_findings = []
    cache = {}
    total_rules = len(rules)
    regex_workers = max(1, int(regex_workers or 1))
    matches_by_rule = {}
    pre_scan_rule_stats = {}

    if regex_workers == 1 or total_rules <= 1:
        for idx, rule in enumerate(rules, start=1):
            log_progress(f"Regex rule {idx}/{total_rules}: {rule['id']}")
            matches = _run_rg(scan_path, rule, ignore_globs)
            log_progress(f"Rule {rule['id']} produced {len(matches)} match(es)")
            matches_by_rule[rule["id"]] = matches
    else:
        log_progress(f"Starting parallel regex pre-scan with workers={regex_workers} for {total_rules} rule(s)")
        with ThreadPoolExecutor(max_workers=regex_workers) as executor:
            future_to_rule = {
                executor.submit(_run_rg, scan_path, rule, ignore_globs): rule
                for rule in rules
            }
            done = 0
            for future in as_completed(future_to_rule):
                rule = future_to_rule[future]
                matches_by_rule[rule["id"]] = future.result()
                done += 1
                if done % 5 == 0 or done == total_rules:
                    log_progress(f"Regex execution progress: {done}/{total_rules} rule(s) completed")

        for idx, rule in enumerate(rules, start=1):
            matches = matches_by_rule.get(rule["id"], [])
            log_progress(f"Regex rule {idx}/{total_rules}: {rule['id']}")
            log_progress(f"Rule {rule['id']} produced {len(matches)} match(es)")

    for idx, rule in enumerate(rules, start=1):
        pre_scan_rule_stats[rule["id"]] = {"raw_matches": len(matches_by_rule.get(rule["id"], [])), "unique_findings": 0}

    reached_limit = False
    for idx, rule in enumerate(rules, start=1):
        matches = matches_by_rule.get(rule["id"], [])
        for m in matches:
            if not _match_in_diff_scope(m, scan_path, changed_lines_by_file):
                continue
            snippet = _snippet(m["file"], m["line"], context_lines, cache)
            dependency_risk = _is_dependency_risk_path(m["file"])
            key = f"regex|{rule['id']}|{m['file']}|{m['line']}|{hashlib.sha1(m['match_text'].encode('utf-8', errors='ignore')).hexdigest()[:12]}"
            all_findings.append(
                {
                    "finding_key": key,
                    "source": "regex",
                    "rule_id": rule["id"],
                    "rule_title": rule["title"],
                    "category": rule.get("category", "reliability"),
                    "top_level_category": rule.get("top_level_category", "dotnet"),
                    "sub_category": rule.get("sub_category", "performance"),
                    "default_severity": rule.get("severity", "S3"),
                    "enforcement_level": str(rule.get("enforcement_level", "hard_fail")).lower(),
                    "rationale": rule.get("rationale", ""),
                    "file": m["file"],
                    "line": m["line"],
                    "column": m["column"],
                    "file_type": _file_type(m["file"]),
                    "language": _language_for_file(m["file"]),
                    "match_text": m["match_text"],
                    "snippet": snippet,
                    "confidence_hint": _coerce_float(rule.get("confidence_hint", 0.65), 0.65),
                    "safe_ai_risk_hint": str(rule.get("safe_ai_risk", "")).strip().lower(),
                    "action_bucket": "dependency_risk" if dependency_risk else "app_code",
                    "action_hint": "upgrade_dependency_or_csp" if dependency_risk else "app_fix_backlog",
                }
            )
            if len(all_findings) >= max_findings:
                reached_limit = True
                break
        if reached_limit:
            break

    unique = []
    seen = set()
    for item in all_findings:
        if item["finding_key"] in seen:
            continue
        seen.add(item["finding_key"])
        unique.append(item)
        rid = str(item.get("rule_id", "unknown"))
        if rid not in pre_scan_rule_stats:
            pre_scan_rule_stats[rid] = {"raw_matches": 0, "unique_findings": 0}
        pre_scan_rule_stats[rid]["unique_findings"] += 1

    if reached_limit:
        log_progress(f"Reached max-findings limit ({max_findings}) during pre-scan")
    return unique, pre_scan_rule_stats


def _find_dotnet_target(scan_path):
    sln = sorted(scan_path.rglob("*.sln"))
    if sln:
        return sln[0]
    csproj = sorted(scan_path.rglob("*.csproj"))
    if csproj:
        return csproj[0]
    return None


def _run_roslyn_sarif(scan_path, output_dir, target, configuration, timeout_seconds):
    if not shutil.which("dotnet"):
        return None, "dotnet not found in PATH"

    resolved_target = Path(target).resolve() if target else _find_dotnet_target(scan_path)
    if not resolved_target:
        return None, "no .sln or .csproj found for Roslyn scan"

    sarif_path = (Path(output_dir) / "roslyn.sarif").resolve()
    cmd = [
        "dotnet",
        "build",
        str(resolved_target),
        "-nologo",
        "-v:minimal",
        "-p:RunAnalyzers=true",
        f"-p:ErrorLog={sarif_path}",
        "-p:TreatWarningsAsErrors=false",
        "-p:EnforceCodeStyleInBuild=true",
        "-p:AnalysisLevel=latest",
        "-c",
        configuration,
    ]

    workdir = str(resolved_target.parent)
    result = subprocess.run(
        cmd,
        cwd=workdir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout_seconds,
    )

    if sarif_path.exists():
        return sarif_path, None

    stderr = (result.stderr or "").strip()
    stdout_tail = "\n".join((result.stdout or "").splitlines()[-10:])
    message = stderr if stderr else stdout_tail
    return None, (message or "dotnet build did not produce SARIF output")


def _parse_roslyn_findings(sarif_path, scan_root, context_lines, ignore_globs, changed_lines_by_file=None):
    cache = {}
    findings = []
    payload = json.loads(Path(sarif_path).read_text(encoding="utf-8", errors="ignore"))

    for run in payload.get("runs", []):
        rule_lookup = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id")
            if rid:
                rule_lookup[rid] = rule

        for result in run.get("results", []):
            rid = result.get("ruleId", "ROSLYN-UNKNOWN")
            level = (result.get("level") or "warning").lower()
            severity = ROSLYN_LEVEL_TO_S.get(level, "S2")

            message = result.get("message", {})
            if isinstance(message, dict):
                message_text = message.get("text", "Roslyn analyzer finding")
            elif isinstance(message, str):
                message_text = message
            else:
                message_text = "Roslyn analyzer finding"
            locations = result.get("locations", [])
            if not locations:
                continue

            phys = locations[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "unknown")
            region = phys.get("region", {})
            line = int(region.get("startLine", 1))
            column = int(region.get("startColumn", 1))

            norm_path = _normalize_path(uri, scan_root)
            try:
                rel = Path(norm_path).resolve().relative_to(Path(scan_root).resolve()).as_posix()
            except Exception:
                rel = Path(norm_path).as_posix()
            if _is_ignored_path(rel, ignore_globs):
                continue
            if changed_lines_by_file:
                if rel not in changed_lines_by_file:
                    continue
                touched_lines = changed_lines_by_file.get(rel, set())
                if touched_lines and line not in touched_lines:
                    continue
            snippet = _snippet(norm_path, line, context_lines, cache)
            dependency_risk = _is_dependency_risk_path(norm_path)

            rule_meta = rule_lookup.get(rid, {})
            title = (
                rule_meta.get("shortDescription", {}).get("text")
                or rule_meta.get("name")
                or rid
            )
            rationale = rule_meta.get("fullDescription", {}).get("text", "")

            key = f"roslyn|{rid}|{norm_path}|{line}|{hashlib.sha1(message_text.encode('utf-8', errors='ignore')).hexdigest()[:12]}"
            findings.append(
                {
                    "finding_key": key,
                    "source": "roslyn",
                    "rule_id": rid,
                    "rule_title": title,
                    "category": "reliability",
                    "default_severity": severity,
                    "rationale": rationale,
                    "file": norm_path,
                    "line": line,
                    "column": column,
                    "file_type": _file_type(norm_path),
                    "language": _language_for_file(norm_path),
                    "match_text": message_text,
                    "snippet": snippet,
                    "confidence_hint": 0.95,
                    "action_bucket": "dependency_risk" if dependency_risk else "app_code",
                    "action_hint": "upgrade_dependency_or_csp" if dependency_risk else "app_fix_backlog",
                }
            )

    unique = []
    seen = set()
    for item in findings:
        if item["finding_key"] in seen:
            continue
        seen.add(item["finding_key"])
        unique.append(item)
    return unique


def _extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.replace("json", "", 1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidate = text[first : last + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Fallback: scan for balanced JSON object candidates inside explanatory text.
    candidates = []
    start = None
    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if start is None:
            if ch == "{":
                start = i
                depth = 1
                in_string = False
                escaped = False
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "\"":
                in_string = False
            continue
        if ch == "\"":
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidates.append(text[start : i + 1])
                start = None
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    raise ValueError("Could not parse JSON from LLM response")


def _patch_quality(patch_text):
    text = str(patch_text or "").strip()
    if not text or text.lower() == "unknown":
        return "unknown"
    plus = []
    minus = []
    for line in text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("+"):
            plus.append(line[1:].strip())
        elif line.startswith("-"):
            minus.append(line[1:].strip())
    if not plus and not minus:
        return "no_op"
    if plus == minus:
        return "no_op"
    return "valid"


def _patch_changed_lines(patch_text):
    plus = []
    minus = []
    for line in str(patch_text or "").splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("+"):
            plus.append(line[1:])
        elif line.startswith("-"):
            minus.append(line[1:])
    return plus, minus


def _line_is_comment_in_diff(line):
    t = str(line or "").lstrip()
    if not t:
        return True
    if t.startswith("+") or t.startswith("-"):
        t = t[1:].lstrip()
    return t.startswith("//") or t.startswith("/*") or t.startswith("*") or t.startswith("*/") or t.startswith("///")


def _normalize_diff_path(raw):
    p = str(raw or "").strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p.replace("\\", "/")


def _extract_patch_locality_info(patch_text):
    lines = str(patch_text or "").splitlines()
    files = []
    current_file = None
    current_hunk_new_line = None
    changed_by_file = {}

    for line in lines:
        if line.startswith("+++ "):
            raw = line[4:].strip()
            if raw == "/dev/null":
                current_file = None
                current_hunk_new_line = None
                continue
            current_file = _normalize_diff_path(raw)
            if current_file not in files:
                files.append(current_file)
            changed_by_file.setdefault(current_file, set())
            current_hunk_new_line = None
            continue
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if not m:
                current_hunk_new_line = None
                continue
            current_hunk_new_line = int(m.group(1))
            continue
        if current_file is None or current_hunk_new_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed_by_file[current_file].add(current_hunk_new_line)
            current_hunk_new_line += 1
            continue
        if line.startswith("-") and not line.startswith("---"):
            # Deletion consumes old line only; keep new-side cursor unchanged.
            continue
        if line.startswith(" "):
            current_hunk_new_line += 1

    return {
        "files": files,
        "changed_by_file": changed_by_file,
    }


def _patch_target_matches_finding(target_file, finding_file):
    t = _normalize_diff_path(target_file).lower()
    f = str(finding_file or "").replace("\\", "/").lower()
    if not t or not f:
        return False
    if f.endswith("/" + t) or f == t:
        return True
    return Path(f).name.lower() == Path(t).name.lower()


def _is_commentish_line(text):
    t = str(text or "").strip()
    if not t:
        return True
    return (
        t.startswith("//")
        or t.startswith("/*")
        or t.startswith("*")
        or t.startswith("*/")
        or t.startswith("#")
        or t.startswith("///")
    )


def _extract_param_name(param_text):
    p = str(param_text or "").strip()
    if not p:
        return ""
    p = p.split("=", 1)[0].strip()
    p = re.sub(r"\b(this|ref|out|in|params)\b", "", p)
    p = re.sub(r"\s+", " ", p).strip()
    if not p:
        return ""
    # Last identifier-like token is usually parameter name.
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", p)
    return m.group(1) if m else ""


def _has_duplicate_param_name_in_added_signature(plus_lines):
    for line in plus_lines:
        text = str(line or "")
        if "(" not in text or ")" not in text:
            continue
        # Heuristic: likely method/ctor signature line.
        if not re.search(r"\b(public|private|protected|internal|async|static|Task|ValueTask|void|class)\b", text):
            continue
        m = re.search(r"\(([^)]*)\)", text)
        if not m:
            continue
        raw_params = [x.strip() for x in m.group(1).split(",") if x.strip()]
        if not raw_params:
            continue
        seen = set()
        for rp in raw_params:
            name = _extract_param_name(rp).lower()
            if not name:
                continue
            if name in seen:
                return True
            seen.add(name)
    return False


def _patch_sanity_issues(patch_text, finding, strict_locality=False, locality_window=12):
    issues = []
    text = str(patch_text or "")
    lower = text.lower()
    if not text.strip() or text.strip().lower() == "unknown":
        return issues

    plus_lines, minus_lines = _patch_changed_lines(text)
    changed = plus_lines + minus_lines
    if changed and all(_is_commentish_line(x) for x in changed):
        issues.append("comment_only_change")

    if _has_duplicate_param_name_in_added_signature(plus_lines):
        issues.append("duplicate_parameter_name")

    forbidden_markers = [
        "asqueryable(cancellationtoken)",
        "jsonconvert.serializeobjectasync",
    ]
    if any(x in lower for x in forbidden_markers):
        issues.append("hallucinated_or_invalid_api")

    if re.search(r"\basync\s*\{", lower):
        issues.append("invalid_async_syntax")

    # Drop duplicate added lines that indicate broken patch assembly.
    norm_plus = [re.sub(r"\s+", " ", str(x).strip()) for x in plus_lines if str(x).strip()]
    if norm_plus:
        seen = set()
        dup = False
        for line in norm_plus:
            if line in seen:
                dup = True
                break
            seen.add(line)
        if dup:
            issues.append("duplicate_added_lines")

    rule_id = str((finding or {}).get("rule_id", "")).upper()
    if rule_id and rule_id not in {"NFR-API-015"} and "usehsts" in lower:
        issues.append("unrelated_security_change")

    # Block patches that disable persistence paths.
    removed_save = [x for x in minus_lines if re.search(r"\bSaveChanges(Async)?\s*\(", str(x))]
    if removed_save:
        added_save = [x for x in plus_lines if re.search(r"\bSaveChanges(Async)?\s*\(", str(x))]
        if not added_save or all(_line_is_comment_in_diff(x) for x in added_save):
            issues.append("unsafe_persistence_change")

    # Block unrelated auth/security pipeline changes except for security-focused rules.
    sec_tokens = r"\b(AllowAnonymous|Authorize|UseAuthentication|UseAuthorization|UseHsts|Role|Policy|Claim)\b"
    touches_sec = any(re.search(sec_tokens, str(x), flags=re.IGNORECASE) for x in changed)
    if touches_sec and rule_id not in {"NFR-API-015"}:
        issues.append("unrelated_auth_or_security_change")

    # Detect obvious boolean behavior flips on same assignment symbol.
    lhs_minus = {}
    for raw in minus_lines:
        m = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(true|false)\b", str(raw), flags=re.IGNORECASE)
        if m:
            lhs_minus[m.group(1).lower()] = m.group(2).lower()
    for raw in plus_lines:
        m = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(true|false)\b", str(raw), flags=re.IGNORECASE)
        if not m:
            continue
        lhs = m.group(1).lower()
        rhs = m.group(2).lower()
        if lhs in lhs_minus and lhs_minus[lhs] != rhs:
            issues.append("unrelated_boolean_behavior_flip")
            break

    if bool(strict_locality):
        info = _extract_patch_locality_info(text)
        files = info.get("files", [])
        changed_by_file = info.get("changed_by_file", {})
        if len(files) != 1:
            issues.append("multi_file_or_unverifiable_patch")
        else:
            target = files[0]
            if not _patch_target_matches_finding(target, (finding or {}).get("file", "")):
                issues.append("patch_targets_different_file")
            else:
                changed_lines = sorted(changed_by_file.get(target, set()))
                if not changed_lines:
                    issues.append("patch_line_unverifiable")
                else:
                    line = int((finding or {}).get("line", 1) or 1)
                    window = max(0, int(locality_window or 0))
                    low = max(1, line - window)
                    high = line + window
                    if any((ln < low or ln > high) for ln in changed_lines):
                        issues.append("patch_outside_locality_window")

    return sorted(set(issues))


def _classify_llm_error(exc):
    if isinstance(exc, ValueError) and "JSON" in str(exc):
        return False, "parse_error"
    if isinstance(exc, requests.exceptions.Timeout):
        return True, "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return True, "connection_error"
    if isinstance(exc, requests.exceptions.HTTPError):
        status = None
        try:
            status = exc.response.status_code if exc.response is not None else None
        except Exception:
            status = None
        if status in {408, 429} or (status is not None and status >= 500):
            return True, f"http_{status}"
        return False, f"http_{status}" if status is not None else "http_error"
    return False, exc.__class__.__name__


def _canonical_provider_name(value):
    raw = str(value or "").strip().lower()
    aliases = {
        "ollama": "ollama",
        "openai": "openai",
        "openrouter": "openrouter",
        "xai": "xai",
        "grok": "xai",
        "gemini": "gemini",
        "google": "gemini",
    }
    return aliases.get(raw, raw or "ollama")


def _provider_label(provider):
    name = _canonical_provider_name(provider)
    labels = {
        "ollama": "Ollama",
        "openai": "OpenAI",
        "openrouter": "OpenRouter",
        "xai": "xAI",
        "gemini": "Gemini",
    }
    return labels.get(name, name)


def _openai_like_extract_content(resp_json):
    choices = resp_json.get("choices", [])
    if not choices:
        return ""
    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    content = message.get("content", "")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
        return "\n".join(parts)
    return str(content or "")


def _openai_extract_content(resp_json):
    return _openai_like_extract_content(resp_json)


def _gemini_extract_content(resp_json):
    candidates = resp_json.get("candidates", [])
    if not candidates:
        return ""
    first = candidates[0] if isinstance(candidates[0], dict) else {}
    content = first.get("content", {})
    parts = content.get("parts", []) if isinstance(content, dict) else []
    out = []
    for p in parts:
        if isinstance(p, dict) and p.get("text"):
            out.append(str(p["text"]))
    return "\n".join(out)


def _resolve_llm_runtime(args):
    provider = _canonical_provider_name(
        getattr(args, "llm_provider", "") or os.getenv("NFR_LLM_PROVIDER") or os.getenv("LLM_PROVIDER") or "ollama"
    )
    if provider == "openai":
        return {
            "provider": provider,
            "model": getattr(args, "openai_model", "") or os.getenv("NFR_OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o-mini",
            "base_url": getattr(args, "openai_base_url", "") or os.getenv("NFR_OPENAI_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1",
            "api_key": getattr(args, "openai_api_key", "") or os.getenv("NFR_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY") or "",
        }
    if provider == "openrouter":
        return {
            "provider": provider,
            "model": getattr(args, "openrouter_model", "") or os.getenv("NFR_OPENROUTER_MODEL") or os.getenv("OPENROUTER_MODEL") or "openai/gpt-4o-mini",
            "base_url": getattr(args, "openrouter_base_url", "") or os.getenv("NFR_OPENROUTER_BASE_URL") or os.getenv("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1",
            "api_key": getattr(args, "openrouter_api_key", "") or os.getenv("NFR_OPENROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY") or "",
        }
    if provider == "xai":
        return {
            "provider": provider,
            "model": getattr(args, "xai_model", "") or os.getenv("NFR_XAI_MODEL") or os.getenv("XAI_MODEL") or "grok-beta",
            "base_url": getattr(args, "xai_base_url", "") or os.getenv("NFR_XAI_BASE_URL") or os.getenv("XAI_BASE_URL") or "https://api.x.ai/v1",
            "api_key": getattr(args, "xai_api_key", "") or os.getenv("NFR_XAI_API_KEY") or os.getenv("XAI_API_KEY") or "",
        }
    if provider == "gemini":
        return {
            "provider": provider,
            "model": getattr(args, "gemini_model", "") or os.getenv("NFR_GEMINI_MODEL") or os.getenv("GEMINI_MODEL") or "gemini-1.5-flash",
            "base_url": getattr(args, "gemini_base_url", "") or os.getenv("NFR_GEMINI_BASE_URL") or os.getenv("GEMINI_BASE_URL") or "https://generativelanguage.googleapis.com/v1beta",
            "api_key": getattr(args, "gemini_api_key", "") or os.getenv("NFR_GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY") or "",
        }
    return {
        "provider": "ollama",
        "model": os.getenv("NFR_OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL") or "qwen3-coder:30b",
        "base_url": os.getenv("NFR_OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434",
        "api_key": "",
    }


def _provider_requires_key(provider):
    return _canonical_provider_name(provider) in {"openai", "openrouter", "xai", "gemini"}


def _is_local_host(host):
    if not host:
        return False
    h = str(host).strip().lower()
    return h in {"localhost", "127.0.0.1", "::1"}


def _is_external_llm_boundary(provider_name, base_url):
    p = _canonical_provider_name(provider_name)
    if p in {"openai", "openrouter", "xai", "gemini"}:
        return True
    if p == "ollama":
        try:
            host = urlparse(str(base_url or "")).hostname
        except Exception:
            host = ""
        return not _is_local_host(host)
    return True


def _safe_ai_risk_rank(level):
    v = str(level or "low").strip().lower()
    if v == "high":
        return 3
    if v == "medium":
        return 2
    return 1


def _safe_ai_risk_from_rank(rank):
    r = int(rank or 1)
    if r >= 3:
        return "high"
    if r == 2:
        return "medium"
    return "low"


def _has_safe_ai_boundary_signal(text):
    hay = str(text or "").lower()
    pats = [
        r"\bhttpclient\b",
        r"\bopenaiclient\b",
        r"\bpostasync\b",
        r"\bsendasync\b",
        r"\bfetch\s*\(",
        r"\baxios\.post\s*\(",
        r"\brequests\.post\s*\(",
        r"\blog\s*\(",
        r"\bwritealltext\b",
        r"\bupload\b",
    ]
    return any(re.search(p, hay) for p in pats)


def _is_safe_ai_noise_path(path):
    text = str(path or "").replace("\\", "/").lower()
    hints = [
        "/test/",
        "/tests/",
        "/spec/",
        "/fixtures/",
        "/samples/",
        "/example/",
        "/examples/",
        "/node_modules/",
        "/wwwroot/lib/",
        "/vendor/",
    ]
    if text.endswith(".min.js"):
        return True
    return any(h in text for h in hints)


def _ai_policy_risk_for_finding(finding):
    hint = str(finding.get("safe_ai_risk_hint", "") or "").strip().lower()
    base_from_hint = hint in {"high", "medium", "low"}
    hay = " ".join(
        [
            str(finding.get("rule_id", "")),
            str(finding.get("rule_title", "")),
            str(finding.get("file", "")),
            str(finding.get("match_text", "")),
            str(finding.get("snippet", "")),
        ]
    ).lower()
    if base_from_hint:
        base_rank = _safe_ai_risk_rank(hint)
    else:
        base_rank = 1

    # High risk: actual secret/token/key literals.
    high_literal_pats = [
        r"(?i)\b(password|api[_\s-]?key|client[_\s-]?secret|connectionstring|accountkey|sharedaccesskey|aws_secret_access_key|azure_client_secret|private[_\s-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        r"-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._-]{15,}",
    ]
    if any(re.search(p, hay) for p in high_literal_pats):
        base_rank = max(base_rank, 3)

    # Medium risk: sensitive logic hints and infrastructure literals.
    medium_pats = [
        r"(?i)\b(generatejwt|createtoken|validatetoken|accesstoken|refreshtoken|openid|oauth|oidc|saml|identityserver)\b",
        r"(?i)(?=.*\b(log|writealltext|postasync|sendasync|upload|serialize(?:object)?|tojson)\b)(?=.*\b(email|phone|address|ssn|aadhaar|pan|customer|user|profile)\b)",
        r"(?i)(redis://|amqp://|kafka://|mongodb://|server=|host=|endpoint=|internal\.api|private\.api)",
    ]
    if any(re.search(p, hay) for p in medium_pats):
        base_rank = max(base_rank, 2)

    # Low risk: architecture hints only.
    low_pats = [
        r"(?i)\b(ensuretenantaccess|validatetenantaccess|tenantauthorization|where\s*\([^)\n]{0,120}tenantid[^)\n]{0,120}\))\b",
        r"(?i)\b(verifysignature|rsa\.verify|hmac|validatelicense|decryptlicense)\b",
    ]
    if any(re.search(p, hay) for p in low_pats):
        base_rank = max(base_rank, 1)

    # Boundary-aware one-level elevation when sensitive code appears near external/logging boundary.
    is_sensitive = base_rank >= 2
    if is_sensitive and _has_safe_ai_boundary_signal(hay):
        base_rank = min(3, base_rank + 1)

    # Suppress likely noisy contexts.
    if _is_safe_ai_noise_path(finding.get("file", "")) and base_rank < 3:
        base_rank = 1

    return _safe_ai_risk_from_rank(base_rank)


def _redact_snippet_for_external(snippet):
    text = str(snippet or "")
    rules = [
        (r"(?i)(secret|password|token|api[_\s-]?key|client[_\s-]?secret|connectionstring)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1 = \"REDACTED\""),
        (r"(?i)(secret|password|token|api[_\s-]?key|client[_\s-]?secret|connectionstring)\s*[:=]\s*[^,\s;]+", r"\1 = REDACTED"),
        (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "REDACTED_JWT"),
    ]
    for pat, repl in rules:
        text = re.sub(pat, repl, text)
    return text


def _build_policy_blocked_result(finding, policy_mode, policy_risk, external_boundary):
    parsed = {
        "isIssue": True,
        "severity": finding.get("default_severity", "S3"),
        "confidence": 0.2,
        "title": f"LLM review blocked by safe AI policy for {finding.get('rule_id','unknown')}",
        "why": (
            f"External LLM transmission blocked ({policy_mode}) for {policy_risk}-risk snippet. "
            "Manual review required."
        ),
        "recommendation": "Review internally or use local-only model for sensitive code.",
        "testing_notes": ["Use local LLM or redacted snippet for external review."],
        "patch": "unknown",
        "changed_lines_reason": "",
        "patch_quality": "unknown",
        "patch_attention": "unavailable",
        "patch_attention_reason": "policy_blocked",
    }
    finding_out = dict(finding)
    finding_out["llm_review"] = parsed
    finding_out["llm_transport"] = {
        "attempts": 0,
        "attempts_allowed": 0,
        "fallback_used": True,
        "error_kind": "policy_blocked",
        "from_cache": False,
        "recovered_after_retry": False,
        "elapsed_ms": 0.0,
    }
    finding_out["llm_error_kind"] = "policy_blocked"
    finding_out["llm_attempts"] = 0
    finding_out["llm_retried"] = False
    finding_out["ai_policy"] = {
        "mode": policy_mode,
        "risk": policy_risk,
        "external_boundary": bool(external_boundary),
        "blocked": True,
        "redacted": False,
    }
    return finding_out


def _patch_playbook_for_rule(rule_id):
    rid = str(rule_id or "").upper()
    playbooks = {
        "NFR-DOTNET-003": "Prefer async/await over .Result/.Wait/GetAwaiter().GetResult(). Update signatures to async Task and propagate await safely.",
        "NFR-DOTNET-001": "Add CancellationToken parameter (ct) and pass ct to HttpClient async methods. Avoid CancellationToken.None in request paths.",
        "NFR-API-001": "Add CancellationToken to controller action signature and pass it through service/repo async calls.",
        "NFR-API-016": "Propagate existing CancellationToken from controller to downstream async operations without introducing duplicate parameters.",
        "NFR-API-004A": "Do not suggest JsonConvert.SerializeObjectAsync. If string payload is needed, keep synchronous serialization and optimize options/hot path. Use SerializeAsync only when writing to a stream.",
        "NFR-API-004B": "Keep serializer contract consistent. Do not auto-switch APIs unless settings compatibility is preserved.",
        "NFR-FE-005A": "For dynamic HTML sources, sanitize with DOMPurify before assigning to innerHTML/dangerouslySetInnerHTML.",
        "NFR-FE-005B": "If raw HTML usage is required, sanitize; otherwise prefer textContent or safe render APIs.",
        "NFR-DOTNET-014": "Replace empty catch with explicit logging and rethrow unless swallowing is intentional and documented.",
    }
    return playbooks.get(rid, "Keep patch minimal, local, and compile-safe. Avoid changing public signatures unless required.")


def _extract_class_hint(snippet):
    text = str(snippet or "")
    pats = [
        r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        r"\binterface\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        r"\bnamespace\s+([A-Za-z_][A-Za-z0-9_.]*)\b",
    ]
    for pat in pats:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return "unknown_class"


def _semantic_context_for_finding(finding):
    snippet = str(finding.get("snippet") or "")
    function_hint = _extract_function_hint(snippet)
    class_hint = _extract_class_hint(snippet)
    return (
        f"class_hint={class_hint}; function_hint={function_hint}; "
        f"language={finding.get('language','unknown')}; file_type={finding.get('file_type','unknown')}"
    )


def _is_unified_diff_like(patch_text):
    text = str(patch_text or "")
    if not text.strip() or text.strip().lower() == "unknown":
        return False
    has_header = ("--- " in text and "+++ " in text)
    has_hunk = "@@" in text
    has_delta = any(line.startswith("+") or line.startswith("-") for line in text.splitlines())
    return bool(has_header and has_hunk and has_delta)


def _confidence_for_patch_retry(parsed, finding):
    try:
        if parsed and parsed.get("confidence") is not None:
            return float(parsed.get("confidence"))
    except Exception:
        pass
    try:
        if finding.get("confidence_hint") is not None:
            return float(finding.get("confidence_hint"))
    except Exception:
        pass
    return float(_source_confidence_hint(finding))


def _should_attempt_patch_retry(parsed, finding, prefer_patch_s1s2, prefer_patch_all, patch_min_confidence):
    if str((finding or {}).get("patch_policy", "")).strip().lower() == "advisory_only":
        return False
    sev = str((parsed or {}).get("severity") or finding.get("default_severity") or "S3").upper()
    if sev in {"S1", "S2"} and bool(prefer_patch_s1s2):
        return True
    if not bool(prefer_patch_all):
        return False
    return _confidence_for_patch_retry(parsed, finding) >= float(patch_min_confidence or 0.0)


def _classify_patch_attention(finding, parsed):
    patch = str((parsed or {}).get("patch", "unknown") or "unknown")
    p = patch.strip().lower()
    if p in {"", "unknown"}:
        return "unavailable", "no_patch"
    lower = patch.lower()
    risky_tokens = [
        "cancellationtoken",
        "task<",
        "public ",
        "private ",
        "protected ",
        "interface ",
        "class ",
        "throw;",
    ]
    if any(tok in lower for tok in risky_tokens):
        return "needs_attention", "signature_or_behavior_change"
    return "safe", "local_change"


def _patch_template_key(finding):
    snippet = finding.get("snippet") or finding.get("match_text") or ""
    func = _extract_function_hint(snippet)
    raw = f"{finding.get('rule_id','unknown')}|{func}|{_normalize_text_for_key(finding.get('match_text') or '')}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()


def _resolve_patch_template_cache_path(cache_file, output_dir):
    p = Path(cache_file or "patch_template_cache.json")
    if not p.is_absolute():
        p = Path(output_dir) / p
    return p


def load_patch_template_cache(cache_path):
    p = Path(cache_path)
    if not p.exists() or not p.is_file():
        return {}
    try:
        payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {}


def save_patch_template_cache(cache_path, cache_data):
    p = Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")


def _apply_patch_template_if_available(
    item,
    template_cache,
    patch_strict_locality=False,
    patch_locality_window=12,
):
    review = (item.get("llm_review", {}) or {})
    patch = str(review.get("patch", "unknown") or "unknown").strip().lower()
    if patch != "unknown":
        return item, False
    key = _patch_template_key(item)
    cached = template_cache.get(key) if isinstance(template_cache, dict) else None
    if not isinstance(cached, dict):
        return item, False
    candidate = str(cached.get("patch", "unknown") or "unknown")
    if candidate.strip().lower() == "unknown":
        return item, False
    out = dict(item)
    out_review = dict(review)
    out_review["patch"] = candidate
    out_review["patch_quality"] = _patch_quality(candidate)
    sanity_issues = _patch_sanity_issues(
        candidate,
        out,
        strict_locality=bool(patch_strict_locality),
        locality_window=int(patch_locality_window or 0),
    )
    if sanity_issues:
        out_review["patch"] = "unknown"
        out_review["patch_quality"] = "unknown"
        out_review["patch_sanity_issues"] = sanity_issues
    out_review["patch_from_template_cache"] = True
    attention, reason = _classify_patch_attention(out, out_review)
    out_review["patch_attention"] = attention
    out_review["patch_attention_reason"] = reason
    out["llm_review"] = out_review
    return out, True


def _send_llm_request(
    provider,
    model,
    base_url,
    api_key,
    prompt,
    temperature,
    connect_timeout_seconds,
    read_timeout_seconds,
):
    provider_name = _canonical_provider_name(provider)
    timeout = (float(connect_timeout_seconds), float(read_timeout_seconds))
    if provider_name in {"openai", "openrouter", "xai"}:
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
        resp.raise_for_status()
        return _openai_like_extract_content(resp.json())
    if provider_name == "gemini":
        url = f"{base_url.rstrip('/')}/models/{model}:generateContent"
        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{"role": "user", "parts": [{"text": f"{SYSTEM_PROMPT}\n\n{prompt}"}]}],
            "generationConfig": {"temperature": temperature},
        }
        resp = requests.post(url, params={"key": api_key}, headers=headers, json=body, timeout=timeout)
        resp.raise_for_status()
        return _gemini_extract_content(resp.json())

    url = f"{base_url.rstrip('/')}/api/chat"
    body = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "options": {"temperature": temperature},
    }
    resp = requests.post(url, json=body, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


def _maybe_retry_patch_for_unknown(
    finding,
    parsed,
    provider_name,
    provider_label,
    model,
    base_url,
    api_key,
    temperature,
    connect_timeout_seconds,
    read_timeout_seconds,
    prefer_patch_s1s2,
    prefer_patch_all,
    patch_min_confidence,
    snippet_for_prompt,
):
    is_issue = bool((parsed or {}).get("isIssue", False))
    patch_value = str((parsed or {}).get("patch", "unknown") or "unknown").strip().lower()
    if not is_issue or patch_value != "unknown":
        return parsed
    if not _should_attempt_patch_retry(parsed, finding, prefer_patch_s1s2, prefer_patch_all, patch_min_confidence):
        return parsed

    patch_prompt = (
        "Return JSON only with keys: patch, changed_lines_reason.\n"
        "Generate a minimal, safe unified diff patch for this finding.\n"
        "Use only symbols visible in snippet/context. If impossible, return {\"patch\":\"unknown\"}.\n\n"
        "Hard constraints:\n"
        "- Do not change unrelated behavior.\n"
        "- Do not remove/disable persistence or security calls.\n"
        "- Do not invent APIs or overloads.\n"
        "- If signature changes are uncertain, return patch=unknown.\n\n"
        f"Rule ID: {finding.get('rule_id','unknown')}\n"
        f"Patch Playbook: {_patch_playbook_for_rule(finding.get('rule_id',''))}\n"
        f"Semantic Context: {_semantic_context_for_finding(finding)}\n"
        f"File: {finding.get('file','unknown')}\n"
        f"Line: {finding.get('line',1)}\n"
        "Snippet:\n"
        f"{snippet_for_prompt}\n"
    )
    try:
        content = _send_llm_request(
            provider_name,
            model,
            base_url,
            api_key,
            patch_prompt,
            temperature,
            connect_timeout_seconds,
            read_timeout_seconds,
        )
        patch_only = _extract_json(content)
        candidate = str((patch_only or {}).get("patch", "unknown") or "unknown")
        if candidate.strip().lower() != "unknown":
            parsed["patch"] = candidate
            parsed["changed_lines_reason"] = str((patch_only or {}).get("changed_lines_reason", "") or "").strip()
            parsed["patch_retry_used"] = True
            log_progress(
                f"{provider_label} patch retry succeeded for {finding.get('rule_id','unknown')} "
                f"at {finding.get('file','unknown')}:{finding.get('line',1)}."
            )
    except Exception as exc:
        log_progress(
            f"{provider_label} patch retry failed for {finding.get('rule_id','unknown')} "
            f"at {finding.get('file','unknown')}:{finding.get('line',1)}. Error: {exc}"
        )
    return parsed


def _retry_patch_after_noop(
    finding,
    parsed,
    provider_name,
    provider_label,
    model,
    base_url,
    api_key,
    temperature,
    connect_timeout_seconds,
    read_timeout_seconds,
    repair_retries,
    snippet_for_prompt,
):
    attempts = max(0, int(repair_retries or 0))
    if attempts <= 0:
        return parsed
    patch = str((parsed or {}).get("patch", "unknown") or "unknown")
    if _patch_quality(patch) != "no_op":
        return parsed
    for attempt in range(1, attempts + 1):
        repair_prompt = (
            "Return JSON only with keys: patch, changed_lines_reason.\n"
            "Previous patch was a NO-OP (no effective code changes).\n"
            "Provide a corrected unified diff with real line changes, minimal and safe.\n"
            "Do not repeat identical +/- lines. If impossible, return {\"patch\":\"unknown\"}.\n\n"
            "Hard constraints:\n"
            "- Do not change unrelated behavior.\n"
            "- Do not remove/disable persistence or security calls.\n"
            "- Do not invent APIs or overloads.\n\n"
            f"Rule ID: {finding.get('rule_id','unknown')}\n"
            f"Patch Playbook: {_patch_playbook_for_rule(finding.get('rule_id',''))}\n"
            f"Semantic Context: {_semantic_context_for_finding(finding)}\n"
            f"File: {finding.get('file','unknown')}\n"
            f"Line: {finding.get('line',1)}\n"
            "Snippet:\n"
            f"{snippet_for_prompt}\n\n"
            "Previous no-op patch:\n"
            f"{patch}\n"
        )
        try:
            content = _send_llm_request(
                provider_name,
                model,
                base_url,
                api_key,
                repair_prompt,
                temperature,
                connect_timeout_seconds,
                read_timeout_seconds,
            )
            repaired = _extract_json(content)
            candidate = str((repaired or {}).get("patch", "unknown") or "unknown")
            parsed["patch"] = candidate
            parsed["changed_lines_reason"] = str((repaired or {}).get("changed_lines_reason", "") or "").strip()
            parsed["patch_repair_attempts"] = attempt
            if _patch_quality(candidate) != "no_op":
                log_progress(
                    f"{provider_label} patch repair succeeded for {finding.get('rule_id','unknown')} "
                    f"at {finding.get('file','unknown')}:{finding.get('line',1)} (attempt {attempt}/{attempts})."
                )
                return parsed
        except Exception as exc:
            log_progress(
                f"{provider_label} patch repair failed for {finding.get('rule_id','unknown')} "
                f"at {finding.get('file','unknown')}:{finding.get('line',1)} (attempt {attempt}/{attempts}). Error: {exc}"
            )
    return parsed


def _verify_patch_semantics(
    finding,
    parsed,
    provider_name,
    provider_label,
    model,
    base_url,
    api_key,
    temperature,
    connect_timeout_seconds,
    read_timeout_seconds,
    snippet_for_prompt,
    enabled=False,
):
    if not bool(enabled):
        return parsed
    if not isinstance(parsed, dict):
        return parsed
    patch_text = str(parsed.get("patch", "unknown") or "unknown")
    if patch_text.strip().lower() == "unknown":
        return parsed

    verify_prompt = (
        "Return JSON only with keys: patch_valid, reason, confidence.\n"
        "Validate whether the suggested patch is technically correct for the given finding and snippet.\n"
        "Check for: wrong API usage, no-op edits, unrelated semantic changes, signature-breaking edits, "
        "or changes not justified by the finding.\n"
        "If uncertain, set patch_valid=false.\n\n"
        f"Rule ID: {finding.get('rule_id','unknown')}\n"
        f"Rule Title: {finding.get('rule_title','unknown')}\n"
        f"File: {finding.get('file','unknown')}\n"
        f"Line: {finding.get('line',1)}\n"
        "Snippet:\n"
        f"{snippet_for_prompt}\n\n"
        "Patch:\n"
        f"{patch_text}\n"
    )

    try:
        content = _send_llm_request(
            provider_name,
            model,
            base_url,
            api_key,
            verify_prompt,
            temperature,
            connect_timeout_seconds,
            read_timeout_seconds,
        )
        verdict = _extract_json(content)
    except Exception as exc:
        parsed["patch_verification"] = {
            "attempted": True,
            "status": "error",
            "reason": f"{provider_label} verifier failed: {exc}",
        }
        return parsed

    patch_valid = bool(verdict.get("patch_valid", False))
    reason = str(verdict.get("reason", "") or "").strip()
    try:
        conf = float(verdict.get("confidence", 0.0) or 0.0)
    except Exception:
        conf = 0.0
    conf = max(0.0, min(conf, 1.0))

    parsed["patch_verification"] = {
        "attempted": True,
        "status": "accepted" if patch_valid else "rejected",
        "reason": reason,
        "confidence": conf,
    }
    if patch_valid:
        return parsed

    parsed["patch"] = "unknown"
    parsed["changed_lines_reason"] = ""
    parsed["patch_quality"] = "unknown"
    notes = list(parsed.get("testing_notes", []) or [])
    notes.append(
        "Patch verifier rejected suggested patch as not semantically safe/correct for the snippet."
        + (f" Reason: {reason}" if reason else "")
    )
    parsed["testing_notes"] = notes
    return parsed


def _slim_snippet_for_prompt(finding):
    snippet = str(finding.get("snippet") or finding.get("match_text") or "")
    sev = str(finding.get("default_severity", "S3")).upper()
    if sev in {"S1", "S2"}:
        return snippet

    target_line = int(finding.get("line", 1) or 1)
    lines = snippet.splitlines()
    if not lines:
        return snippet

    parsed = []
    for raw in lines:
        m = re.match(r"^\s*(\d+):\s?(.*)$", raw)
        if m:
            parsed.append((int(m.group(1)), m.group(2)))
        else:
            parsed.append((None, raw))

    center_idx = None
    for idx, (ln, _) in enumerate(parsed):
        if ln == target_line:
            center_idx = idx
            break
    if center_idx is None:
        center_idx = max(0, min(len(parsed) - 1, len(parsed) // 2))

    start = max(0, center_idx - 4)
    end = min(len(parsed), center_idx + 5)
    selected = parsed[start:end]
    out = []
    for ln, body in selected:
        if ln is None:
            out.append(body)
        else:
            out.append(f"{ln:5d}: {body}")
    slim = "\n".join(out)
    if len(slim) > 2200:
        slim = slim[:2200]
    return slim


def _review_single_finding(
    finding,
    provider,
    model,
    base_url,
    api_key,
    temperature,
    retries,
    retry_backoff_seconds,
    connect_timeout_seconds,
    read_timeout_seconds,
    prefer_patch_s1s2,
    prefer_patch_all_severities,
    patch_min_confidence,
    patch_repair_retries,
    patch_strict_locality,
    patch_locality_window,
    patch_verify_pass,
    safe_ai_policy_mode,
    safe_ai_allow_external_high_risk,
    safe_ai_redact_medium,
):
    started = time.perf_counter()
    rule_guidance = "N/A"
    default_sev = str(finding.get("default_severity", "S3")).upper()
    patch_guidance = (
        "If safe patch cannot be produced from this snippet alone, set patch to 'unknown'. "
        "Do not invent symbols or methods."
    )
    if default_sev in {"S1", "S2"}:
        patch_guidance = (
            "Prioritize producing a minimal, safe unified diff patch for this S1/S2 finding. "
            "Use only symbols visible in snippet/context. If truly impossible, return patch='unknown'."
        )
    patch_guidance += (
        " Do not modify unrelated lines; do not remove/disable persistence or security calls; "
        "do not invent APIs/overloads; if uncertain, return patch='unknown'."
    )
    patch_playbook = _patch_playbook_for_rule(finding.get("rule_id", ""))
    semantic_context = _semantic_context_for_finding(finding)
    provider_name = _canonical_provider_name(provider)
    provider_label = _provider_label(provider_name)
    external_boundary = _is_external_llm_boundary(provider_name, base_url)
    policy_mode = str(safe_ai_policy_mode or "warn").strip().lower()
    if policy_mode not in {"off", "warn", "enforce"}:
        policy_mode = "warn"
    policy_risk = _ai_policy_risk_for_finding(finding)
    snippet_for_prompt = _slim_snippet_for_prompt(finding)
    policy_redacted = False
    if external_boundary and policy_mode in {"warn", "enforce"}:
        if policy_risk == "high" and not bool(safe_ai_allow_external_high_risk):
            if policy_mode == "enforce":
                return _build_policy_blocked_result(finding, policy_mode, policy_risk, external_boundary)
            log_progress(
                f"Safe AI policy warning: high-risk snippet sent to external provider for "
                f"{finding.get('rule_id','unknown')} at {finding.get('file','unknown')}:{finding.get('line',1)}."
            )
        if policy_risk == "medium" and bool(safe_ai_redact_medium):
            snippet_for_prompt = _redact_snippet_for_external(snippet_for_prompt)
            policy_redacted = True
    if str(finding.get("rule_id", "")).startswith("NFR-API-004"):
        rule_guidance = (
            "Do NOT suggest JsonConvert.SerializeObjectAsync (invalid API). "
            "Only suggest SerializeAsync/DeserializeAsync when writing to or reading from streams. "
            "If a string payload is required, keep synchronous serialization and optimize by reusing serializer options "
            "and avoiding serialize-deserialize round trips in hot paths."
        )
    rule_payload = {
        "id": finding["rule_id"],
        "title": finding["rule_title"],
        "category": finding["category"],
        "top_level_category": finding.get("top_level_category", "dotnet"),
        "sub_category": finding.get("sub_category", "performance"),
        "default_severity": finding["default_severity"],
        "rationale": finding["rationale"],
        "source": finding.get("source", "unknown"),
    }
    prompt = USER_TEMPLATE.format(
        rule_json=json.dumps(rule_payload, ensure_ascii=True),
        rule_guidance=rule_guidance,
        patch_guidance=patch_guidance,
        patch_playbook=patch_playbook,
        semantic_context=semantic_context,
        file_path=finding["file"],
        line=finding["line"],
        snippet=snippet_for_prompt,
    )

    parsed = None
    last_error_kind = ""
    fallback_used = False
    attempts_used = 0
    attempts_total = max(0, int(retries)) + 1
    for attempt in range(1, attempts_total + 1):
        attempts_used = attempt
        try:
            content = _send_llm_request(
                provider_name,
                model,
                base_url,
                api_key,
                prompt,
                temperature,
                connect_timeout_seconds,
                read_timeout_seconds,
            )
            parsed = _extract_json(content)
            if attempt > 1:
                log_progress(
                    f"{provider_label} request recovered after retry for {finding.get('rule_id', 'unknown')} "
                    f"at {finding.get('file', 'unknown')}:{finding.get('line', 1)} "
                    f"(attempt {attempt}/{attempts_total})."
                )
            break
        except Exception as exc:
            retriable, error_kind = _classify_llm_error(exc)
            last_error_kind = error_kind
            context = (
                f"{finding.get('rule_id', 'unknown')} at "
                f"{finding.get('file', 'unknown')}:{finding.get('line', 1)}"
            )
            if retriable and attempt < attempts_total:
                delay = max(0.0, float(retry_backoff_seconds)) * (2 ** (attempt - 1))
                log_progress(
                    f"{provider_label} request failed ({error_kind}) for {context}. "
                    f"Attempt {attempt}/{attempts_total}. Retrying in {delay:.1f}s. Error: {exc}"
                )
                if delay > 0:
                    time.sleep(delay)
                continue

            log_progress(
                f"{provider_label} request failed ({error_kind}) for {context}. "
                f"Attempt {attempt}/{attempts_total}. "
                f"{'Non-retriable' if not retriable else 'Retries exhausted'}; using fallback review. Error: {exc}"
            )
            parsed = {
                "isIssue": True,
                "severity": finding["default_severity"],
                "confidence": 0.2,
                "title": f"LLM review failed for {finding['rule_id']}",
                "why": f"Could not validate finding using {provider_label}: {exc}",
                "recommendation": "Manual review required.",
                "testing_notes": [f"Re-run scan after ensuring {provider_label} model/service is available."],
                "patch": "unknown",
                "changed_lines_reason": "",
            }
            fallback_used = True
            break

    sev = str(parsed.get("severity") or finding["default_severity"] or "S3").upper()
    if sev not in SEVERITY_ORDER:
        sev = "S3"
    parsed["severity"] = sev
    parsed["effort"] = _normalize_effort(parsed.get("effort"))
    parsed["benefit"] = _normalize_benefit(parsed.get("benefit"), sev)
    parsed["changed_lines_reason"] = str(parsed.get("changed_lines_reason", "") or "").strip()
    if "quick_win" not in parsed:
        parsed["quick_win"] = _infer_quick_win(sev, parsed["effort"], parsed["benefit"])
    else:
        parsed["quick_win"] = bool(parsed.get("quick_win"))
    parsed = _post_llm_false_positive_gate(parsed, finding, fallback_used=fallback_used)
    current_conf = _confidence_for_patch_retry(parsed, finding)
    if sev not in {"S1", "S2"} and current_conf < float(patch_min_confidence or 0.0):
        parsed["patch"] = "unknown"
        parsed["changed_lines_reason"] = ""
        parsed["patch_policy"] = "confidence_gated"
    if str(finding.get("patch_policy", "")).strip().lower() == "advisory_only":
        parsed["patch"] = "unknown"
        parsed["changed_lines_reason"] = ""
        parsed["patch_policy"] = "advisory_only"
    parsed["patch_quality"] = _patch_quality(parsed.get("patch", "unknown"))
    parsed = _maybe_retry_patch_for_unknown(
        finding,
        parsed,
        provider_name,
        provider_label,
        model,
        base_url,
        api_key,
        temperature,
        connect_timeout_seconds,
        read_timeout_seconds,
        prefer_patch_s1s2,
        prefer_patch_all_severities,
        patch_min_confidence,
        snippet_for_prompt,
    )
    parsed["patch_quality"] = _patch_quality(parsed.get("patch", "unknown"))
    parsed = _retry_patch_after_noop(
        finding,
        parsed,
        provider_name,
        provider_label,
        model,
        base_url,
        api_key,
        temperature,
        connect_timeout_seconds,
        read_timeout_seconds,
        patch_repair_retries,
        snippet_for_prompt,
    )
    parsed["patch_quality"] = _patch_quality(parsed.get("patch", "unknown"))
    if parsed["patch_quality"] == "valid" and not _is_unified_diff_like(parsed.get("patch", "")):
        parsed["patch_quality"] = "unknown"
        parsed["patch"] = "unknown"
        parsed["changed_lines_reason"] = ""
        notes = list(parsed.get("testing_notes", []) or [])
        notes.append("Suggested patch was not a valid unified diff; manual fix proposal required.")
        parsed["testing_notes"] = notes
    if parsed["patch_quality"] == "no_op":
        parsed["patch"] = "unknown"
        parsed["changed_lines_reason"] = ""
        notes = list(parsed.get("testing_notes", []) or [])
        notes.append("Suggested patch was a no-op; manual fix proposal required.")
        parsed["testing_notes"] = notes
    sanity_issues = _patch_sanity_issues(
        parsed.get("patch", "unknown"),
        finding,
        strict_locality=bool(patch_strict_locality),
        locality_window=int(patch_locality_window or 0),
    )
    parsed["patch_sanity_issues"] = sanity_issues
    if sanity_issues:
        parsed["patch"] = "unknown"
        parsed["changed_lines_reason"] = ""
        parsed["patch_quality"] = "unknown"
        notes = list(parsed.get("testing_notes", []) or [])
        notes.append(f"Suggested patch failed sanity checks ({', '.join(sanity_issues)}); manual fix proposal required.")
        parsed["testing_notes"] = notes
    parsed = _verify_patch_semantics(
        finding,
        parsed,
        provider_name,
        provider_label,
        model,
        base_url,
        api_key,
        temperature,
        connect_timeout_seconds,
        read_timeout_seconds,
        snippet_for_prompt,
        enabled=bool(patch_verify_pass),
    )
    parsed["patch_quality"] = _patch_quality(parsed.get("patch", "unknown"))
    patch_attention, patch_attention_reason = _classify_patch_attention(finding, parsed)
    parsed["patch_attention"] = patch_attention
    parsed["patch_attention_reason"] = patch_attention_reason

    finding_out = dict(finding)
    finding_out["llm_review"] = parsed
    finding_out["llm_transport"] = {
        "attempts": attempts_used,
        "attempts_allowed": attempts_total,
        "fallback_used": fallback_used,
        "error_kind": last_error_kind,
        "from_cache": False,
        "recovered_after_retry": (not fallback_used and attempts_used > 1),
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
    }
    finding_out["llm_error_kind"] = last_error_kind
    finding_out["llm_attempts"] = attempts_used
    finding_out["llm_retried"] = attempts_used > 1
    finding_out["ai_policy"] = {
        "mode": policy_mode,
        "risk": policy_risk,
        "external_boundary": bool(external_boundary),
        "blocked": False,
        "redacted": bool(policy_redacted),
    }
    return finding_out


def review_with_llm(
    findings,
    provider,
    model,
    base_url,
    api_key,
    temperature,
    workers=1,
    retries=2,
    retry_backoff_seconds=1.5,
    connect_timeout_seconds=20.0,
    read_timeout_seconds=120.0,
    prefer_patch_s1s2=True,
    prefer_patch_all_severities=True,
    patch_min_confidence=0.6,
    patch_repair_retries=1,
    patch_strict_locality=False,
    patch_locality_window=12,
    patch_verify_pass=False,
    safe_ai_policy_mode="warn",
    safe_ai_allow_external_high_risk=False,
    safe_ai_redact_medium=True,
):
    reviewed = []
    total = len(findings)
    workers = max(1, int(workers or 1))
    provider_name = _canonical_provider_name(provider)
    provider_label = _provider_label(provider_name)
    log_progress(
        f"Starting {provider_label} review for {total} finding(s) with model '{model}' (workers={workers})."
    )

    if workers == 1 or total <= 1:
        for idx, finding in enumerate(findings, start=1):
            reviewed.append(
                _review_single_finding(
                    finding,
                    provider_name,
                    model,
                    base_url,
                    api_key,
                    temperature,
                    retries,
                    retry_backoff_seconds,
                    connect_timeout_seconds,
                    read_timeout_seconds,
                    prefer_patch_s1s2,
                    prefer_patch_all_severities,
                    patch_min_confidence,
                    patch_repair_retries,
                    patch_strict_locality,
                    patch_locality_window,
                    patch_verify_pass,
                    safe_ai_policy_mode,
                    safe_ai_allow_external_high_risk,
                    safe_ai_redact_medium,
                )
            )
            if idx % 10 == 0 or idx == total:
                log_progress(f"{provider_label} review progress: {idx}/{total}")
        return reviewed

    ordered = [None] * total
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {
            executor.submit(
                _review_single_finding,
                finding,
                provider_name,
                model,
                base_url,
                api_key,
                temperature,
                retries,
                retry_backoff_seconds,
                connect_timeout_seconds,
                read_timeout_seconds,
                prefer_patch_s1s2,
                prefer_patch_all_severities,
                patch_min_confidence,
                patch_repair_retries,
                patch_strict_locality,
                patch_locality_window,
                patch_verify_pass,
                safe_ai_policy_mode,
                safe_ai_allow_external_high_risk,
                safe_ai_redact_medium,
            ): idx
            for idx, finding in enumerate(findings)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            ordered[idx] = future.result()
            done += 1
            if done % 10 == 0 or done == total:
                log_progress(f"{provider_label} review progress: {done}/{total}")

    return [x for x in ordered if x is not None]


def load_baseline_keys(path):
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        findings = payload.get("findings", []) if isinstance(payload, dict) else payload
        return {x.get("finding_key") for x in findings if isinstance(x, dict) and x.get("finding_key")}
    except Exception:
        return set()


def _percentile(values, pct):
    vals = sorted(float(v) for v in values if v is not None)
    if not vals:
        return 0.0
    if len(vals) == 1:
        return vals[0]
    k = (len(vals) - 1) * (float(pct) / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    if lo == hi:
        return vals[lo]
    frac = k - lo
    return vals[lo] * (1 - frac) + vals[hi] * frac


def _latency_stats_from_reviewed(items):
    lat = [float((x.get("llm_transport", {}) or {}).get("elapsed_ms", 0.0)) for x in items]
    lat = [x for x in lat if x > 0]
    if not lat:
        return {"count": 0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0}
    return {
        "count": len(lat),
        "avg_ms": round(sum(lat) / len(lat), 2),
        "p50_ms": round(_percentile(lat, 50), 2),
        "p95_ms": round(_percentile(lat, 95), 2),
    }


def baseline_path_for_project(output_dir, baseline_dir, project_name):
    return Path(output_dir) / baseline_dir / f"{project_name}.json"


def write_baseline_file(path, findings, scan_meta):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scan": {
            "project": scan_meta.get("project", ""),
            "run_version": scan_meta.get("run_version", ""),
            "scan_path": scan_meta.get("scan_path", ""),
            "written_at": datetime.now().isoformat(timespec="seconds"),
        },
        "findings": [
            {
                "finding_key": f.get("finding_key"),
                "rule_id": f.get("rule_id"),
                "file": f.get("file"),
                "line": f.get("line"),
            }
            for f in findings
            if isinstance(f, dict) and f.get("finding_key")
        ],
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def _normalize_text_for_key(text):
    value = str(text or "").lower()
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > 2000:
        value = value[:2000]
    return value


def _llm_cache_key(finding):
    raw = f"{finding.get('rule_id', 'unknown')}|{_normalize_text_for_key(finding.get('snippet') or finding.get('match_text') or '')}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()


def _resolve_cache_path(cache_file, output_dir):
    p = Path(cache_file or "llm_review_cache.json")
    if not p.is_absolute():
        p = Path(output_dir) / p
    return p


def load_llm_cache(cache_path):
    p = Path(cache_path)
    if not p.exists() or not p.is_file():
        return {}
    try:
        payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {}


def save_llm_cache(cache_path, cache_data):
    p = Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")


def _source_confidence_hint(finding):
    if finding.get("confidence_hint") is not None:
        try:
            return float(finding.get("confidence_hint"))
        except Exception:
            pass
    source = str(finding.get("source", "")).lower()
    if source == "roslyn":
        return 0.95
    return 0.65


def _priority_sort_key(finding):
    sev = str(finding.get("default_severity", "S3")).upper()
    sev_rank = SEVERITY_ORDER.get(sev, 2)
    noisy_rank = 1 if bool(finding.get("priority_demoted")) else 0
    hint = finding.get("confidence_hint")
    if hint is None:
        hint = _source_confidence_hint(finding)
    try:
        hint = float(hint)
    except Exception:
        hint = 0.5
    return (
        noisy_rank,
        sev_rank,
        -hint,
        str(finding.get("rule_id", "")),
        str(finding.get("file", "")),
        int(finding.get("line", 1) or 1),
    )


def _extract_function_hint(snippet):
    text = str(snippet or "")
    patterns = [
        r"\b(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|\s)+\s+[A-Za-z_][A-Za-z0-9_<>,\[\]\?]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*\([^)]*\)\s*=>",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return "unknown_function"


def build_llm_clusters(findings):
    grouped = {}
    order = 0
    for f in findings:
        func = _extract_function_hint(f.get("snippet", ""))
        match_key = _normalize_text_for_key(f.get("match_text", ""))
        if len(match_key) > 240:
            match_key = match_key[:240]
        key = (
            str(f.get("rule_id", "unknown")),
            str(f.get("file", "unknown")),
            func,
            match_key,
        )
        if key not in grouped:
            grouped[key] = {
                "cluster_id": f"cluster_{len(grouped) + 1}",
                "members": [],
                "order": order,
            }
            order += 1
        grouped[key]["members"].append(f)

    clusters = []
    for g in grouped.values():
        members = g["members"]
        members_sorted = sorted(members, key=_priority_sort_key)
        representative = members_sorted[0]
        clusters.append(
            {
                "cluster_id": g["cluster_id"],
                "representative": representative,
                "members": members,
                "order": g["order"],
            }
        )
    return clusters


def expand_cluster_review(rep_reviewed, cluster):
    out = []
    members = cluster.get("members", [])
    for member in members:
        item = dict(member)
        item["llm_review"] = dict(rep_reviewed.get("llm_review", {}))
        transport = dict(rep_reviewed.get("llm_transport", {}))
        item["llm_transport"] = transport
        item["llm_error_kind"] = rep_reviewed.get("llm_error_kind", "")
        item["llm_attempts"] = rep_reviewed.get("llm_attempts", 0)
        item["llm_retried"] = bool(rep_reviewed.get("llm_retried", False))
        item["llm_cluster"] = {
            "cluster_id": cluster.get("cluster_id"),
            "cluster_size": len(members),
            "representative_key": cluster.get("representative", {}).get("finding_key"),
            "function_hint": _extract_function_hint(member.get("snippet", "")),
        }
        out.append(item)
    return out


def adapt_llm_workers(current_workers, max_workers, batch_reviewed, stable_batches):
    if not batch_reviewed:
        return current_workers, stable_batches
    timeout_like = 0
    fallback_used = 0
    for item in batch_reviewed:
        t = item.get("llm_transport", {}) or {}
        if t.get("fallback_used"):
            fallback_used += 1
        kind = str(t.get("error_kind") or "")
        if kind in {"timeout", "connection_error"} or kind.startswith("http_5") or kind == "http_429":
            timeout_like += 1

    total = len(batch_reviewed)
    timeout_rate = timeout_like / total
    fallback_rate = fallback_used / total

    if current_workers > 1 and (timeout_rate >= 0.15 or fallback_rate >= 0.25):
        new_workers = max(1, current_workers - 1)
        if new_workers < current_workers:
            log_progress(
                f"Adaptive workers: reducing llm-workers {current_workers} -> {new_workers} "
                f"(timeout_rate={timeout_rate:.2f}, fallback_rate={fallback_rate:.2f})"
            )
            return new_workers, 0
        return current_workers, 0

    if current_workers < max_workers and timeout_rate == 0.0 and fallback_rate <= 0.05:
        stable_batches += 1
        if stable_batches >= 2:
            new_workers = min(max_workers, current_workers + 1)
            if new_workers > current_workers:
                log_progress(
                    f"Adaptive workers: increasing llm-workers {current_workers} -> {new_workers} "
                    f"after stable batches."
                )
                return new_workers, 0
        return current_workers, stable_batches

    return current_workers, 0


def _module_key(path):
    p = Path(path).parts
    if len(p) >= 2:
        return f"{p[0]}/{p[1]}"
    if len(p) == 1:
        return p[0]
    return "unknown"


def summarize(reviewed):
    for item in reviewed:
        item["trust_tier"] = trust_tier_of(item)
    confirmed = [x for x in reviewed if bool(x.get("llm_review", {}).get("isIssue", False))]
    fallback_findings = [x for x in reviewed if bool((x.get("llm_transport", {}) or {}).get("fallback_used", False))]

    def severity_of(item):
        sev = item.get("llm_review", {}).get("severity") or item.get("default_severity") or "S3"
        return sev if sev in SEVERITY_ORDER else "S3"

    confirmed.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(severity_of(x), 2),
            -float(x.get("llm_review", {}).get("confidence", 0.0) or 0.0),
        )
    )

    by_category = Counter(x.get("category", "unknown") for x in confirmed)
    by_module = Counter(_module_key(x.get("file", "")) for x in confirmed)
    by_severity = Counter(severity_of(x) for x in confirmed)
    by_source = Counter(x.get("source", "unknown") for x in confirmed)
    by_trust_tier = Counter(x.get("trust_tier", "unknown") for x in confirmed)
    by_action_bucket = Counter(x.get("action_bucket", "app_code") for x in confirmed)
    by_language = Counter(x.get("language", "unknown") for x in confirmed)
    by_file_type = Counter(x.get("file_type", "unknown") for x in confirmed)
    rule_quality = build_rule_quality_scoreboard(reviewed)
    patch_quality = Counter(str((x.get("llm_review", {}) or {}).get("patch_quality", "unknown")).lower() for x in reviewed)
    patch_attention = Counter(str((x.get("llm_review", {}) or {}).get("patch_attention", "unavailable")).lower() for x in reviewed)
    patch_generated = sum(
        1
        for x in reviewed
        if str((x.get("llm_review", {}) or {}).get("patch", "unknown")).strip().lower() not in {"", "unknown"}
    )
    template_applied = sum(
        1 for x in reviewed if bool((x.get("llm_review", {}) or {}).get("patch_from_template_cache", False))
    )
    patch_metrics = {
        "generated": patch_generated,
        "unknown": int(patch_quality.get("unknown", 0)),
        "no_op_dropped": int(patch_quality.get("no_op", 0)),
        "valid_quality": int(patch_quality.get("valid", 0)),
        "safe_generated": int(patch_attention.get("safe", 0)),
        "needs_attention_generated": int(patch_attention.get("needs_attention", 0)),
        "template_cache_applied": int(template_applied),
        "attention_split": dict(patch_attention),
        "total_reviewed": len(reviewed),
    }
    ai_policy_metrics = {
        "external_boundary_findings": sum(1 for x in reviewed if bool((x.get("ai_policy", {}) or {}).get("external_boundary", False))),
        "blocked_findings": sum(1 for x in reviewed if bool((x.get("ai_policy", {}) or {}).get("blocked", False))),
        "redacted_findings": sum(1 for x in reviewed if bool((x.get("ai_policy", {}) or {}).get("redacted", False))),
        "high_risk_findings": sum(1 for x in reviewed if str((x.get("ai_policy", {}) or {}).get("risk", "")).lower() == "high"),
        "medium_risk_findings": sum(1 for x in reviewed if str((x.get("ai_policy", {}) or {}).get("risk", "")).lower() == "medium"),
    }

    return {
        "all_reviewed": reviewed,
        "confirmed": confirmed,
        "fallback_findings": fallback_findings,
        "by_category": dict(by_category),
        "by_module": dict(by_module),
        "by_severity": dict(by_severity),
        "by_source": dict(by_source),
        "by_trust_tier": dict(by_trust_tier),
        "by_action_bucket": dict(by_action_bucket),
        "by_language": dict(by_language),
        "by_file_type": dict(by_file_type),
        "rule_quality": rule_quality,
        "patch_metrics": patch_metrics,
        "ai_policy_metrics": ai_policy_metrics,
        "app_fix_backlog_count": sum(1 for x in confirmed if x.get("action_bucket", "app_code") != "dependency_risk"),
        "dependency_risk_count": sum(1 for x in confirmed if x.get("action_bucket", "app_code") == "dependency_risk"),
    }


def write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta):
    path = Path(output_dir) / scan_meta["queue_file"]
    payload = {
        "scan": scan_meta,
        "roslyn": roslyn_meta,
        "summary": {
            "total_findings": len(findings),
            "reviewed_count": sum(1 for f in findings if status_by_key.get(f["finding_key"]) == "reviewed"),
            "pending_count": sum(1 for f in findings if status_by_key.get(f["finding_key"]) != "reviewed"),
        },
        "status_by_key": status_by_key,
        "reviewed": reviewed,
        "findings": findings,
        "items": [
            {
                "finding_key": f.get("finding_key"),
                "status": status_by_key.get(f.get("finding_key"), "pending"),
                "source": f.get("source", "unknown"),
                "rule_id": f.get("rule_id", "unknown"),
                "file": f.get("file", "unknown"),
                "line": f.get("line", 1),
            }
            for f in findings
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_queue_report(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Queue file not found: {path}")
    payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    findings = payload.get("findings", [])
    reviewed = payload.get("reviewed", [])
    status_by_key = payload.get("status_by_key", {})

    if not isinstance(findings, list):
        raise ValueError("Invalid queue file: findings must be a list")
    if not isinstance(reviewed, list):
        raise ValueError("Invalid queue file: reviewed must be a list")
    if not isinstance(status_by_key, dict):
        status_by_key = {}

    if not status_by_key:
        status_by_key = {f.get("finding_key"): "pending" for f in findings if f.get("finding_key")}
        for item in reviewed:
            fk = item.get("finding_key")
            if fk:
                status_by_key[fk] = "reviewed"

    return {
        "scan_meta": payload.get("scan", {}),
        "roslyn_meta": payload.get("roslyn", {}),
        "findings": findings,
        "reviewed": reviewed,
        "status_by_key": status_by_key,
        "queue_path": str(p.resolve()),
    }


def write_json_report(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=None):
    output_path = Path(output_dir) / scan_meta["findings_file"]
    payload = {
        "summary": {
            "total_reviewed": len(summary_data["all_reviewed"]),
            "confirmed_issues": len(summary_data["confirmed"]),
            "fallback_findings": len(summary_data.get("fallback_findings", [])),
            "by_severity": summary_data["by_severity"],
            "by_category": summary_data["by_category"],
            "by_module": summary_data["by_module"],
            "by_source": summary_data["by_source"],
            "by_trust_tier": summary_data.get("by_trust_tier", {}),
            "by_action_bucket": summary_data.get("by_action_bucket", {}),
            "by_language": summary_data["by_language"],
            "by_file_type": summary_data["by_file_type"],
            "throughput": summary_data.get("throughput", {}),
            "rule_quality": summary_data.get("rule_quality", {}),
            "patch_metrics": summary_data.get("patch_metrics", {}),
            "ai_policy_metrics": summary_data.get("ai_policy_metrics", {}),
            "rule_precision_trend": summary_data.get("rule_precision_trend", {}),
            "rule_pipeline_stats": summary_data.get("rule_pipeline_stats", {}),
            "rule_noise_recommendations": summary_data.get("rule_noise_recommendations", []),
            "app_fix_backlog_count": summary_data.get("app_fix_backlog_count", 0),
            "dependency_risk_count": summary_data.get("dependency_risk_count", 0),
        },
        "scan": scan_meta,
        "roslyn": roslyn_meta,
        "findings": summary_data["all_reviewed"],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Compatibility pointer for existing tools/UI
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def write_fallback_report(summary_data, output_dir, scan_meta, pointers_dir=None):
    path = Path(output_dir) / scan_meta["fallback_file"]
    payload = {
        "summary": {
            "total_reviewed": len(summary_data.get("all_reviewed", [])),
            "fallback_findings": len(summary_data.get("fallback_findings", [])),
        },
        "scan": scan_meta,
        "fallback_findings": summary_data.get("fallback_findings", []),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "fallback_findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_safe_ai_risk_report(findings, output_dir, scan_meta, provider_name, base_url, pointers_dir=None):
    external_boundary = _is_external_llm_boundary(provider_name, base_url)
    items = []
    counts = Counter()
    for f in findings or []:
        risk = _ai_policy_risk_for_finding(f)
        counts[risk] += 1
        items.append(
            {
                "finding_key": f.get("finding_key"),
                "rule_id": f.get("rule_id"),
                "source": f.get("source", "unknown"),
                "file": f.get("file", "unknown"),
                "line": f.get("line", 1),
                "risk": risk,
                "top_level_category": f.get("top_level_category", "unknown"),
                "sub_category": f.get("sub_category", "unknown"),
                "match_text": str(f.get("match_text", ""))[:500],
            }
        )
    payload = {
        "scan": scan_meta,
        "provider": _provider_label(provider_name),
        "external_boundary": bool(external_boundary),
        "summary": {
            "total_findings": len(items),
            "high": int(counts.get("high", 0)),
            "medium": int(counts.get("medium", 0)),
            "low": int(counts.get("low", 0)),
        },
        "findings": items,
    }
    project = scan_meta.get("project", "project")
    run_version = scan_meta.get("run_version", datetime.now().strftime("%Y%m%d_%H%M%S"))
    out = Path(output_dir) / f"safe_ai_risk__{project}__{run_version}.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "safe_ai_risk.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def write_safe_ai_risk_markdown(risk_payload, output_dir, scan_meta, pointers_dir=None):
    summary = (risk_payload or {}).get("summary", {}) or {}
    findings = (risk_payload or {}).get("findings", []) or []
    provider = (risk_payload or {}).get("provider", "unknown")
    external = bool((risk_payload or {}).get("external_boundary", False))
    project = scan_meta.get("project", "project")
    run_version = scan_meta.get("run_version", datetime.now().strftime("%Y%m%d_%H%M%S"))
    path = Path(output_dir) / f"safe_ai_risk_digest__{project}__{run_version}.md"

    lines = []
    lines.append("# Safe AI Risk Digest")
    lines.append("")
    lines.append(f"- Provider: {provider}")
    lines.append(f"- External boundary: {external}")
    lines.append(f"- Total findings: {int(summary.get('total_findings', len(findings)))}")
    lines.append(f"- High: {int(summary.get('high', 0))}")
    lines.append(f"- Medium: {int(summary.get('medium', 0))}")
    lines.append(f"- Low: {int(summary.get('low', 0))}")
    lines.append("")

    lines.append("## High-Risk Items (Top 100)")
    lines.append("")
    high = [f for f in findings if str(f.get("risk", "")).lower() == "high"]
    if not high:
        lines.append("- None")
    else:
        for item in high[:100]:
            lines.append(
                f"- `{item.get('rule_id', 'unknown')}` at "
                f"`{item.get('file', 'unknown')}:{item.get('line', 1)}` "
                f"category=`{item.get('top_level_category', 'unknown')}/{item.get('sub_category', 'unknown')}`"
            )
    lines.append("")

    lines.append("## Guidance")
    lines.append("")
    lines.append("- High: local model only or manual review; block external providers.")
    lines.append("- Medium: redact before external provider usage.")
    lines.append("- Low: allowed under policy and standard review.")
    lines.append("")

    content = "\n".join(lines)
    path.write_text(content, encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "safe_ai_risk_digest.md").write_text(content, encoding="utf-8")
    return path


def write_safe_ai_risk_sarif(risk_payload, output_dir, scan_meta, pointers_dir=None):
    findings = (risk_payload or {}).get("findings", []) or []
    provider = (risk_payload or {}).get("provider", "unknown")
    external = bool((risk_payload or {}).get("external_boundary", False))

    rules = [
        {
            "id": "SAFE-AI-RISK",
            "name": "Safe AI Risk Classification",
            "shortDescription": {"text": "Snippet risk level for external AI boundary"},
            "fullDescription": {
                "text": "Classifies findings as high/medium/low for safe external AI usage."
            },
        }
    ]

    level_map = {"high": "error", "medium": "warning", "low": "note"}
    results = []
    for item in findings:
        risk = str(item.get("risk", "low")).lower()
        msg = (
            f"Safe AI risk={risk}; provider={provider}; external_boundary={external}; "
            f"rule_id={item.get('rule_id', 'unknown')}"
        )
        results.append(
            {
                "ruleId": "SAFE-AI-RISK",
                "level": level_map.get(risk, "note"),
                "message": {"text": msg},
                "properties": {
                    "safe_ai_risk": risk,
                    "nfr_source": item.get("source", "unknown"),
                    "top_level_category": item.get("top_level_category", "unknown"),
                    "sub_category": item.get("sub_category", "unknown"),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.get("file", "unknown")},
                            "region": {"startLine": int(item.get("line", 1) or 1)},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "nfr_audit_safe_ai", "rules": rules}},
                "results": results,
            }
        ],
    }

    project = scan_meta.get("project", "project")
    run_version = scan_meta.get("run_version", datetime.now().strftime("%Y%m%d_%H%M%S"))
    path = Path(output_dir) / f"safe_ai_risk__{project}__{run_version}.sarif"
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "safe_ai_risk.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def write_markdown(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=None):
    path = Path(output_dir) / scan_meta["digest_file"]
    confirmed = summary_data["confirmed"]

    lines = []
    lines.append("# NFR Risk Digest")
    lines.append("")
    lines.append(f"- Reviewed findings: {len(summary_data['all_reviewed'])}")
    lines.append(f"- Confirmed issues: {len(confirmed)}")
    lines.append(f"- Fallback-LLM findings: {len(summary_data.get('fallback_findings', []))}")
    lines.append(f"- Severity split: {summary_data['by_severity']}")
    lines.append(f"- Source split: {summary_data['by_source']}")
    lines.append(f"- Trust-tier split: {summary_data.get('by_trust_tier', {})}")
    lines.append(f"- Action bucket split: {summary_data.get('by_action_bucket', {})}")
    lines.append(f"- App-fix backlog count: {summary_data.get('app_fix_backlog_count', 0)}")
    lines.append(f"- Dependency-risk count: {summary_data.get('dependency_risk_count', 0)}")
    lines.append(f"- Patch metrics: {summary_data.get('patch_metrics', {})}")
    lines.append(f"- Safe AI policy metrics: {summary_data.get('ai_policy_metrics', {})}")
    if summary_data.get("throughput"):
        lines.append(f"- Throughput: {summary_data.get('throughput')}")
    lines.append("")

    lines.append("## Roslyn")
    lines.append("")
    lines.append(f"- Enabled: {roslyn_meta.get('enabled', False)}")
    lines.append(f"- Executed: {roslyn_meta.get('executed', False)}")
    lines.append(f"- Findings imported: {roslyn_meta.get('imported_findings', 0)}")
    if roslyn_meta.get("note"):
        lines.append(f"- Note: {roslyn_meta.get('note')}")
    lines.append("")

    lines.append("## Executive Summary (Top 5)")
    lines.append("")
    top = confirmed[:5]
    if not top:
        lines.append("No confirmed issues.")
    for idx, item in enumerate(top, start=1):
        review = item["llm_review"]
        lines.append(
            f"{idx}. [{review.get('severity', item['default_severity'])}] {review.get('title', item['rule_title'])} - `{item['file']}:{item['line']}`"
        )
        lines.append(f"   Source: {item.get('source', 'unknown')}")
        lines.append(f"   Impact: {review.get('why', 'N/A')}")
        lines.append(f"   Fix: {review.get('recommendation', 'N/A')}")
    lines.append("")

    lines.append("## By Category")
    lines.append("")
    if summary_data["by_category"]:
        for k, v in sorted(summary_data["by_category"].items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## By Module")
    lines.append("")
    if summary_data["by_module"]:
        for k, v in sorted(summary_data["by_module"].items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Rule Quality Scoreboard")
    lines.append("")
    quality = summary_data.get("rule_quality", {})
    if quality:
        for rid, stats in sorted(quality.items(), key=lambda kv: (-int(kv[1].get("reviewed", 0)), kv[0]))[:20]:
            lines.append(
                f"- {rid}: reviewed={stats.get('reviewed', 0)}, confirmed={stats.get('confirmed', 0)}, "
                f"precision={stats.get('precision', 0.0)}, fallback_rate={stats.get('fallback_rate', 0.0)}, "
                f"timeout_like_rate={stats.get('timeout_like_rate', 0.0)}"
            )
            top_fp = stats.get("top_false_positive_reasons", []) or []
            if top_fp:
                reason = top_fp[0].get("reason", "unspecified")
                count = top_fp[0].get("count", 0)
                lines.append(f"  - top_fp_reason: {reason} ({count})")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Rule Precision Trend (Current Run vs Historical)")
    lines.append("")
    trend = summary_data.get("rule_precision_trend", {})
    if trend:
        for rid, item in sorted(trend.items(), key=lambda kv: (kv[1].get("trend", "stable"), -kv[1].get("current_run_reviewed", 0), kv[0]))[:25]:
            lines.append(
                f"- {rid}: trend={item.get('trend', 'stable')}, "
                f"prev={item.get('previous_precision', 0.0)}, "
                f"current={item.get('current_run_precision', 0.0)}, "
                f"delta={item.get('delta', 0.0)}, "
                f"reviewed={item.get('current_run_reviewed', 0)}"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Fallback Governance")
    lines.append("")

    lines.append("## Noise Recommendations")
    lines.append("")
    recs = summary_data.get("rule_noise_recommendations", [])
    if recs:
        for item in recs:
            lines.append(
                f"- {item.get('rule_id', 'unknown')}: action={item.get('recommended_action', 'monitor')}, "
                f"precision={item.get('precision', 0.0)}, fallback_rate={item.get('fallback_rate', 0.0)}, "
                f"reviewed={item.get('reviewed', 0)}"
            )
    else:
        lines.append("- None")
    lines.append("")
    fallback_items = summary_data.get("fallback_findings", [])
    if not fallback_items:
        lines.append("- No fallback findings.")
    else:
        lines.append(f"- Findings requiring fallback/manual attention: {len(fallback_items)}")
        for item in fallback_items[:20]:
            lines.append(
                f"- `{item.get('rule_id', 'unknown')}` at `{item.get('file', 'unknown')}:{item.get('line', 1)}` "
                f"error_kind=`{item.get('llm_error_kind', '')}`"
            )
    lines.append("")

    lines.append("## Action Plan")
    lines.append("")
    lines.append("### Quick Wins")
    lines.append("- Propagate `CancellationToken` to HttpClient/EF Core async calls.")
    lines.append("- Replace `.Result` / `.Wait()` and `Thread.Sleep()` in request paths.")
    lines.append("- Replace `new HttpClient()` call-site allocation with `IHttpClientFactory`.")
    lines.append("")
    lines.append("### Structural Fixes")
    lines.append("- Standardize timeout/retry/circuit-breaker policies per downstream.")
    lines.append("- Add analyzer gating in CI for cancellation-token propagation and async hygiene.")
    lines.append("- Correlate static findings with p95/p99 latency and timeout telemetry for prioritization.")
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    if not confirmed:
        lines.append("No confirmed issues.")
    for item in confirmed:
        review = item["llm_review"]
        lines.append(f"### {review.get('title', item['rule_title'])}")
        lines.append(f"- Source: `{item.get('source', 'unknown')}`")
        lines.append(f"- Rule: `{item['rule_id']}`")
        lines.append(f"- Severity: `{review.get('severity', item['default_severity'])}`")
        lines.append(f"- Confidence: `{review.get('confidence', 0.0)}`")
        lines.append(f"- Location: `{item['file']}:{item['line']}`")
        lines.append(f"- Why: {review.get('why', 'N/A')}")
        lines.append(f"- Recommendation: {review.get('recommendation', 'N/A')}")
        changed_reason = str(review.get("changed_lines_reason", "") or "").strip()
        if changed_reason:
            lines.append(f"- Patch Change Reason: {changed_reason}")
        notes = review.get("testing_notes", []) or []
        if notes:
            lines.append("- Testing Notes:")
            for n in notes[:5]:
                lines.append(f"  - {n}")
        patch = review.get("patch", "unknown")
        if isinstance(patch, str) and patch.strip() and patch.strip().lower() != "unknown":
            lines.append("- Suggested Patch:")
            lines.append("```diff")
            lines.append(patch.strip())
            lines.append("```")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "nfr_digest.md").write_text("\n".join(lines), encoding="utf-8")
    return path


def write_sarif(summary_data, output_dir, scan_meta, pointers_dir=None):
    rules = {}
    results = []

    for item in summary_data["confirmed"]:
        review = item.get("llm_review", {})
        rid = item["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": item.get("rule_title", rid),
                "shortDescription": {"text": item.get("rule_title", rid)},
                "fullDescription": {"text": item.get("rationale", "")},
            }

        severity = review.get("severity", item.get("default_severity", "S3"))
        severity = severity if severity in SEVERITY_LEVEL else "S3"

        results.append(
            {
                "ruleId": rid,
                "level": SEVERITY_LEVEL[severity],
                "message": {"text": review.get("why", item.get("match_text", "Potential NFR risk."))},
                "properties": {
                    "nfr_source": item.get("source", "unknown"),
                    "confidence": review.get("confidence", 0.0),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item["file"]},
                            "region": {
                                "startLine": item.get("line", 1),
                                "startColumn": item.get("column", 1),
                            },
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nfr_audit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    path = Path(output_dir) / scan_meta["sarif_file"]
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    pointer_root = Path(pointers_dir) if pointers_dir else Path(output_dir)
    pointer_root.mkdir(parents=True, exist_ok=True)
    (pointer_root / "nfr.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def evaluate_ci_policy(summary_data, args):
    mode = str(getattr(args, "ci_mode", "off") or "off").strip().lower()
    if mode in {"", "off", "none"}:
        return {"mode": "off", "breached": False, "messages": []}
    if mode not in {"warn", "soft-fail", "hard-fail"}:
        mode = "warn"

    passed_flags = set(getattr(args, "_passed_flags", set()) or set())
    allowed_tiers = _parse_csv_set(getattr(args, "ci_count_trust_tiers", ""))
    if mode == "hard-fail" and "ci_count_trust_tiers" not in passed_flags:
        # Safer default for hard-fail: only higher-trust tiers block builds.
        allowed_tiers = {"llm_confirmed", "fast_routed"}
    elif not allowed_tiers:
        allowed_tiers = {"llm_confirmed", "fast_routed", "fallback", "regex_only", "roslyn"}

    confirmed = summary_data.get("confirmed", [])
    scoped = [x for x in confirmed if str(x.get("trust_tier", "unknown")).lower() in allowed_tiers]
    if mode == "hard-fail":
        # In hard-fail mode, treat review-level findings as non-blocking by default.
        scoped = [x for x in scoped if str(x.get("enforcement_level", "hard_fail")).lower() == "hard_fail"]
    fallback_items = [x for x in confirmed if str(x.get("trust_tier", "unknown")).lower() == "fallback"]
    by_sev = Counter(str((x.get("llm_review", {}) or {}).get("severity", x.get("default_severity", "S3"))).upper() for x in scoped)

    thresholds = {
        "total": int(getattr(args, "ci_max_total", -1) or -1),
        "S1": int(getattr(args, "ci_threshold_s1", -1) or -1),
        "S2": int(getattr(args, "ci_threshold_s2", -1) or -1),
        "S3": int(getattr(args, "ci_threshold_s3", -1) or -1),
        "S4": int(getattr(args, "ci_threshold_s4", -1) or -1),
        "patch_generated_min": int(getattr(args, "ci_min_patch_generated", -1) or -1),
        "patch_no_op_max": int(getattr(args, "ci_max_patch_no_op", -1) or -1),
    }

    breaches = []
    if thresholds["total"] >= 0 and len(scoped) > thresholds["total"]:
        breaches.append(f"total={len(scoped)} > threshold={thresholds['total']}")
    for sev in ("S1", "S2", "S3", "S4"):
        threshold = thresholds[sev]
        value = int(by_sev.get(sev, 0))
        if threshold >= 0 and value > threshold:
            breaches.append(f"{sev}={value} > threshold={threshold}")
    patch_metrics = summary_data.get("patch_metrics", {}) or {}
    patch_generated = int(patch_metrics.get("generated", 0) or 0)
    patch_no_op = int(patch_metrics.get("no_op_dropped", 0) or 0)
    if thresholds["patch_generated_min"] >= 0 and patch_generated < thresholds["patch_generated_min"]:
        breaches.append(f"patch_generated={patch_generated} < min_required={thresholds['patch_generated_min']}")
    if thresholds["patch_no_op_max"] >= 0 and patch_no_op > thresholds["patch_no_op_max"]:
        breaches.append(f"patch_no_op={patch_no_op} > max_allowed={thresholds['patch_no_op_max']}")

    messages = []
    scope_desc = ",".join(sorted(allowed_tiers))
    messages.append(f"CI policy scope trust_tiers=[{scope_desc}] count={len(scoped)}")
    messages.append(f"Patch metrics: generated={patch_generated}, no_op={patch_no_op}")
    if mode == "hard-fail" and fallback_items:
        messages.append(
            f"Fallback findings present ({len(fallback_items)}); treated as warn-only in hard-fail mode."
        )
    if breaches:
        messages.append("CI policy breaches: " + "; ".join(breaches))
    else:
        messages.append("CI policy passed.")
    return {"mode": mode, "breached": bool(breaches), "messages": messages}


def run_safe_ai_only(scan_path, output_root_dir, args, llm_provider, base_url):
    project_name = _project_name_from_scan_path(scan_path)
    run_version = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = _resolve_artifact_output_dir(output_root_dir, project_name, run_version, args.output_layout)
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_meta = {
        "project": project_name,
        "run_version": run_version,
        "scan_path": str(scan_path),
        "output_layout": str(args.output_layout),
    }

    log_progress(f"Safe AI standalone scan started for path: {scan_path}")
    log_progress(f"Output directory: {output_dir.resolve()}")

    ignore_globs = load_ignore_globs(scan_path, args.ignore_file)
    if ignore_globs:
        log_progress(f"Loaded {len(ignore_globs)} ignore glob(s) from {args.ignore_file}")

    safe_rules = load_rules(args.safe_ai_rules)
    safe_rule_paths = _normalize_rule_paths(args.safe_ai_rules)
    log_progress(f"Loaded {len(safe_rules)} safe-ai regex rule(s) from {', '.join(safe_rule_paths)}")

    changed_lines_by_file = {}
    if args.diff_base:
        changed_lines_by_file = load_git_diff_filter(
            scan_path,
            args.diff_base,
            args.diff_head,
            files_only=bool(args.diff_files_only),
        )
        if changed_lines_by_file:
            changed_files = len(changed_lines_by_file)
            mode = "changed files" if args.diff_files_only else "changed lines"
            log_progress(
                f"Diff mode enabled ({mode}): base={args.diff_base}, head={args.diff_head}, files={changed_files}"
            )
        else:
            log_progress("Diff mode returned no changes or could not be applied; scanning full scope.")

    regex_started = time.perf_counter()
    safe_findings, _ = pre_scan(
        scan_path,
        safe_rules,
        args.context_lines,
        args.max_findings,
        ignore_globs,
        regex_workers=args.regex_workers,
        changed_lines_by_file=changed_lines_by_file,
    )
    regex_stage_seconds = time.perf_counter() - regex_started
    log_progress(f"Safe AI regex pre-scan produced {len(safe_findings)} finding(s)")
    log_progress(f"Safe AI regex stage timing: {regex_stage_seconds:.2f}s")

    risk_path = write_safe_ai_risk_report(
        safe_findings, output_dir, scan_meta, llm_provider, base_url, pointers_dir=output_root_dir
    )
    risk_payload = json.loads(risk_path.read_text(encoding="utf-8", errors="ignore"))
    risk_md_path = write_safe_ai_risk_markdown(risk_payload, output_dir, scan_meta, pointers_dir=output_root_dir)
    risk_sarif_path = write_safe_ai_risk_sarif(risk_payload, output_dir, scan_meta, pointers_dir=output_root_dir)

    risk_summary = (risk_payload.get("summary", {}) or {})
    log_progress(
        "Safe AI standalone summary: "
        f"total={risk_summary.get('total_findings', 0)}, "
        f"high={risk_summary.get('high', 0)}, "
        f"medium={risk_summary.get('medium', 0)}, "
        f"low={risk_summary.get('low', 0)}, "
        f"external_boundary={risk_payload.get('external_boundary', False)}"
    )

    print(
        "Safe AI standalone scan complete. "
        f"Total={risk_summary.get('total_findings', 0)} | "
        f"High={risk_summary.get('high', 0)} | "
        f"Medium={risk_summary.get('medium', 0)} | "
        f"Low={risk_summary.get('low', 0)}"
    )
    print(f"Reports written: {risk_path.name}, {risk_md_path.name}, {risk_sarif_path.name}")
    print(f"Run output directory: {output_dir}")
    print(f"Latest pointers updated in: {output_root_dir}")


def main():
    load_env()
    args = parse_args()
    run_started = time.perf_counter()
    regex_stage_seconds = 0.0
    roslyn_stage_seconds = 0.0
    llm_stage_seconds = 0.0

    runtime = _resolve_llm_runtime(args)
    llm_provider = runtime["provider"]
    model = runtime["model"]
    base_url = runtime["base_url"]
    llm_api_key = runtime["api_key"]

    scan_path = Path(args.path).resolve()
    output_root_dir = Path(args.output_dir)
    output_root_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_root_dir
    if bool(args.safe_ai_only):
        if args.resume_queue:
            raise ValueError("--safe-ai-only cannot be combined with --resume-queue")
        run_safe_ai_only(scan_path, output_root_dir, args, llm_provider, base_url)
        return
    changed_lines_by_file = {}
    pre_scan_rule_stats = {}
    roslyn_meta = {
        "enabled": bool(args.include_roslyn),
        "executed": False,
        "imported_findings": 0,
        "note": "",
        "sarif_path": "",
    }

    if args.resume_queue:
        loaded = load_queue_report(args.resume_queue)
        scan_meta = loaded["scan_meta"]
        if not scan_meta:
            raise ValueError("Invalid queue file: missing scan metadata")
        if not scan_meta.get("fallback_file"):
            project_name = scan_meta.get("project", _project_name_from_scan_path(scan_path))
            run_version = scan_meta.get("run_version", datetime.now().strftime("%Y%m%d_%H%M%S"))
            scan_meta["fallback_file"] = f"fallback_findings__{project_name}__{run_version}.json"
        queue_file_path = Path(loaded["queue_path"])
        output_dir = queue_file_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        scan_meta["output_layout"] = scan_meta.get("output_layout", "flat")
        scan_path = Path(scan_meta.get("scan_path", str(scan_path))).resolve()
        findings = loaded["findings"]
        reviewed = loaded["reviewed"]
        status_by_key = loaded["status_by_key"]
        if loaded.get("roslyn_meta"):
            roslyn_meta = loaded["roslyn_meta"]
        log_progress(f"Resuming run from queue: {queue_file_path.name}")
        log_progress(f"Output directory: {output_dir.resolve()}")
        log_progress(
            f"Loaded queue state: total={len(findings)}, reviewed={len(reviewed)}, "
            f"pending={sum(1 for f in findings if status_by_key.get(f.get('finding_key')) != 'reviewed')}"
        )
    else:
        project_name = _project_name_from_scan_path(scan_path)
        run_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"findings__{project_name}__{run_version}"
        scan_meta = {
            "project": project_name,
            "run_version": run_version,
            "scan_path": str(scan_path),
            "output_layout": str(args.output_layout),
            "findings_file": f"{base_name}.json",
            "queue_file": f"findings_queue__{project_name}__{run_version}.json",
            "digest_file": f"nfr_digest__{project_name}__{run_version}.md",
            "sarif_file": f"nfr__{project_name}__{run_version}.sarif",
            "fallback_file": f"fallback_findings__{project_name}__{run_version}.json",
        }
        output_dir = _resolve_artifact_output_dir(output_root_dir, project_name, run_version, args.output_layout)
        output_dir.mkdir(parents=True, exist_ok=True)
        log_progress(f"NFR Audit Workbench scan started for path: {scan_path}")
        log_progress(f"Output directory: {output_dir.resolve()}")
        ignore_globs = load_ignore_globs(scan_path, args.ignore_file)
        if ignore_globs:
            log_progress(f"Loaded {len(ignore_globs)} ignore glob(s) from {args.ignore_file}")

        rules = load_rules(args.rules)
        rule_paths = _normalize_rule_paths(args.rules)
        log_progress(f"Loaded {len(rules)} regex rule(s) from {', '.join(rule_paths)}")
        if args.diff_base:
            changed_lines_by_file = load_git_diff_filter(
                scan_path,
                args.diff_base,
                args.diff_head,
                files_only=bool(args.diff_files_only),
            )
            if changed_lines_by_file:
                changed_files = len(changed_lines_by_file)
                mode = "changed files" if args.diff_files_only else "changed lines"
                log_progress(
                    f"Diff mode enabled ({mode}): base={args.diff_base}, head={args.diff_head}, files={changed_files}"
                )
            else:
                log_progress("Diff mode returned no changes or could not be applied; scanning full scope.")
        regex_started = time.perf_counter()
        regex_findings, pre_scan_rule_stats = pre_scan(
            scan_path,
            rules,
            args.context_lines,
            args.max_findings,
            ignore_globs,
            regex_workers=args.regex_workers,
            changed_lines_by_file=changed_lines_by_file,
        )
        regex_findings = apply_contextual_overrides(regex_findings, args=args)
        regex_stage_seconds = time.perf_counter() - regex_started
        log_progress(f"Regex pre-scan produced {len(regex_findings)} finding(s)")
        log_progress(f"Regex stage timing: {regex_stage_seconds:.2f}s")

        roslyn_findings = []
        if args.include_roslyn:
            log_progress("Roslyn scan enabled. Running dotnet analyzer build...")
            roslyn_started = time.perf_counter()
            sarif_path, roslyn_error = _run_roslyn_sarif(
                scan_path,
                output_dir,
                args.dotnet_target,
                args.dotnet_configuration,
                args.dotnet_timeout_seconds,
            )
            if sarif_path:
                roslyn_findings = _parse_roslyn_findings(
                    sarif_path,
                    scan_path,
                    args.context_lines,
                    ignore_globs,
                    changed_lines_by_file=changed_lines_by_file,
                )
                roslyn_meta["executed"] = True
                roslyn_meta["imported_findings"] = len(roslyn_findings)
                roslyn_meta["sarif_path"] = str(sarif_path)
                log_progress(f"Roslyn findings imported: {len(roslyn_findings)}")
            else:
                roslyn_meta["note"] = roslyn_error
                log_progress(f"Roslyn scan note: {roslyn_error}")
            roslyn_stage_seconds = time.perf_counter() - roslyn_started
            log_progress(f"Roslyn stage timing: {roslyn_stage_seconds:.2f}s")

        findings_all = regex_findings + roslyn_findings
        log_progress(f"Combined findings before baseline filter: {len(findings_all)}")

        use_incremental = bool(args.incremental or args.only_new)
        baseline_path = None
        if use_incremental:
            if args.baseline:
                baseline_path = Path(args.baseline)
            else:
                baseline_path = baseline_path_for_project(output_root_dir, args.baseline_dir, project_name)
            baseline_keys = load_baseline_keys(str(baseline_path))
            findings = [f for f in findings_all if f["finding_key"] not in baseline_keys]
            log_progress(
                f"Incremental mode: baseline keys={len(baseline_keys)} | "
                f"new/changed findings={len(findings)}"
            )
        else:
            findings = findings_all
            log_progress("Full scan mode enabled (incremental disabled).")

        if baseline_path is None:
            baseline_path = baseline_path_for_project(output_root_dir, args.baseline_dir, project_name)
        written_baseline = write_baseline_file(baseline_path, findings_all, scan_meta)
        log_progress(f"Baseline updated: {written_baseline}")

        reviewed = []
        status_by_key = {f["finding_key"]: "pending" for f in findings}
        queue_path = write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
        log_progress(f"Queue file written: {queue_path.name}")

    reviewed_by_key = {
        item.get("finding_key"): item
        for item in reviewed
        if isinstance(item, dict) and item.get("finding_key")
    }
    for fk in reviewed_by_key:
        status_by_key[fk] = "reviewed"
    reviewed = list(reviewed_by_key.values())

    cache_path = _resolve_cache_path(args.llm_cache_file, output_root_dir)
    llm_cache = load_llm_cache(cache_path) if args.use_llm_cache else {}
    if args.use_llm_cache:
        log_progress(f"Loaded LLM cache entries: {len(llm_cache)} from {cache_path}")
    patch_template_cache_path = _resolve_patch_template_cache_path(args.patch_template_cache_file, output_root_dir)
    patch_template_cache = load_patch_template_cache(patch_template_cache_path) if args.use_patch_template_cache else {}
    if args.use_patch_template_cache:
        log_progress(f"Loaded patch template cache entries: {len(patch_template_cache)} from {patch_template_cache_path}")

    pending_findings = [f for f in findings if status_by_key.get(f.get("finding_key")) != "reviewed"]
    if args.safe_ai_dry_run:
        risk_path = write_safe_ai_risk_report(
            pending_findings, output_dir, scan_meta, llm_provider, base_url, pointers_dir=output_root_dir
        )
        risk_payload = json.loads(risk_path.read_text(encoding="utf-8", errors="ignore"))
        risk_md_path = write_safe_ai_risk_markdown(risk_payload, output_dir, scan_meta, pointers_dir=output_root_dir)
        risk_sarif_path = write_safe_ai_risk_sarif(risk_payload, output_dir, scan_meta, pointers_dir=output_root_dir)
        risk_summary = (risk_payload.get("summary", {}) or {})
        log_progress(
            "Safe AI dry-run summary: "
            f"total={risk_summary.get('total_findings', 0)}, "
            f"high={risk_summary.get('high', 0)}, "
            f"medium={risk_summary.get('medium', 0)}, "
            f"low={risk_summary.get('low', 0)}, "
            f"external_boundary={risk_payload.get('external_boundary', False)}"
        )
        log_progress(
            f"Safe AI reports written: {risk_path.name}, {risk_md_path.name}, {risk_sarif_path.name}"
        )
        args.max_llm = 0
    quality_path = _resolve_quality_path(args.rule_quality_file, output_root_dir)
    quality_history = load_rule_quality(quality_path)
    noisy_rules = set()
    if args.auto_demote_noisy_rules:
        noisy_rules = derive_noisy_rules(
            quality_history,
            min_reviewed=args.noisy_rule_min_reviewed,
            max_precision=args.noisy_rule_max_precision,
            max_fallback_rate=args.noisy_rule_max_fallback_rate,
        )
        if noisy_rules:
            for f in pending_findings:
                if str(f.get("rule_id", "")) in noisy_rules:
                    f["priority_demoted"] = True
            log_progress(f"Auto-demoted noisy rules in queue ordering: {len(noisy_rules)} rule(s).")
    if args.prioritize_llm_queue:
        pending_findings = sorted(pending_findings, key=_priority_sort_key)

    if args.dedup_before_llm:
        clusters = build_llm_clusters(pending_findings)
    else:
        clusters = [
            {"cluster_id": f"cluster_{idx + 1}", "representative": f, "members": [f], "order": idx}
            for idx, f in enumerate(pending_findings)
        ]

    rep_queue = []
    cluster_by_rep_key = {}
    for c in clusters:
        rep = dict(c["representative"])
        rep["_cluster_id"] = c["cluster_id"]
        rep["_llm_cache_key"] = _llm_cache_key(rep)
        rep_queue.append(rep)
        cluster_by_rep_key[rep["finding_key"]] = c

    if args.dedup_before_llm:
        member_total = sum(len(c.get("members", [])) for c in clusters)
        log_progress(
            f"Dedup before LLM: {member_total} pending finding(s) collapsed to "
            f"{len(rep_queue)} representative finding(s)."
        )

    pipeline_stats = build_rule_pipeline_stats(pre_scan_rule_stats, pending_findings, rep_queue, [])

    cache_hits = 0
    fast_routed_hits = 0
    reps_to_review = []
    for rep in rep_queue:
        ck = rep.get("_llm_cache_key")
        if args.use_llm_cache and ck in llm_cache:
            cached = llm_cache.get(ck, {})
            cached_review = dict(rep)
            cached_review["llm_review"] = dict(cached.get("llm_review", {}))
            cached_review["llm_transport"] = {
                "attempts": 0,
                "attempts_allowed": 0,
                "fallback_used": False,
                "error_kind": "",
                "from_cache": True,
                "recovered_after_retry": False,
            }
            cached_review["llm_error_kind"] = ""
            cached_review["llm_attempts"] = 0
            cached_review["llm_retried"] = False
            if args.use_patch_template_cache:
                cached_review, _ = _apply_patch_template_if_available(
                    cached_review,
                    patch_template_cache,
                    patch_strict_locality=bool(args.patch_strict_locality),
                    patch_locality_window=int(args.patch_locality_window),
                )
            expanded = expand_cluster_review(cached_review, cluster_by_rep_key[rep["finding_key"]])
            for item in expanded:
                reviewed_by_key[item["finding_key"]] = item
                status_by_key[item["finding_key"]] = "reviewed"
            cache_hits += 1
        elif (
            args.fast_high_confidence_routing
            and rep.get("source") == "regex"
            and _coerce_float(rep.get("confidence_hint") or _source_confidence_hint(rep), 0.0)
            >= _coerce_float(args.high_confidence_threshold, 0.9)
            and _severity_at_or_above(rep.get("default_severity", "S3"), args.high_confidence_max_severity)
        ):
            routed = build_fast_routed_review(rep)
            expanded = expand_cluster_review(routed, cluster_by_rep_key[rep["finding_key"]])
            for item in expanded:
                reviewed_by_key[item["finding_key"]] = item
                status_by_key[item["finding_key"]] = "reviewed"
            fast_routed_hits += 1
        else:
            reps_to_review.append(rep)

    pipeline_stats = build_rule_pipeline_stats(pre_scan_rule_stats, pending_findings, rep_queue, reps_to_review)
    log_rule_pipeline_stats(pipeline_stats)

    if cache_hits:
        covered = sum(
            len(cluster_by_rep_key[rep["finding_key"]]["members"])
            for rep in rep_queue
            if rep.get("_llm_cache_key") in llm_cache
        )
        log_progress(f"LLM cache hits: {cache_hits} representative item(s), covering {covered} finding(s).")
    if fast_routed_hits:
        log_progress(f"Fast-routed high-confidence representative items: {fast_routed_hits}.")

    reviewed = list(reviewed_by_key.values())
    write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
    if args.use_llm_cache:
        save_llm_cache(cache_path, llm_cache)
    if args.use_patch_template_cache:
        save_patch_template_cache(patch_template_cache_path, patch_template_cache)

    batch_size = int(args.max_llm)
    total_for_llm = len(reps_to_review)

    if batch_size <= 0:
        log_progress("Skipping LLM review because --max-llm is 0.")
        regex_only_added = 0
        for item in pending_findings:
            fk = item.get("finding_key")
            if not fk or fk in reviewed_by_key:
                continue
            regex_only_item = dict(item)
            regex_only_item["llm_review"] = {
                "isIssue": False,
                "severity": regex_only_item.get("default_severity", "S3"),
                "confidence": float(regex_only_item.get("confidence_hint") or _source_confidence_hint(regex_only_item)),
                "why": "LLM review skipped (--max-llm=0). Regex/Roslyn finding retained for triage.",
                "recommendation": "Review required.",
                "patch": "unknown",
            }
            regex_only_item["llm_transport"] = {
                "attempts": 0,
                "attempts_allowed": 0,
                "fallback_used": False,
                "error_kind": "skipped",
                "from_cache": False,
                "recovered_after_retry": False,
                "llm_skipped": True,
            }
            regex_only_item["llm_error_kind"] = "skipped"
            regex_only_item["llm_attempts"] = 0
            regex_only_item["llm_retried"] = False
            regex_only_item["review_status"] = "regex_only"
            reviewed_by_key[fk] = regex_only_item
            status_by_key[fk] = "reviewed"
            regex_only_added += 1
        log_progress(f"LLM skipped mode: retained {regex_only_added} regex/roslyn finding(s) in final findings output.")
    elif total_for_llm == 0:
        log_progress("No pending representative findings available for LLM review.")
    else:
        if _provider_requires_key(llm_provider) and not llm_api_key:
            label = _provider_label(llm_provider)
            raise ValueError(f"{label} provider selected but API key is not set in CLI/env.")
        start = 0
        batch_no = 1
        max_workers = max(1, int(args.llm_workers))
        current_workers = max_workers
        stable_batches = 0
        while start < total_for_llm:
            end = min(start + batch_size, total_for_llm)
            current_batch = reps_to_review[start:end]
            covered_count = sum(len(cluster_by_rep_key[rep["finding_key"]]["members"]) for rep in current_batch)
            log_progress(
                f"Sending batch {batch_no}: {len(current_batch)} representative finding(s) "
                f"covering {covered_count} finding(s) to {llm_provider} ({start + 1}-{end} of {total_for_llm})"
            )
            llm_batch_started = time.perf_counter()
            batch_reviewed = review_with_llm(
                current_batch,
                llm_provider,
                model,
                base_url,
                llm_api_key,
                args.temperature,
                workers=current_workers,
                retries=args.llm_retries,
                retry_backoff_seconds=args.llm_retry_backoff_seconds,
                connect_timeout_seconds=args.llm_connect_timeout_seconds,
                read_timeout_seconds=args.llm_read_timeout_seconds,
                prefer_patch_s1s2=bool(args.prefer_patch_s1s2),
                prefer_patch_all_severities=bool(args.prefer_patch_all_severities),
                patch_min_confidence=float(args.patch_min_confidence),
                patch_repair_retries=int(args.patch_repair_retries),
                patch_strict_locality=bool(args.patch_strict_locality),
                patch_locality_window=int(args.patch_locality_window),
                patch_verify_pass=bool(args.patch_verify_pass),
                safe_ai_policy_mode=str(args.safe_ai_policy_mode),
                safe_ai_allow_external_high_risk=bool(args.safe_ai_allow_external_high_risk),
                safe_ai_redact_medium=bool(args.safe_ai_redact_medium),
            )
            llm_batch_seconds = time.perf_counter() - llm_batch_started
            llm_stage_seconds += llm_batch_seconds
            batch_lat = _latency_stats_from_reviewed(batch_reviewed)
            log_progress(
                f"LLM batch timing: {llm_batch_seconds:.2f}s | latency_ms avg/p50/p95="
                f"{batch_lat['avg_ms']}/{batch_lat['p50_ms']}/{batch_lat['p95_ms']} "
                f"(count={batch_lat['count']})"
            )

            for rep_result in batch_reviewed:
                if args.use_patch_template_cache:
                    rep_result, template_applied = _apply_patch_template_if_available(
                        rep_result,
                        patch_template_cache,
                        patch_strict_locality=bool(args.patch_strict_locality),
                        patch_locality_window=int(args.patch_locality_window),
                    )
                    if template_applied:
                        log_progress(
                            f"Patch template cache applied for {rep_result.get('rule_id','unknown')} "
                            f"at {rep_result.get('file','unknown')}:{rep_result.get('line',1)}."
                        )
                cluster = cluster_by_rep_key.get(rep_result["finding_key"])
                if not cluster:
                    cluster = {
                        "cluster_id": rep_result.get("_cluster_id", "cluster_unknown"),
                        "representative": rep_result,
                        "members": [rep_result],
                    }
                expanded = expand_cluster_review(rep_result, cluster)
                for item in expanded:
                    reviewed_by_key[item["finding_key"]] = item
                    status_by_key[item["finding_key"]] = "reviewed"

                if args.use_llm_cache and not rep_result.get("llm_transport", {}).get("fallback_used"):
                    ck = rep_result.get("_llm_cache_key") or _llm_cache_key(rep_result)
                    llm_cache[ck] = {
                        "llm_review": rep_result.get("llm_review", {}),
                        "updated_at": datetime.now().isoformat(timespec="seconds"),
                    }
                if args.use_patch_template_cache:
                    review_patch = str((rep_result.get("llm_review", {}) or {}).get("patch", "unknown") or "unknown")
                    if review_patch.strip().lower() != "unknown":
                        ptk = _patch_template_key(rep_result)
                        patch_template_cache[ptk] = {
                            "rule_id": rep_result.get("rule_id", "unknown"),
                            "patch": review_patch,
                            "updated_at": datetime.now().isoformat(timespec="seconds"),
                        }

            reviewed = list(reviewed_by_key.values())
            write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
            if args.use_llm_cache:
                save_llm_cache(cache_path, llm_cache)
            if args.use_patch_template_cache:
                save_patch_template_cache(patch_template_cache_path, patch_template_cache)

            summary_data = summarize(reviewed)
            json_path = write_json_report(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=output_root_dir)
            md_path = write_markdown(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=output_root_dir)
            sarif_path = write_sarif(summary_data, output_dir, scan_meta, pointers_dir=output_root_dir)
            fallback_path = write_fallback_report(summary_data, output_dir, scan_meta, pointers_dir=output_root_dir)
            log_progress(
                f"Merged outputs updated after batch {batch_no}: "
                f"{json_path.name}, {md_path.name}, {sarif_path.name}, {fallback_path.name}"
            )

            if args.adaptive_llm_workers:
                current_workers, stable_batches = adapt_llm_workers(
                    current_workers, max_workers, batch_reviewed, stable_batches
                )

            if end >= total_for_llm:
                break

            if args.auto_continue_batches:
                log_progress("Auto-continue enabled. Proceeding to next batch.")
                start = end
                batch_no += 1
                continue

            if not sys.stdin or not sys.stdin.isatty():
                log_progress("Non-interactive shell detected. Stopping before next batch.")
                break

            try:
                answer = input(
                    f"Processed {end}/{total_for_llm} representative items. Continue with next batch of up to {batch_size}? [y/N]: "
                ).strip().lower()
            except EOFError:
                log_progress("No interactive input available. Stopping before next batch.")
                break
            if answer not in {"y", "yes"}:
                log_progress("Stopped by user after current batch.")
                break

            start = end
            batch_no += 1

    reviewed = list(reviewed_by_key.values())

    summary_data = summarize(reviewed)
    total_seconds = time.perf_counter() - run_started
    llm_lat = _latency_stats_from_reviewed(reviewed)
    summary_data["throughput"] = {
        "stage_seconds": {
            "regex": round(regex_stage_seconds, 2),
            "roslyn": round(roslyn_stage_seconds, 2),
            "llm": round(llm_stage_seconds, 2),
            "total": round(total_seconds, 2),
        },
        "llm_latency_ms": llm_lat,
    }
    summary_data["rule_pipeline_stats"] = pipeline_stats
    current_quality = summary_data.get("rule_quality", {})
    summary_data["rule_precision_trend"] = build_rule_precision_trend(quality_history, current_quality)
    merged_quality = merge_rule_quality(quality_history, current_quality)
    save_rule_quality(quality_path, merged_quality)
    summary_data["rule_quality"] = merged_quality.get("rules", {})
    summary_data["rule_noise_recommendations"] = build_noise_recommendations(summary_data.get("rule_quality", {}))
    if summary_data["rule_noise_recommendations"]:
        log_progress("Top noisy rules and recommended actions:")
        for item in summary_data["rule_noise_recommendations"]:
            log_progress(
                f"  {item['rule_id']}: action={item['recommended_action']} "
                f"(precision={item['precision']}, fallback_rate={item['fallback_rate']}, reviewed={item['reviewed']})"
            )
    log_progress(
        f"Stage timings (s): regex={regex_stage_seconds:.2f}, roslyn={roslyn_stage_seconds:.2f}, "
        f"llm={llm_stage_seconds:.2f}, total={total_seconds:.2f}"
    )
    log_progress(
        f"LLM latency_ms summary: avg={llm_lat['avg_ms']}, p50={llm_lat['p50_ms']}, "
        f"p95={llm_lat['p95_ms']}, count={llm_lat['count']}"
    )
    json_path = write_json_report(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=output_root_dir)
    md_path = write_markdown(summary_data, output_dir, roslyn_meta, scan_meta, pointers_dir=output_root_dir)
    sarif_path = write_sarif(summary_data, output_dir, scan_meta, pointers_dir=output_root_dir)
    fallback_path = write_fallback_report(summary_data, output_dir, scan_meta, pointers_dir=output_root_dir)
    write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
    ci_policy = evaluate_ci_policy(summary_data, args)
    for msg in ci_policy.get("messages", []):
        log_progress(msg)

    print(f"NFR Audit Workbench scan complete. Reviewed: {len(reviewed)} | Confirmed: {len(summary_data['confirmed'])}")
    print(f"Source split (confirmed): {summary_data['by_source']}")
    print(f"Reports written: {json_path.name}, {md_path.name}, {sarif_path.name}, {fallback_path.name}")
    print(f"Run output directory: {output_dir}")
    print(f"Latest pointers updated in: {output_root_dir}")
    if ci_policy.get("breached"):
        mode = ci_policy.get("mode", "warn")
        if mode == "hard-fail":
            print("CI policy result: HARD-FAIL")
            sys.exit(2)
        if mode == "soft-fail":
            print("CI policy result: SOFT-FAIL (non-blocking)")
        else:
            print("CI policy result: WARN")
    else:
        if ci_policy.get("mode") != "off":
            print("CI policy result: PASS")


if __name__ == "__main__":
    main()
