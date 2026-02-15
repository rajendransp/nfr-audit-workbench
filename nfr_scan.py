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
    "Return valid JSON only. No markdown. No prose outside JSON."
)

USER_TEMPLATE = """
Evaluate this pre-scan finding. Confirm if this is a real non-functional risk.

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

Rule:
{rule_json}

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
    parser = argparse.ArgumentParser(description="NFR Audit Workbench scan + Ollama review")
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
        default=120,
        help="LLM batch size. Use 0 to skip Ollama review.",
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
        help="Concurrent Ollama requests per batch (1 keeps sequential behavior).",
    )
    parser.add_argument(
        "--llm-retries",
        type=int,
        default=2,
        help="Retries for retriable Ollama failures (timeout/connection/5xx/429).",
    )
    parser.add_argument(
        "--llm-retry-backoff-seconds",
        type=float,
        default=1.5,
        help="Base backoff seconds for Ollama retries (exponential: base, 2x, 4x...).",
    )
    parser.add_argument(
        "--llm-connect-timeout-seconds",
        type=float,
        default=20.0,
        help="Connect timeout for Ollama HTTP requests.",
    )
    parser.add_argument(
        "--llm-read-timeout-seconds",
        type=float,
        default=120.0,
        help="Read timeout for Ollama HTTP requests.",
    )
    parser.add_argument(
        "--llm-cache-file",
        default="llm_review_cache.json",
        help="LLM review cache file (relative to output dir unless absolute path).",
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
    if rule.get("ignore_comment_lines", False) and _is_comment_only_line(line_text):
        return True
    if rule.get("id") == "NFR-DOTNET-003" and not _is_blocking_dotnet_result_line(line_text):
        return True
    if rule.get("id") == "NFR-FE-014":
        # If a dependency array is present in the same effect call line, this is not the target case.
        if re.search(r"\buseEffect\s*\([^\n]*,\s*\[", str(line_text or "")):
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


def apply_contextual_overrides(findings):
    out = []
    for finding in findings:
        item = dict(finding)
        rid = str(item.get("rule_id", ""))
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
                    "rationale": rule.get("rationale", ""),
                    "file": m["file"],
                    "line": m["line"],
                    "column": m["column"],
                    "file_type": _file_type(m["file"]),
                    "language": _language_for_file(m["file"]),
                    "match_text": m["match_text"],
                    "snippet": snippet,
                    "confidence_hint": _coerce_float(rule.get("confidence_hint", 0.65), 0.65),
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
        return json.loads(candidate)
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


def _classify_ollama_error(exc):
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
    model,
    url,
    temperature,
    retries,
    retry_backoff_seconds,
    connect_timeout_seconds,
    read_timeout_seconds,
):
    started = time.perf_counter()
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
        file_path=finding["file"],
        line=finding["line"],
        snippet=_slim_snippet_for_prompt(finding),
    )

    body = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "options": {"temperature": temperature},
    }

    parsed = None
    last_error_kind = ""
    fallback_used = False
    attempts_used = 0
    attempts_total = max(0, int(retries)) + 1
    for attempt in range(1, attempts_total + 1):
        attempts_used = attempt
        try:
            resp = requests.post(
                url,
                json=body,
                timeout=(float(connect_timeout_seconds), float(read_timeout_seconds)),
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            parsed = _extract_json(content)
            if attempt > 1:
                log_progress(
                    f"Ollama request recovered after retry for {finding.get('rule_id', 'unknown')} "
                    f"at {finding.get('file', 'unknown')}:{finding.get('line', 1)} "
                    f"(attempt {attempt}/{attempts_total})."
                )
            break
        except Exception as exc:
            retriable, error_kind = _classify_ollama_error(exc)
            last_error_kind = error_kind
            context = (
                f"{finding.get('rule_id', 'unknown')} at "
                f"{finding.get('file', 'unknown')}:{finding.get('line', 1)}"
            )
            if retriable and attempt < attempts_total:
                delay = max(0.0, float(retry_backoff_seconds)) * (2 ** (attempt - 1))
                log_progress(
                    f"Ollama request failed ({error_kind}) for {context}. "
                    f"Attempt {attempt}/{attempts_total}. Retrying in {delay:.1f}s. Error: {exc}"
                )
                if delay > 0:
                    time.sleep(delay)
                continue

            log_progress(
                f"Ollama request failed ({error_kind}) for {context}. "
                f"Attempt {attempt}/{attempts_total}. "
                f"{'Non-retriable' if not retriable else 'Retries exhausted'}; using fallback review. Error: {exc}"
            )
            parsed = {
                "isIssue": True,
                "severity": finding["default_severity"],
                "confidence": 0.2,
                "title": f"LLM review failed for {finding['rule_id']}",
                "why": f"Could not validate finding using Ollama: {exc}",
                "recommendation": "Manual review required.",
                "testing_notes": ["Re-run scan after ensuring Ollama model is available."],
                "patch": "unknown",
            }
            fallback_used = True
            break

    sev = str(parsed.get("severity") or finding["default_severity"] or "S3").upper()
    if sev not in SEVERITY_ORDER:
        sev = "S3"
    parsed["severity"] = sev
    parsed["effort"] = _normalize_effort(parsed.get("effort"))
    parsed["benefit"] = _normalize_benefit(parsed.get("benefit"), sev)
    if "quick_win" not in parsed:
        parsed["quick_win"] = _infer_quick_win(sev, parsed["effort"], parsed["benefit"])
    else:
        parsed["quick_win"] = bool(parsed.get("quick_win"))
    parsed["patch_quality"] = _patch_quality(parsed.get("patch", "unknown"))
    if parsed["patch_quality"] == "no_op":
        parsed["patch"] = "unknown"
        notes = list(parsed.get("testing_notes", []) or [])
        notes.append("Suggested patch was a no-op; manual fix proposal required.")
        parsed["testing_notes"] = notes

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
    return finding_out


def review_with_ollama(
    findings,
    model,
    base_url,
    temperature,
    workers=1,
    retries=2,
    retry_backoff_seconds=1.5,
    connect_timeout_seconds=20.0,
    read_timeout_seconds=120.0,
):
    reviewed = []
    url = f"{base_url.rstrip('/')}/api/chat"
    total = len(findings)
    workers = max(1, int(workers or 1))
    log_progress(f"Starting Ollama review for {total} finding(s) with model '{model}' (workers={workers}).")

    if workers == 1 or total <= 1:
        for idx, finding in enumerate(findings, start=1):
            reviewed.append(
                _review_single_finding(
                    finding,
                    model,
                    url,
                    temperature,
                    retries,
                    retry_backoff_seconds,
                    connect_timeout_seconds,
                    read_timeout_seconds,
                )
            )
            if idx % 10 == 0 or idx == total:
                log_progress(f"Ollama review progress: {idx}/{total}")
        return reviewed

    ordered = [None] * total
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {
            executor.submit(
                _review_single_finding,
                finding,
                model,
                url,
                temperature,
                retries,
                retry_backoff_seconds,
                connect_timeout_seconds,
                read_timeout_seconds,
            ): idx
            for idx, finding in enumerate(findings)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            ordered[idx] = future.result()
            done += 1
            if done % 10 == 0 or done == total:
                log_progress(f"Ollama review progress: {done}/{total}")

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


def write_json_report(summary_data, output_dir, roslyn_meta, scan_meta):
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
    (Path(output_dir) / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def write_fallback_report(summary_data, output_dir, scan_meta):
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
    (Path(output_dir) / "fallback_findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_markdown(summary_data, output_dir, roslyn_meta, scan_meta):
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
    (Path(output_dir) / "nfr_digest.md").write_text("\n".join(lines), encoding="utf-8")
    return path


def write_sarif(summary_data, output_dir, scan_meta):
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
    (Path(output_dir) / "nfr.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
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
    fallback_items = [x for x in confirmed if str(x.get("trust_tier", "unknown")).lower() == "fallback"]
    by_sev = Counter(str((x.get("llm_review", {}) or {}).get("severity", x.get("default_severity", "S3"))).upper() for x in scoped)

    thresholds = {
        "total": int(getattr(args, "ci_max_total", -1) or -1),
        "S1": int(getattr(args, "ci_threshold_s1", -1) or -1),
        "S2": int(getattr(args, "ci_threshold_s2", -1) or -1),
        "S3": int(getattr(args, "ci_threshold_s3", -1) or -1),
        "S4": int(getattr(args, "ci_threshold_s4", -1) or -1),
    }

    breaches = []
    if thresholds["total"] >= 0 and len(scoped) > thresholds["total"]:
        breaches.append(f"total={len(scoped)} > threshold={thresholds['total']}")
    for sev in ("S1", "S2", "S3", "S4"):
        threshold = thresholds[sev]
        value = int(by_sev.get(sev, 0))
        if threshold >= 0 and value > threshold:
            breaches.append(f"{sev}={value} > threshold={threshold}")

    messages = []
    scope_desc = ",".join(sorted(allowed_tiers))
    messages.append(f"CI policy scope trust_tiers=[{scope_desc}] count={len(scoped)}")
    if mode == "hard-fail" and fallback_items:
        messages.append(
            f"Fallback findings present ({len(fallback_items)}); treated as warn-only in hard-fail mode."
        )
    if breaches:
        messages.append("CI policy breaches: " + "; ".join(breaches))
    else:
        messages.append("CI policy passed.")
    return {"mode": mode, "breached": bool(breaches), "messages": messages}


def main():
    load_env()
    args = parse_args()
    run_started = time.perf_counter()
    regex_stage_seconds = 0.0
    roslyn_stage_seconds = 0.0
    llm_stage_seconds = 0.0

    model = os.getenv("NFR_OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL") or "qwen3-coder:30b"
    base_url = os.getenv("NFR_OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"

    scan_path = Path(args.path).resolve()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
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
            "findings_file": f"{base_name}.json",
            "queue_file": f"findings_queue__{project_name}__{run_version}.json",
            "digest_file": f"nfr_digest__{project_name}__{run_version}.md",
            "sarif_file": f"nfr__{project_name}__{run_version}.sarif",
            "fallback_file": f"fallback_findings__{project_name}__{run_version}.json",
        }
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
        regex_findings = apply_contextual_overrides(regex_findings)
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
                baseline_path = baseline_path_for_project(output_dir, args.baseline_dir, project_name)
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
            baseline_path = baseline_path_for_project(output_dir, args.baseline_dir, project_name)
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

    cache_path = _resolve_cache_path(args.llm_cache_file, output_dir)
    llm_cache = load_llm_cache(cache_path) if args.use_llm_cache else {}
    if args.use_llm_cache:
        log_progress(f"Loaded LLM cache entries: {len(llm_cache)} from {cache_path}")

    pending_findings = [f for f in findings if status_by_key.get(f.get("finding_key")) != "reviewed"]
    quality_path = _resolve_quality_path(args.rule_quality_file, output_dir)
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

    batch_size = int(args.max_llm)
    total_for_llm = len(reps_to_review)

    if batch_size <= 0:
        log_progress("Skipping Ollama review because --max-llm is 0.")
    elif total_for_llm == 0:
        log_progress("No pending representative findings available for Ollama review.")
    else:
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
                f"covering {covered_count} finding(s) to Ollama ({start + 1}-{end} of {total_for_llm})"
            )
            llm_batch_started = time.perf_counter()
            batch_reviewed = review_with_ollama(
                current_batch,
                model,
                base_url,
                args.temperature,
                workers=current_workers,
                retries=args.llm_retries,
                retry_backoff_seconds=args.llm_retry_backoff_seconds,
                connect_timeout_seconds=args.llm_connect_timeout_seconds,
                read_timeout_seconds=args.llm_read_timeout_seconds,
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

            reviewed = list(reviewed_by_key.values())
            write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
            if args.use_llm_cache:
                save_llm_cache(cache_path, llm_cache)

            summary_data = summarize(reviewed)
            json_path = write_json_report(summary_data, output_dir, roslyn_meta, scan_meta)
            md_path = write_markdown(summary_data, output_dir, roslyn_meta, scan_meta)
            sarif_path = write_sarif(summary_data, output_dir, scan_meta)
            fallback_path = write_fallback_report(summary_data, output_dir, scan_meta)
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
    json_path = write_json_report(summary_data, output_dir, roslyn_meta, scan_meta)
    md_path = write_markdown(summary_data, output_dir, roslyn_meta, scan_meta)
    sarif_path = write_sarif(summary_data, output_dir, scan_meta)
    fallback_path = write_fallback_report(summary_data, output_dir, scan_meta)
    write_queue_report(findings, status_by_key, reviewed, output_dir, scan_meta, roslyn_meta)
    ci_policy = evaluate_ci_policy(summary_data, args)
    for msg in ci_policy.get("messages", []):
        log_progress(msg)

    print(f"NFR Audit Workbench scan complete. Reviewed: {len(reviewed)} | Confirmed: {len(summary_data['confirmed'])}")
    print(f"Source split (confirmed): {summary_data['by_source']}")
    print(f"Reports written: {json_path.name}, {md_path.name}, {sarif_path.name}, {fallback_path.name}")
    print(f"Latest pointers updated in: {output_dir}")
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
