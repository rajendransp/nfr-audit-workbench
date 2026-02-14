import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from collections import Counter
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
    parser.add_argument("--path", default=".", help="Repository or service path to scan")
    parser.add_argument(
        "--rules",
        default="rules/dotnet_rules.json",
        help="Path to JSON rules file",
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
        "--max-llm",
        type=int,
        default=120,
        help="Max findings sent to Ollama",
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
        help="Optional baseline findings JSON path",
    )
    parser.add_argument(
        "--only-new",
        action="store_true",
        help="Report only findings not present in baseline",
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
    return parser.parse_args()


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Rules JSON must be a list")
    return data


def _run_rg(path, rule):
    rg_path = shutil.which("rg")
    if not rg_path:
        return _run_regex_fallback(path, rule)

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

    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if result.returncode not in (0, 1):
        raise RuntimeError(f"rg failed for {rule['id']}: {result.stderr.strip()}")

    matches = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("type") != "match":
            continue
        data = entry["data"]
        matches.append(
            {
                "file": data["path"]["text"],
                "line": data["line_number"],
                "column": data["submatches"][0]["start"] + 1 if data.get("submatches") else 1,
                "match_text": data["lines"]["text"].rstrip("\n"),
            }
        )
    return matches


def _is_included(rel_path, include_globs, exclude_globs):
    include_ok = True
    if include_globs:
        include_ok = any(fnmatch(rel_path, g) for g in include_globs)
    if not include_ok:
        return False
    if exclude_globs and any(fnmatch(rel_path, g) for g in exclude_globs):
        return False
    return True


def _run_regex_fallback(path, rule):
    pattern = re.compile(rule["pattern"])
    include_globs = rule.get("include_globs", [])
    exclude_globs = rule.get("exclude_globs", [])

    matches = []
    root = Path(path)
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        rel_path = file_path.relative_to(root).as_posix()
        if not _is_included(rel_path, include_globs, exclude_globs):
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


def pre_scan(scan_path, rules, context_lines, max_findings):
    all_findings = []
    cache = {}
    total_rules = len(rules)
    for idx, rule in enumerate(rules, start=1):
        log_progress(f"Regex rule {idx}/{total_rules}: {rule['id']}")
        matches = _run_rg(scan_path, rule)
        log_progress(f"Rule {rule['id']} produced {len(matches)} match(es)")
        for m in matches:
            snippet = _snippet(m["file"], m["line"], context_lines, cache)
            key = f"regex|{rule['id']}|{m['file']}|{m['line']}|{hashlib.sha1(m['match_text'].encode('utf-8', errors='ignore')).hexdigest()[:12]}"
            all_findings.append(
                {
                    "finding_key": key,
                    "source": "regex",
                    "rule_id": rule["id"],
                    "rule_title": rule["title"],
                    "category": rule.get("category", "reliability"),
                    "default_severity": rule.get("severity", "S3"),
                    "rationale": rule.get("rationale", ""),
                    "file": m["file"],
                    "line": m["line"],
                    "column": m["column"],
                    "file_type": _file_type(m["file"]),
                    "language": _language_for_file(m["file"]),
                    "match_text": m["match_text"],
                    "snippet": snippet,
                }
            )
            if len(all_findings) >= max_findings:
                log_progress(f"Reached max-findings limit ({max_findings}) during pre-scan")
                return all_findings

    unique = []
    seen = set()
    for item in all_findings:
        if item["finding_key"] in seen:
            continue
        seen.add(item["finding_key"])
        unique.append(item)
    return unique


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


def _parse_roslyn_findings(sarif_path, scan_root, context_lines):
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
            snippet = _snippet(norm_path, line, context_lines, cache)

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


def review_with_ollama(findings, model, base_url, temperature):
    reviewed = []
    url = f"{base_url.rstrip('/')}/api/chat"
    total = len(findings)
    log_progress(f"Starting Ollama review for {total} finding(s) with model '{model}'.")

    for idx, finding in enumerate(findings, start=1):
        rule_payload = {
            "id": finding["rule_id"],
            "title": finding["rule_title"],
            "category": finding["category"],
            "default_severity": finding["default_severity"],
            "rationale": finding["rationale"],
            "source": finding.get("source", "unknown"),
        }
        prompt = USER_TEMPLATE.format(
            rule_json=json.dumps(rule_payload, ensure_ascii=True),
            file_path=finding["file"],
            line=finding["line"],
            snippet=finding["snippet"] or finding.get("match_text", ""),
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

        try:
            resp = requests.post(url, json=body, timeout=(20, 120))
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            parsed = _extract_json(content)
        except Exception as exc:
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

        finding_out = dict(finding)
        finding_out["llm_review"] = parsed
        reviewed.append(finding_out)
        if idx % 10 == 0 or idx == total:
            log_progress(f"Ollama review progress: {idx}/{total}")

    return reviewed


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


def _module_key(path):
    p = Path(path).parts
    if len(p) >= 2:
        return f"{p[0]}/{p[1]}"
    if len(p) == 1:
        return p[0]
    return "unknown"


def summarize(reviewed):
    confirmed = [x for x in reviewed if bool(x.get("llm_review", {}).get("isIssue", False))]

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
    by_language = Counter(x.get("language", "unknown") for x in confirmed)
    by_file_type = Counter(x.get("file_type", "unknown") for x in confirmed)

    return {
        "all_reviewed": reviewed,
        "confirmed": confirmed,
        "by_category": dict(by_category),
        "by_module": dict(by_module),
        "by_severity": dict(by_severity),
        "by_source": dict(by_source),
        "by_language": dict(by_language),
        "by_file_type": dict(by_file_type),
    }


def write_json_report(summary_data, output_dir, roslyn_meta, scan_meta):
    output_path = Path(output_dir) / scan_meta["findings_file"]
    payload = {
        "summary": {
            "total_reviewed": len(summary_data["all_reviewed"]),
            "confirmed_issues": len(summary_data["confirmed"]),
            "by_severity": summary_data["by_severity"],
            "by_category": summary_data["by_category"],
            "by_module": summary_data["by_module"],
            "by_source": summary_data["by_source"],
            "by_language": summary_data["by_language"],
            "by_file_type": summary_data["by_file_type"],
        },
        "scan": scan_meta,
        "roslyn": roslyn_meta,
        "findings": summary_data["all_reviewed"],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Compatibility pointer for existing tools/UI
    (Path(output_dir) / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def write_markdown(summary_data, output_dir, roslyn_meta, scan_meta):
    path = Path(output_dir) / scan_meta["digest_file"]
    confirmed = summary_data["confirmed"]

    lines = []
    lines.append("# NFR Risk Digest")
    lines.append("")
    lines.append(f"- Reviewed findings: {len(summary_data['all_reviewed'])}")
    lines.append(f"- Confirmed issues: {len(confirmed)}")
    lines.append(f"- Severity split: {summary_data['by_severity']}")
    lines.append(f"- Source split: {summary_data['by_source']}")
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


def main():
    load_env()
    args = parse_args()

    model = os.getenv("NFR_OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL") or "qwen3-coder:30b"
    base_url = os.getenv("NFR_OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"

    scan_path = Path(args.path).resolve()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    project_name = _project_name_from_scan_path(scan_path)
    run_version = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"findings__{project_name}__{run_version}"
    scan_meta = {
        "project": project_name,
        "run_version": run_version,
        "scan_path": str(scan_path),
        "findings_file": f"{base_name}.json",
        "digest_file": f"nfr_digest__{project_name}__{run_version}.md",
        "sarif_file": f"nfr__{project_name}__{run_version}.sarif",
    }
    log_progress(f"NFR Audit Workbench scan started for path: {scan_path}")
    log_progress(f"Output directory: {output_dir.resolve()}")

    rules = load_rules(args.rules)
    log_progress(f"Loaded {len(rules)} regex rule(s) from {args.rules}")
    regex_findings = pre_scan(scan_path, rules, args.context_lines, args.max_findings)
    log_progress(f"Regex pre-scan produced {len(regex_findings)} finding(s)")

    roslyn_meta = {
        "enabled": bool(args.include_roslyn),
        "executed": False,
        "imported_findings": 0,
        "note": "",
        "sarif_path": "",
    }
    roslyn_findings = []

    if args.include_roslyn:
        log_progress("Roslyn scan enabled. Running dotnet analyzer build...")
        sarif_path, roslyn_error = _run_roslyn_sarif(
            scan_path,
            output_dir,
            args.dotnet_target,
            args.dotnet_configuration,
            args.dotnet_timeout_seconds,
        )
        if sarif_path:
            roslyn_findings = _parse_roslyn_findings(sarif_path, scan_path, args.context_lines)
            roslyn_meta["executed"] = True
            roslyn_meta["imported_findings"] = len(roslyn_findings)
            roslyn_meta["sarif_path"] = str(sarif_path)
            log_progress(f"Roslyn findings imported: {len(roslyn_findings)}")
        else:
            roslyn_meta["note"] = roslyn_error
            log_progress(f"Roslyn scan note: {roslyn_error}")

    findings = regex_findings + roslyn_findings
    log_progress(f"Combined findings before baseline filter: {len(findings)}")

    if args.only_new:
        baseline_keys = load_baseline_keys(args.baseline)
        findings = [f for f in findings if f["finding_key"] not in baseline_keys]
        log_progress(f"Findings after baseline filter: {len(findings)}")

    findings_for_llm = findings[: args.max_llm]
    log_progress(f"Sending {len(findings_for_llm)} finding(s) to Ollama (max_llm={args.max_llm})")
    reviewed = review_with_ollama(findings_for_llm, model, base_url, args.temperature)

    summary_data = summarize(reviewed)
    json_path = write_json_report(summary_data, output_dir, roslyn_meta, scan_meta)
    md_path = write_markdown(summary_data, output_dir, roslyn_meta, scan_meta)
    sarif_path = write_sarif(summary_data, output_dir, scan_meta)

    print(f"NFR Audit Workbench scan complete. Reviewed: {len(reviewed)} | Confirmed: {len(summary_data['confirmed'])}")
    print(f"Source split (confirmed): {summary_data['by_source']}")
    print(f"Reports written: {json_path.name}, {md_path.name}, {sarif_path.name}")
    print(f"Latest pointers updated in: {output_dir}")


if __name__ == "__main__":
    main()
