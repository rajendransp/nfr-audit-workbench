# NFR DIGEST - TEMPLATE v2

(Run-based, technically precise, safe-fix oriented)

## 1. Run Summary

Repository: `<repo-name>`  
Ruleset Version: `<ruleset-name + version>`  
Scan Scope: `run_only`  
Scan Timestamp: `<timestamp>`

Findings Summary

| Metric | Count |
| --- | ---: |
| Reviewed findings | `<number>` |
| Confirmed findings | `<number>` |
| False positives | `<number>` |
| Manual attention required | `<number>` |

Definition:
- Reviewed = total findings evaluated in this run
- Confirmed = findings validated as real technical risks
- Manual attention = findings where automated analysis could not confidently determine correctness

## 2. Severity Breakdown (Confirmed Findings Only)

| Severity | Count | Meaning |
| --- | ---: | --- |
| S1 | `<n>` | Definite scalability / reliability risk; fix required |
| S2 | `<n>` | Real issue or design smell; fix recommended |
| S3 | `<n>` | Advisory / best practice |
| S4 | `<n>` | Informational |

Warning:
Severity reflects technical risk, not execution context.  
Execution context (request path vs background job vs migration) must be evaluated during remediation.
Policy: `migration_admin` context may downshift one severity level for load-amplification rules (for example `NFR-TH-008A`, `NFR-TH-008B`, `NFR-IO-LOOP-001`, `NFR-TH-004`).

## 3. Rule Quality Scoreboard (Run-only)

Important:
This scoreboard reflects this scan run only.  
It does not include historical or cross-run aggregation.

| Rule ID | Reviewed | Confirmed | Precision | Fallback Count |
| --- | ---: | ---: | ---: | ---: |
| NFR-TH-008A | `<n>` | `<n>` | `<%>` | `<n>` |
| NFR-API-001 | `<n>` | `<n>` | `<%>` | `<n>` |
| ... | ... | ... | ... | ... |

Interpretation Guidelines:
- Precision = Confirmed / Reviewed for this run
- Fallback Count = cases where parsing/analysis failed and manual review was required
- Low precision does not automatically mean a bad rule; some rules are intentionally conservative (inventory, hardening)
- Low precision architectural rules are risk indicators and require context-aware triage, not blind dismissal.

## 4. Source Attribution (Confirmed Findings Only)

| Detection Source | Count |
| --- | ---: |
| Regex-based | `<n>` |
| LLM-confirmed | `<n>` |
| Hybrid | `<n>` |

Clarification:
Source attribution is shown only for confirmed findings, not for all reviewed findings.

## 5. Key Findings (Validated)

### 5.1 S1 - Critical Technical Risks

Pattern: Awaited DB calls inside loops (NFR-TH-008A)

Why this matters (technical explanation):
- Causes sequential loop-triggered database round-trips
- Amplifies latency
- Can escalate to load amplification under concurrency if invoked by multiple requests/jobs

Correct remediation strategies:
- Batch queries (IN, joins)
- Bulk operations
- Server-side aggregation
- Reduce per-iteration DB execution

Important nuance:
This pattern is always a performance risk.  
It becomes a thundering herd risk only if executed concurrently across requests/jobs.

### 5.2 S2 - Reliability & Hardening Issues

Pattern: Missing CancellationToken in outbound async calls (NFR-API-001)

Why this matters:
- Prevents graceful cancellation
- Increases resource usage during shutdown/timeouts
- Can cause request pile-up under load

Correct remediation:
- Add CancellationToken parameters
- Propagate from caller
- Do not introduce CancellationToken.None as a compliance shortcut

## 6. Patch Suggestions & Safety Notes

Patch Safety Classification

| Patch Type | Safety Level | Notes |
| --- | --- | --- |
| CancellationToken propagation | Safe | Requires signature changes |
| Loop-to-batch refactor | Manual | Structural refactor |
| Bulk DDL statements | Conditional | Driver & DB dependent |
| Introducing CancellationToken.None | Unsafe | Does not enable cancellation |

Patch Safety Notes (Mandatory Reading):
- CancellationToken.None is not a fix. It does not improve cancellation or shutdown behavior.
- Multi-statement SQL commands may require driver support, connection string flags, and careful escaping.
- Sequential loop-triggered execution fixes cannot be safely auto-patched; they require domain-aware refactoring.
- Auto-patch unavailable items require manual review by module owners.
- `patch_attention=no_patch` count should be explicitly reported per run.
- Recommended validation: confirm execution context (request/background/migration) and load test under concurrency.

## 7. Known Limitations of This Report

- Execution context (request vs background vs migration) may require manual validation
- Structural refactors may not generate valid auto-patches
- Inventory rules may surface valid patterns that are not immediate bugs

## 8. Recommendations

Immediate:
- Fix S1 looped DB execution patterns
- Propagate CancellationToken correctly

Medium-term:
- Introduce execution-context tagging
- Standardize DB access abstractions
- Improve bulk-operation utilities

## Feedback To The Report Generation Team

Feedback on NFR Digest Generation (Actionable):
1. Clarify scope in scoreboard.
If a rule quality table includes historical data, label it clearly.
If it is run-only, ensure numbers cannot exceed run totals.
2. Rename ambiguous labels.
Source split -> Confirmed source split.
Fallback/manual attention -> Analysis fallback (manual review required).
3. Avoid misleading fix suggestions.
Do not suggest CancellationToken.None as a fix.
Flag multi-statement SQL patches as conditional.
4. Separate risk vs context.
Use phrasing like "Amplifies load under concurrency" instead of "Will cause thundering herd".
5. Explicitly document auto-patch limits.
State clearly when structural refactors are required, domain knowledge is necessary, and auto-patching is intentionally skipped.
