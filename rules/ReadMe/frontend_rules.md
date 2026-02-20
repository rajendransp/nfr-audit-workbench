# Frontend Rules – Team Guide (frontend_rules.json)

## Summary

This ruleset focuses on **frontend performance, stability, and security**. Frontend patterns can directly trigger backend load (API storms), cause memory leaks, and introduce XSS risks.

**Rule count:** 17 (must match `frontend_rules.json` exactly)

---

## How to read this ruleset

Use these findings to prevent **UI-triggered amplification**:
- Prefer cancellation/timeouts for network calls
- Clean up timers/subscriptions
- Debounce/throttle user input
- Virtualize large lists
- Never inject untrusted HTML


---

# Rule-by-Rule Explanation


## Quick checklist

- [ ] Cancel in-flight requests on navigation/unmount
- [ ] Debounce input-driven API calls
- [ ] Avoid `innerHTML` / sanitize if unavoidable
- [ ] Cleanup timers/subscriptions
- [ ] Virtualize long lists/tables

---

## NFR-FE-001 — fetch call without AbortSignal

Severity: **S3** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Network calls without cancellation/timeout handling.

**Why it exists**  
Unbounded or uncancelled requests waste bandwidth, keep work running after navigation, and complicate error handling.

**How to treat findings**  
Add request cancellation (AbortController), timeouts, and consistent error handling. Avoid duplicate requests on re-render.


## NFR-FE-002 — Axios call without timeout

Severity: **S2** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Network calls without cancellation/timeout handling.

**Why it exists**  
Unbounded or uncancelled requests waste bandwidth, keep work running after navigation, and complicate error handling.

**How to treat findings**  
Add request cancellation (AbortController), timeouts, and consistent error handling. Avoid duplicate requests on re-render.


## NFR-FE-003 — setInterval without cleanup

Severity: **S2** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Timers (`setInterval`, `setTimeout`) without cleanup or with very short periods.

**Why it exists**  
Leaky or aggressive timers create memory leaks and background CPU usage, and can amplify backend load via repeated calls.

**How to treat findings**  
Ensure timers are cleaned up (unsubscribe/clear interval) and avoid very short intervals. Prefer event-driven updates.


## NFR-FE-004 — Unhandled promise chain

Severity: **S2** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Unhandled promise rejections or missing error handling.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-005A — Risky innerHTML/dangerouslySetInnerHTML from dynamic source

Severity: **S1** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Unsafe HTML insertion (`innerHTML`, `dangerouslySetInnerHTML`) that can lead to XSS.

**Why it exists**  
Raw HTML injection is a common XSS vector. Even trusted sources can become unsafe when data paths change.

**How to treat findings**  
Treat as **high priority**. Prefer safe templating/encoding. If raw HTML is required, sanitize with an allowlist and keep content strictly controlled.


## NFR-FE-005B — innerHTML/dangerouslySetInnerHTML with static literal (review)

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Unsafe HTML insertion (`innerHTML`, `dangerouslySetInnerHTML`) that can lead to XSS.

**Why it exists**  
Raw HTML injection is a common XSS vector. Even trusted sources can become unsafe when data paths change.

**How to treat findings**  
Treat as **high priority**. Prefer safe templating/encoding. If raw HTML is required, sanitize with an allowlist and keep content strictly controlled.


## NFR-FE-006 — Array index used as React key

Severity: **S3** · Category: **front_end** · Sub-category: **performance**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-007 — Potential heavy mapping in render path (review)

Severity: **S3** · Category: **front_end** · Sub-category: **performance**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-008 — No lazy loading for route components

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-009 — Image without lazy loading

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-010 — Frequent input handler without debounce/throttle

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Input/change handlers without debounce/throttle leading to excessive API calls/renders.

**Why it exists**  
Without debounce/throttle, rapid user input can trigger many renders/API calls, increasing backend QPS and UI jank.

**How to treat findings**  
Apply debounce/throttle for input handlers and batch server calls. Consider caching and client-side filtering where appropriate.


## NFR-FE-011 — console.log in app code

Severity: **S4** · Category: **front_end** · Sub-category: **performance**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-012 — Blocking synchronous Web Storage access in loop

Severity: **S4** · Category: **front_end** · Sub-category: **performance**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-013 — Unbounded list rendering without virtualization

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Large list/table rendering without virtualization.

**Why it exists**  
Rendering thousands of DOM nodes is expensive and causes slow UI and high memory usage.

**How to treat findings**  
Adopt virtualization (windowing) for long lists/tables, and paginate on the server.


## NFR-FE-014 — useEffect data fetch missing dependency array

Severity: **S3** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Network calls without cancellation/timeout handling.

**Why it exists**  
Unbounded or uncancelled requests waste bandwidth, keep work running after navigation, and complicate error handling.

**How to treat findings**  
Add request cancellation (AbortController), timeouts, and consistent error handling. Avoid duplicate requests on re-render.


## NFR-FE-015 — addEventListener in effect without cleanup

Severity: **S2** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-016 — Large bundle import anti-patterns

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Frontend patterns that can cause performance issues, leaks, or security risks.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.

