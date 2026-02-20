# Razor Rules – Team Guide (razor_rules.json)

## Summary

This ruleset focuses on **Razor/Blazor view safety and performance**. Views should primarily render; heavy logic, DB calls, or raw HTML rendering increase risk.

**Rule count:** 6 (must match `razor_rules.json` exactly)

---

## How to read this ruleset

Treat view-layer findings as **high-leverage**:
- Views should not execute expensive work
- Raw HTML APIs require sanitization
- Avoid hidden DB/network calls in rendering


---

# Rule-by-Rule Explanation


## Quick checklist

- [ ] Render-only views; avoid DB calls in views
- [ ] Sanitize any raw HTML rendering
- [ ] Keep event handlers lightweight
- [ ] Avoid expensive loops during render

---

## NFR-RAZOR-001 — Large list rendering without Virtualize

Severity: **S4** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Razor/Blazor patterns that impact security, performance, or maintainability.

**Why it exists**  
Rendering thousands of DOM nodes is expensive and causes slow UI and high memory usage.

**How to treat findings**  
Adopt virtualization (windowing) for long lists/tables, and paginate on the server.


## NFR-RAZOR-002 — Frequent @oninput handler without shaping

Severity: **S4** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Razor/Blazor event handlers with patterns that can cause excessive re-renders.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-RAZOR-003 — IJSRuntime call inside loop

Severity: **S2** · Category: **front_end** · Sub-category: **concurrency**


**What it flags**  
Razor/Blazor patterns that impact security, performance, or maintainability.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-RAZOR-004 — Risky raw HTML rendering via MarkupString

Severity: **S1** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Razor/Blazor raw HTML rendering patterns that could bypass encoding.

**Why it exists**  
Razor/Blazor normally encodes output. Raw HTML APIs bypass encoding and can introduce XSS if content is not strictly controlled.

**How to treat findings**  
Treat as **security review**. Ensure content is sanitized/encoded and comes from a trusted, controlled source.


## NFR-RAZOR-004B — Generic MarkupString raw HTML usage

Severity: **S3** · Category: **front_end** · Sub-category: **loading**


**What it flags**  
Razor/Blazor raw HTML rendering patterns that could bypass encoding.

**Why it exists**  
Razor/Blazor normally encodes output. Raw HTML APIs bypass encoding and can introduce XSS if content is not strictly controlled.

**How to treat findings**  
Treat as **security review**. Ensure content is sanitized/encoded and comes from a trusted, controlled source.


## NFR-RAZOR-005 — Synchronous work in lifecycle method

Severity: **S2** · Category: **front_end** · Sub-category: **performance**


**What it flags**  
Razor/Blazor patterns that impact security, performance, or maintainability.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.

