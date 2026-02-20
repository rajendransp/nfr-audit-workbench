# AngularJS Migration Rules – Team Guide (angularjs_migration_rules.json)

## Summary

This ruleset helps identify **legacy AngularJS patterns** that slow down pages, leak memory, or block migration. It is primarily a **migration prioritization** and **performance hotspot** guide.

**Rule count:** 10 (must match `angularjs_migration_rules.json` exactly)

---

## How to read this ruleset

Use findings to prioritize migration:
- Reduce heavy watchers/digest work
- Fix leak-prone timers and event handlers
- Add `track by` to repeated lists
- Replace legacy patterns in high-traffic screens first


---

# Rule-by-Rule Explanation


## Quick checklist

- [ ] Limit watchers and avoid deep watches
- [ ] Add `track by` for repeated lists
- [ ] Dispose timers and event handlers
- [ ] Prioritize hotspots for migration

---

## NFR-FE-AJ-001 — AngularJS controller declaration in template

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-002 — AngularJS two-way binding with ng-model

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-003 — AngularJS scope object usage

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-004 — AngularJS module controller registration

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-005 — AngularJS directive with compile/link or replace:true

Severity: **S1** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **must-fix** if on a common user path. Confirm execution context and fix to prevent scale issues.


## NFR-FE-AJ-006 — AngularJS dynamic template compilation with $compile

Severity: **S1** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **must-fix** if on a common user path. Confirm execution context and fix to prevent scale issues.


## NFR-FE-AJ-007 — AngularJS list rendering without stable identity (ng-repeat track by)

Severity: **S3** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
AngularJS `ng-repeat` usage that can create too many watchers or cause expensive digest cycles.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-008 — AngularJS router configuration (ngRoute/ui-router)

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-009 — AngularJS view placeholders in templates

Severity: **S2** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.


## NFR-FE-AJ-010 — AngularJS filters in template expressions

Severity: **S3** · Category: **front_end** · Sub-category: **migration**


**What it flags**  
Legacy AngularJS patterns that hurt performance, maintainability, or migration readiness.

**Why it exists**  
This pattern is correlated with real production issues (slow UI, memory leaks, security exposure, or backend amplification).

**How to treat findings**  
Treat as **review + standardization**. Fix when touching the area, or if it’s on a hot path.

