# Concurrency & Database Rules – Team Guide

## Summary

This ruleset focuses on **how database and downstream calls behave under concurrency**.

It helps us:
- Map **where DB and API calls happen**
- Detect **load amplifiers** (loops, fan-out, unbounded parallelism)
- Prevent **thundering herd** and **resource exhaustion**
- Standardize **timeouts, cancellation, and concurrency limits**

⚠️ These rules are **not bug detectors**.  
They are **scalability and reliability early-warning signals**.

---

## How to Read These Findings

Before fixing anything, always ask:
1. Is this code on a **request path**, **background job**, or **migration/admin path**?
2. Can this code be executed **concurrently**?
3. Does this pattern **multiply work** under load?

Only then decide severity and action.

---

# Rule-by-Rule Explanation

---

## Inventory Phase – “Where do we touch DB / downstream systems?”

These rules **map call sites**.  
They are **not automatically bugs**.

---

### 🔹 NFR-DB-001 – Database invocation keywords (inventory)

**What this rule detects**
- Any code that executes database operations
- EF Core, Dapper, ADO.NET patterns

**Why this rule exists**
Most production issues start with **unexpected DB access paths**:
- DB calls hidden in helpers
- DB access from UI or background jobs
- Inconsistent timeout and cancellation behavior

**How to treat findings**
- Build a **DB-call map**
- Identify **hotspots**
- Use for **standardization**, not immediate refactoring

---

### 🔹 NFR-DB-002 – Raw SQL execution detected

**What this rule detects**
- Inline SQL strings
- Raw query execution bypassing ORM safety

**Why this rule exists**
Raw SQL:
- Bypasses query abstraction
- Often misses timeout, cancellation, or parameterization
- Is harder to govern at scale

**How to treat findings**
- Validate parameterization
- Ensure timeout and cancellation are set
- Prefer shared helpers over ad-hoc SQL

---

### 🔹 NFR-DB-003 – ORM hotspot indicators

**What this rule detects**
- Heavy ORM query usage
- Potential performance-sensitive access paths

**Why this rule exists**
ORMs are safe but:
- Can hide expensive queries
- Can accidentally cause N+1 patterns
- Need consistent usage standards

**How to treat findings**
- Review query shape
- Check execution frequency
- Optimize only if on hot path

---

### 🔹 NFR-DB-004 – Direct ADO.NET command execution

**What this rule detects**
- `SqlCommand`, `NpgsqlCommand`, `DbCommand` usage

**Why this rule exists**
Direct ADO.NET:
- Gives control
- But often skips shared policies (timeouts, retries, cancellation)

**How to treat findings**
- Ensure command timeout is set
- Ensure cancellation token is propagated
- Prefer shared execution helpers

---

### 🔹 NFR-API-001 – Downstream / internal API invocation (inventory)

**What this rule detects**
- HttpClient calls
- Typed clients
- gRPC or SDK calls

**Why this rule exists**
Hidden downstream calls:
- Multiply latency
- Cause cascading failures
- Are often missed during performance reviews

**How to treat findings**
- Identify fan-out paths
- Ensure cancellation propagation
- Validate retry and timeout behavior

---

# Amplifier Phase – “Where does work multiply under load?”

These rules indicate **real scalability risk**.

---

### 🔥 NFR-TH-005 – Parallel downstream or DB fan-out

**What this rule detects**
- Multiple DB or API calls executed in parallel
- Often via `Task.WhenAll`

**Why this rule exists**
Parallel fan-out:
- Can overwhelm DB or services
- Can starve thread pool
- Multiplies retries during partial outages

**Correct mindset**
> Parallelism must be **bounded**, not removed.

---

### 🔥 NFR-TH-007 – Fan-out hidden behind typed clients

**What this rule detects**
- `Task.WhenAll` over typed service / API clients

**Why this rule exists**
Fan-out is harder to notice when hidden behind abstractions.
The risk is the same as direct HttpClient fan-out.

**How to treat findings**
- Add concurrency limits
- Review request cardinality
- Avoid per-item remote calls

---

### 🔥 NFR-TH-008A – Loop-triggered database execution

**What this rule detects**
- Awaited DB calls inside loops

**Why this rule exists**
This is the **single biggest DB load amplifier**.

Important nuance:
- This is **not always ORM N+1**
- Often it is **sequential execution** or **batching opportunity**

**Why it’s risky**
- One request → many DB round-trips
- Under concurrency → exponential load

**Correct fixes**
- Batch queries
- Use bulk operations
- Reuse connection + transaction
- Reduce per-iteration execution

---

### 🔥 NFR-TH-008B – Loop-triggered downstream API calls

**What this rule detects**
- Awaited HttpClient / SDK calls inside loops

**Why this rule exists**
Under concurrency, this causes:
- API storms
- Rate-limit breaches
- Cascading retries

**Correct fixes**
- Batch APIs
- Bound concurrency
- Cache or coalesce requests

---

# Hardening Phase – “Is concurrency controlled and safe?”

These rules reduce **blast radius**.

---

### 🛡️ NFR-HARD-001 – Unbounded parallel execution

**What this rule detects**
- Parallel loops without limits
- `Task.WhenAll` without throttling

**Why this rule exists**
Unbounded concurrency:
- Starves thread pool
- Overloads DB and downstream services
- Causes unpredictable latency spikes

**Correct pattern**
- Use `SemaphoreSlim`
- Set `MaxDegreeOfParallelism`
- Centralize concurrency helpers

---

### 🛡️ NFR-HARD-002 – Cache miss stampede risk

**What this rule detects**
- Cache get → DB call → cache set patterns

**Why this rule exists**
Cache misses under load can:
- Trigger many identical DB queries
- Create synchronized spikes (stampede)

**How to treat findings**
- Add request coalescing
- Use stale-while-revalidate
- Apply per-key locking if needed

---

## Final Guidance to the Team

- Inventory rules help us **see the system**
- Amplifier rules protect us **at scale**
- Hardening rules reduce **blast radius**
- Not every finding needs immediate fixing
- **Context always matters**

> Think in terms of **multipliers**, not just milliseconds.

---