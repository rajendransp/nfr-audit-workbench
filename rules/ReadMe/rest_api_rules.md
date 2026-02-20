# REST API Rules – Team Guide (rest_api_rules.json)

## Summary (What this ruleset is for)

This ruleset protects our APIs from **scale failures** and **operational surprises**:
- Slowdowns due to oversized payloads or missing pagination
- Request pile-ups due to missing timeouts, cancellation, or sync I/O
- Incident amplification due to unsafe retry patterns
- Contract drift due to mixed serializers
- Risky endpoint exposure (anonymous access, missing idempotency)

These rules are **not “bugs by default.”**  
Many are **heuristics** and should be treated as **review prompts**, especially where controls may exist at the gateway/ingress.

**Rule count:** 18

---

## How to interpret findings

Before acting, ask:
1. Is this endpoint **public** or **tenant/user-specific**?
2. Is protection handled **in-app** or **upstream** (gateway/ingress/WAF)?
3. Is this on a **hot path** (high QPS) or admin-only?

---

# Rule-by-Rule Explanation

---

## NFR-API-001 — Controller action missing CancellationToken (S2)

**What it flags**
- Controller actions that don’t accept a `CancellationToken`

**Why it exists**
If clients disconnect or time out, the server should stop doing work.
Cancellation prevents wasted DB/IO work and helps graceful shutdown.

**Typical fix**
- Add `CancellationToken cancellationToken` to the action signature.
- Pass it down to async calls.

**When it may be OK**
- Truly fire-and-forget endpoints (rare).
- Endpoints that do no async work (still recommend consistency).

---

## NFR-API-002 — Large request body limit configured (S2)

**What it flags**
- Very high request body limits (or missing caps) that allow huge payloads

**Why it exists**
Large bodies increase:
- memory pressure
- parsing CPU
- DoS exposure

**Typical fix**
- Set explicit size limits (per endpoint or globally).
- Validate content type and structure early.

**When it may be OK**
- Controlled internal APIs, large file upload endpoints (still require strong guards).

---

## NFR-API-003 — No pagination on collection response (S3)

**What it flags**
- Endpoints returning collections without pagination patterns

**Why it exists**
Unpaged collections lead to:
- large payloads
- slow responses
- client/server memory spikes

**Typical fix**
- Introduce pagination: `page/pageSize`, cursor, or continuation tokens.
- Enforce max page size.

**Important note**
This is a **heuristic**: pagination may exist inside service layer.
Treat as **review** unless confirmed.

---

## NFR-API-004A — Manual JSON serialization used to build HTTP response (S3)

**What it flags**
- Returning manually serialized JSON strings in controller responses

**Why it exists**
Manual serialization:
- bypasses framework formatting and negotiation
- can set wrong headers/content type
- complicates tracing and compression

**Typical fix**
- Return objects and let ASP.NET Core formatters serialize.
- Use `return Ok(obj)` / typed `ActionResult<T>`.

---

## NFR-API-004B — Mixed Newtonsoft/System.Text.Json serializer usage (contract drift risk) (S3)

**What it flags**
- Projects or endpoints using both Newtonsoft.Json and System.Text.Json

**Why it exists**
Different defaults lead to contract drift:
- property naming
- enum handling
- date formats
- null handling

**Typical fix**
- Standardize on one serializer per API surface.
- If both required (legacy), isolate by area and document settings.

---

## NFR-API-004C — JSON serialize→deserialize round-trip (S2)

**What it flags**
- Patterns where code serializes JSON then immediately deserializes (or reverse)

**Why it exists**
This is usually wasteful:
- CPU + allocations
- latency
- GC pressure

**Typical fix**
- Map objects directly (DTO mapping).
- If transformation is required, use strongly typed conversions.

---

## NFR-API-005 — Missing response caching hints on GET endpoint (S3)

**What it flags**
- GET endpoints missing cache hints where caching is expected

**Why it exists**
Cache headers improve:
- performance
- cost
- perceived latency

**Important note**
This rule explicitly says caching hints should apply only for endpoints meant to be public-cacheable.
Authorized and tenant/user-specific endpoints should not be cached publicly.

**Typical fix**
- Add proper cache headers only where safe.
- Use `Cache-Control`, `ETag`, `Last-Modified` where appropriate.

---

## NFR-API-006 — Endpoint returns full entity directly (S3)

**What it flags**
- Returning persistence entities (DB models) directly from API

**Why it exists**
Entities often include:
- unnecessary fields
- sensitive or internal fields
- larger payloads
- unstable contracts

**Typical fix**
- Return DTOs (explicit contract).
- Shape response fields intentionally.

---

## NFR-API-007 — No request timeout policy in HttpClient registration (S2)

**What it flags**
- HttpClient registrations without an obvious timeout policy

**Why it exists**
Without timeouts:
- calls can hang
- threads/resources get stuck
- retries amplify incidents

**Important note**
Heuristic rule: timeouts may exist via handlers, extension methods, or upstream gateway.
Treat as **review** until confirmed.

**Typical fix**
- Ensure per-client timeout policy is set (and consistent).
- Also ensure gateway timeouts align: `DB < API < Gateway`.

---

## NFR-API-008 — Retry policy without jitter/backoff (S2)

**What it flags**
- Retry patterns that retry aggressively without jitter/backoff

**Why it exists**
During partial outages, synchronized retries cause incident amplification (“retry storms”).

**Typical fix**
- Exponential backoff + jitter.
- Retry only idempotent operations.
- Prefer circuit breakers for sustained failures.

---

## NFR-API-009 — No [ApiController] on controller class (S4)

**What it flags**
- Controllers missing `[ApiController]`

**Why it exists**
`[ApiController]` enables safer defaults:
- automatic 400 responses for invalid models
- binding improvements

**Why it’s low severity**
MVC controllers may intentionally omit it.
Treat as low-priority best practice.

---

## NFR-API-010 — Bulk endpoint without max batch constraint (S2)

**What it flags**
- Bulk endpoints that accept unbounded item counts

**Why it exists**
Unbounded batch sizes cause:
- bursty CPU/memory
- DB spikes
- unpredictable latency

**Typical fix**
- Enforce max batch size.
- Return per-item errors safely.
- Consider async job pattern for large requests.

---

## NFR-API-011 — No rate limiting middleware configured (S2)

**What it flags**
- Missing admission control (rate limiting) in-app

**Why it exists**
Rate limiting prevents:
- abuse
- accidental floods
- uneven tenant impact

**Important note**
If enforced upstream (gateway/ingress/WAF), suppress this rule in-app.

**Typical fix**
- Implement middleware or confirm gateway enforcement.
- Use tenant/site-based limits if multi-tenant.

---

## NFR-API-012 — Endpoint reads request body synchronously (S2)

**What it flags**
- Sync request body reads in request pipeline

**Why it exists**
Sync body reads:
- block worker threads
- reduce concurrency
- increase tail latency

**Typical fix**
- Use async reads (`ReadAsync`, model binding, streaming APIs).
- Avoid buffering full bodies unless necessary.

---

## NFR-API-013 — POST retry-sensitive endpoint missing idempotency key handling (S2)

**What it flags**
- POST endpoints that should be idempotent but don’t handle idempotency keys

**Why it exists**
Retries can duplicate processing:
- double creation
- double payment/side-effects
- inconsistent state

**Typical fix**
- Add idempotency keys (header/body).
- Store request key + result for a limited window.

---

## NFR-API-014 — File upload endpoint missing request size guard (S2)

**What it flags**
- Upload endpoints without explicit request size enforcement

**Why it exists**
Uploads are a common abuse vector:
- memory pressure
- disk pressure
- DoS risk

**Typical fix**
- Define endpoint-specific size limits.
- Validate MIME types, extensions, and stream content safely.

---

## NFR-API-015 — Critical endpoint marked AllowAnonymous (S2)

**What it flags**
- Sensitive mutation/auth endpoints that allow anonymous access

**Why it exists**
Anonymous access must be explicit and justified.
The rule excludes common auth entrypoints (where anonymous is expected), but still wants review.

**Typical fix**
- Confirm intended security model.
- Require auth for sensitive operations.
- Add explicit documentation if anonymous is required.

---

## NFR-API-016 — Controller CancellationToken not propagated to async service call (S2)

**What it flags**
- Controller accepts `CancellationToken` but doesn’t pass it to downstream async calls

**Why it exists**
Cancellation must flow end-to-end; otherwise it’s only cosmetic.

**Typical fix**
- Propagate token to service/repo/SDK calls.

**What NOT to do**
- Don’t “fix” by passing `CancellationToken.None`.

---

## Team Guidance (Quick Rules)

- **Request path:** cancellation + timeout are mandatory
- **Bulk endpoints:** always enforce max batch size
- **Retries:** must use backoff + jitter and be idempotent-safe
- **Collections:** paginate or cap
- **Serialization:** standardize to avoid contract drift

---