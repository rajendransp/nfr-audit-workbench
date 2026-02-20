# Safe-AI Rules – Team Guide (safe_ai_rules.json)

## Summary

This ruleset protects our **data boundary** when using or integrating with AI tools (internal or external) and when generating/supporting artifacts like logs, diagnostics bundles, HAR files, crash dumps, or “share this snippet” outputs.

These rules answer one question:

> **“If this code/log/output is shared with an AI system or external party, could it leak secrets, customer data, or our security model?”**

### How to use this ruleset
- Treat **S1** as **stop-the-line**: **redact / rotate / remove** before sharing, and fix the source.
- Treat **S2** as **review-required**: verify data handling and apply masking, token propagation, or isolation.
- Treat **S3** as **awareness**: protect sensitive architecture/security patterns from unnecessary exposure.

**Rule count:** 10 (must match `safe_ai_rules.json` exactly)

---

## What these rules are *not*
- Not a “code style” checker
- Not a replacement for a secrets scanner or DLP solution
- Not saying “don’t use AI” — it is saying **use AI safely**

---

# Rule-by-Rule Explanation

## 🔴 SAFE-AI-001 — Hardcoded secret literal (S1, high)

**What it flags**
- API keys, passwords, client secrets, tokens, connection secrets embedded as literals.

**Why it exists**
Hardcoded secrets are the #1 accidental leak vector:
- copied into tickets
- pasted into chat/AI
- committed to git
- appears in logs/config dumps

**Expected action**
- **Remove from code** → move to secret store/env vars
- **Rotate** any exposed key
- Add **redaction** in logs and diagnostics output

---

## 🔴 SAFE-AI-002 — JWT token literal (S1, high)

**What it flags**
- JWT-looking strings (e.g., `eyJ...`) in code, comments, configs, logs.

**Why it exists**
JWTs often grant real access and can include PII in claims.
Even “expired” tokens are risky (replay, misconfig, long TTL, test tenants).

**Expected action**
- **Redact immediately**
- Avoid logging full tokens; log only token hash/last 6 chars
- If real token leaked: **revoke/rotate signing keys** where applicable

---

## 🔴 SAFE-AI-003A — Private key material (S1, high)

**What it flags**
- PEM private keys (`BEGIN PRIVATE KEY`, RSA/EC key blocks), raw key blobs.

**Why it exists**
Leaking private keys compromises:
- TLS termination
- signing/encryption
- license/signature systems

**Expected action**
- **Remove from repository**
- Rotate cert/key pair
- Restrict key access (vault/HSM)
- Ensure diagnostics tooling redacts PEM blocks

---

## 🟠 SAFE-AI-003B — Certificate block (S2, medium)

**What it flags**
- PEM certificates (`BEGIN CERTIFICATE`) and certificate chains.

**Why it exists**
Certificates are not secrets like private keys, but they still expose:
- internal hostnames
- org structure
- endpoints and trust chain assumptions

**Expected action**
- Allowed in controlled places (public certs), but:
  - avoid embedding internal certs in shared snippets
  - redact internal subject/alt-names in public sharing

---

## 🔴 SAFE-AI-004 — Authorization header with literal token (S1, high)

**What it flags**
- `Authorization: Bearer ...` or similar where the token is literal (code, logs, HAR).

**Why it exists**
This is a direct credential leak and often valid immediately.

**Expected action**
- **Never log Authorization headers**
- Redact in HTTP tracing/HAR exports
- Rotate/revoke tokens if leaked

---

## 🟠 SAFE-AI-005 — Authentication or token flow logic (S2, medium)

**What it flags**
- Code implementing token issuance, refresh, validation, signing, SSO/OIDC flows.

**Why it exists**
These flows are sensitive because exposure can:
- reveal bypass opportunities
- expose assumptions/weak points
- help attackers mimic flows

**Expected action**
- OK to keep in repo; the “Safe-AI” guidance is about **sharing**:
  - avoid pasting entire auth flows into external tools
  - if you must share, strip secrets and reduce to minimal reproducible snippet
  - prefer internal review channels

---

## 🟠 SAFE-AI-006 — Customer data transmitted or logged (S2, medium)

**What it flags**
- Logging or transmission of customer payloads, identifiers, email, phone, address, etc.
- Serialization of full objects to logs or external services.

**Why it exists**
PII/Customer data can leak via:
- debug logs
- error telemetry
- AI prompts and chat history
- support bundles

**Expected action**
- Apply data minimization:
  - log IDs, not full payloads
  - mask PII fields
- Add structured logging + allowlist
- Ensure AI prompts do not include raw customer records

---

## 🟡 SAFE-AI-007 — Tenant isolation enforcement logic (S3, low)

**What it flags**
- Code that enforces tenant boundaries (filters, claims mapping, RLS, tenant routing).

**Why it exists**
This logic reveals how isolation is implemented, which can:
- expose weak spots if shared externally
- leak internal assumptions

**Expected action**
- No change required in code by default
- Treat as “do not overshare”:
  - share only minimal snippets
  - remove internal identifiers and policy details

---

## 🟠 SAFE-AI-008 — Infrastructure endpoint or connection literal (S2, medium)

**What it flags**
- Internal endpoints, hostnames, IPs, connection URLs, bucket names, cluster identifiers.

**Why it exists**
Even without secrets, infrastructure details are sensitive:
- supports reconnaissance
- reveals topology and vendor stack
- increases blast radius if leaked with other clues

**Expected action**
- Replace with placeholders in shared examples
- Move endpoints to configuration
- Redact from logs/diagnostics outputs

---

## 🟡 SAFE-AI-009 — License validation or signature verification (S3, low)

**What it flags**
- Code for license validation, signature verification, tamper detection.

**Why it exists**
This is sensitive logic that may be targeted.
Sharing too much can help bypass attempts.

**Expected action**
- Keep internal; avoid sharing full implementation externally
- For debugging with AI: isolate to non-sensitive repro cases or internal tools

---

## Quick Team Checklist (Before sharing to AI / external)

- [ ] No secrets (keys/passwords/tokens)
- [ ] No Authorization headers
- [ ] No raw customer payloads / PII
- [ ] No private keys / internal endpoints
- [ ] Minimize auth/tenant isolation code shared
- [ ] Prefer redacted, minimal reproducible snippets

---

## Bottom line
Use AI confidently — **but treat prompts, logs, and pasted snippets as public unless proven otherwise**.
