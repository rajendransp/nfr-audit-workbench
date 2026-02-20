# .NET Runtime & Async Rules – Team Guide

## Summary

This ruleset focuses on **.NET runtime safety, async correctness, and reliability under load**.

These rules help us avoid:
- thread-pool starvation
- deadlocks
- unhandled exceptions
- runaway background work
- unresponsive shutdowns

⚠️ These are **runtime behavior rules**, not business-logic rules.  
Many findings are **context-dependent** and require engineering judgment.

---

## How to Read These Rules

Before acting on a finding, ask:
1. Is this code on a **request path**, **background job**, or **startup/migration path**?
2. Can this code run **concurrently**?
3. Does this code block threads or ignore cancellation?

---

# Rule-by-Rule Explanation

---

## 🔹 NFR-DOTNET-001 – HttpClient call without CancellationToken

**What this rule detects**
- `HttpClient.GetAsync / SendAsync / PostAsync` without a `CancellationToken`

**Why this rule exists**
Without cancellation:
- requests keep running after clients disconnect
- shutdowns hang
- resources are wasted under load

**How to treat findings**
- Mandatory for request paths
- Strongly recommended for background jobs
- Avoid “fixing” with `CancellationToken.None`

---

## 🔹 NFR-DOTNET-002 – Task.Delay without CancellationToken

**What this rule detects**
- `Task.Delay(...)` without cancellation

**Why this rule exists**
Delays without cancellation:
- prevent graceful shutdown
- keep threads alive unnecessarily

**How to treat findings**
- Always pass a token if delay is interruptible
- Acceptable only in one-time startup code

---

## 🔹 NFR-DOTNET-003 – Blocking async with `.Result`

**What this rule detects**
- `.Result` on async tasks

**Why this rule exists**
Blocking async calls:
- can deadlock
- consume thread-pool threads
- reduce throughput

**How to treat findings**
- Replace with `await`
- Review carefully in legacy or startup code

---

## 🔹 NFR-DOTNET-003B – Blocking async with `.Wait()`

**What this rule detects**
- `.Wait()` on async tasks

**Why this rule exists**
Same risks as `.Result`, often worse:
- deadlocks
- starvation under load

**How to treat findings**
- Prefer async all the way
- Avoid mixing sync and async paths

---

## 🔹 NFR-DOTNET-004 – `async void` method

**What this rule detects**
- Methods declared as `async void`

**Why this rule exists**
`async void`:
- exceptions crash the process
- cannot be awaited or cancelled

**Correct usage**
- Event handlers only

**Severity**
🚨 Almost always a real bug

---

## 🔹 NFR-DOTNET-005 – Fire-and-forget task execution

**What this rule detects**
- `Task.Run(...)` without awaiting or tracking

**Why this rule exists**
Fire-and-forget tasks:
- hide failures
- outlive request context
- bypass cancellation

**How to treat findings**
- Track the task
- Add cancellation
- Consider background job frameworks

---

## 🔹 NFR-DOTNET-006 – Thread.Sleep usage

**What this rule detects**
- `Thread.Sleep(...)`

**Why this rule exists**
Thread.Sleep:
- blocks thread-pool threads
- kills scalability

**How to treat findings**
- Replace with `Task.Delay` + cancellation

---

## 🔹 NFR-DOTNET-007 – Long-running synchronous work on thread pool

**What this rule detects**
- CPU-bound or blocking work inside async methods

**Why this rule exists**
Long-running sync work:
- starves the thread pool
- delays unrelated requests

**How to treat findings**
- Offload to dedicated workers
- Break work into async chunks

---

## 🔹 NFR-DOTNET-008 – Missing ConfigureAwait in library code

**What this rule detects**
- `await` without `ConfigureAwait(false)` in non-UI libraries

**Why this rule exists**
Library code should not:
- capture synchronization context
- assume UI/thread affinity

**How to treat findings**
- Apply only to shared libraries
- Ignore in ASP.NET request handlers

---

## 🔹 NFR-DOTNET-009 – Task.Run used in ASP.NET request path

**What this rule detects**
- `Task.Run` inside request handling code

**Why this rule exists**
Spawning threads per request:
- bypasses ASP.NET scheduling
- increases latency and contention

**How to treat findings**
- Prefer async APIs
- Use background queues if needed

---

## 🔹 NFR-DOTNET-010 – Loop-triggered async operation

**What this rule detects**
- Awaited async calls inside loops

**Why this rule exists**
Sequential async loops:
- multiply latency
- often indicate batching opportunities

**Important**
- This rule is **generic**
- DB-specific amplification is handled elsewhere

---

## 🔹 NFR-DOTNET-011 – Async method without await

**What this rule detects**
- `async` methods that never `await`

**Why this rule exists**
Misleading async:
- exceptions behave unexpectedly
- adds overhead without benefit

**How to treat findings**
- Remove `async`
- Or introduce proper awaits

---

## 🔹 NFR-DOTNET-012 – Unobserved task exceptions

**What this rule detects**
- Tasks whose exceptions are never observed

**Why this rule exists**
Unobserved exceptions:
- crash the process
- hide failures until too late

---

## 🔹 NFR-DOTNET-013 – Timer without proper disposal

**What this rule detects**
- Timers not disposed or cancelled

**Why this rule exists**
Leaking timers:
- keep executing forever
- cause memory and CPU leaks

---

## 🔹 NFR-DOTNET-014 – Infinite or unbounded loops

**What this rule detects**
- Loops without clear exit conditions

**Why this rule exists**
Unbounded loops:
- cause runaway CPU usage
- are hard to debug in production

---

## 🔹 NFR-DOTNET-015 – Background task without shutdown hook

**What this rule detects**
- Long-running background work without cancellation

**Why this rule exists**
These tasks:
- block graceful shutdown
- corrupt state during redeploys

---

## 🔹 NFR-DOTNET-016 – Blocking I/O in async context

**What this rule detects**
- Sync file or network I/O inside async methods

**Why this rule exists**
Blocking I/O:
- negates async benefits
- reduces throughput

---

## 🔹 NFR-DOTNET-017 – Excessive Task.Run chaining

**What this rule detects**
- Nested or repeated `Task.Run`

**Why this rule exists**
Overuse of Task.Run:
- hides design problems
- complicates cancellation and tracing

---

## 🔹 NFR-DOTNET-018 – Missing timeout in async operations

**What this rule detects**
- Async calls without explicit timeouts

**Why this rule exists**
Without timeouts:
- failures hang indefinitely
- retries pile up

---

## 🔹 NFR-DOTNET-019 – Improper exception swallowing

**What this rule detects**
- Catch blocks that ignore exceptions

**Why this rule exists**
Silent failures:
- hide production issues
- prevent retries or alerts

---

## 🔹 NFR-DOTNET-020 – Async lambda capturing heavy context

**What this rule detects**
- Lambdas capturing large objects or services

**Why this rule exists**
Captured context:
- increases memory pressure
- prolongs object lifetimes

---

## 🔹 NFR-DOTNET-021 – Misuse of Parallel.ForEach

**What this rule detects**
- Parallel loops without bounds or cancellation

**Why this rule exists**
Unbounded parallelism:
- overloads CPU and DB
- destabilizes the system

---

## 🔹 NFR-DOTNET-022 – Improper task scheduling

**What this rule detects**
- Manual schedulers or misuse of TaskScheduler

**Why this rule exists**
Incorrect scheduling:
- leads to starvation
- breaks async assumptions

---

## Final Guidance to the Team

- These rules protect **runtime health**
- Fix **request-path issues first**
- Background and migration paths require context
- Prefer **async all the way**
- Cancellation is not optional at scale

> Healthy async code is boring — and that’s a good thing.