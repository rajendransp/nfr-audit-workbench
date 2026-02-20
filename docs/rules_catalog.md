# Rule Catalog

This catalog reflects the current JSON rule packs.

## Dotnet Rules (`rules/dotnet_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-DOTNET-001 | HttpClient call without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-002 | EF Core async query without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-003 | Blocking wait primitives in async-capable code | S2 | concurrency | 0.75 |
| NFR-DOTNET-003B | Task.Result on async call result | S3 | concurrency | 0.45 |
| NFR-DOTNET-004 | Thread.Sleep used | S2 | performance | 0.95 |
| NFR-DOTNET-005 | new HttpClient in code path | S2 | loading | 0.9 |
| NFR-DOTNET-006 | ExecuteSqlRaw without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-007 | High command timeout configured | S3 | loading | - |
| NFR-DOTNET-008 | Task.Delay without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-009 | Unbounded Parallel.ForEach | S2 | concurrency | - |
| NFR-DOTNET-010 | Potential N+1 query inside loop | S3 | loading | - |
| NFR-DOTNET-011 | async void method | S1 | concurrency | 0.95 |
| NFR-DOTNET-012 | Fire-and-forget background work pattern | S2 | concurrency | 0.55 |
| NFR-DOTNET-013 | Explicit CancellationToken.None | S2 | concurrency | 0.75 |
| NFR-DOTNET-014 | Empty catch block | S2 | loading | 0.8 |
| NFR-DOTNET-015 | Synchronous file read in request path | S2 | performance | - |
| NFR-DOTNET-016 | LINQ materialization before filtering | S3 | performance | - |
| NFR-DOTNET-017 | Large in-memory collection materialization | S3 | loading | 0.4 |
| NFR-DOTNET-018 | Missing pagination in query endpoint | S3 | loading | - |
| NFR-DOTNET-019 | Parallel.ForEachAsync without token | S2 | concurrency | - |
| NFR-DOTNET-020 | Read query without AsNoTracking | S4 | performance | - |
| NFR-DOTNET-021 | Synchronous JSON serialization in hot path (review) | S3 | performance | 0.55 |
| NFR-DOTNET-022 | Async call result not awaited or returned | S2 | concurrency | 0.7 |

## Frontend Rules (`rules/frontend_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-FE-001 | fetch call without AbortSignal | S3 | concurrency | 0.5 |
| NFR-FE-002 | Axios call without timeout | S2 | loading | 0.6 |
| NFR-FE-003 | setInterval without cleanup | S2 | concurrency | 0.6 |
| NFR-FE-004 | Unhandled promise chain | S2 | concurrency | 0.55 |
| NFR-FE-005A | Risky innerHTML/dangerouslySetInnerHTML from dynamic source | S1 | loading | 0.9 |
| NFR-FE-005B | innerHTML/dangerouslySetInnerHTML with static literal (review) | S3 | loading | 0.6 |
| NFR-FE-006 | Array index used as React key | S3 | performance | 0.85 |
| NFR-FE-007 | Potential heavy mapping in render path (review) | S3 | performance | 0.25 |
| NFR-FE-008 | No lazy loading for route components | S3 | loading | 0.45 |
| NFR-FE-009 | Image without lazy loading | S3 | loading | 0.75 |
| NFR-FE-010 | Frequent input handler without debounce/throttle | S3 | loading | 0.5 |
| NFR-FE-011 | console.log in app code | S4 | performance | 0.95 |
| NFR-FE-012 | Blocking synchronous Web Storage access in loop | S4 | performance | 0.25 |
| NFR-FE-013 | Unbounded list rendering without virtualization | S3 | loading | 0.35 |
| NFR-FE-014 | useEffect data fetch missing dependency array | S3 | concurrency | 0.55 |
| NFR-FE-015 | addEventListener in effect without cleanup | S2 | concurrency | 0.6 |
| NFR-FE-016 | Large bundle import anti-patterns | S3 | loading | 0.75 |

## AngularJS Migration Rules (`rules/angularjs_migration_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-FE-AJ-001 | AngularJS controller declaration in template | S2 | migration | 0.95 |
| NFR-FE-AJ-002 | AngularJS two-way binding with ng-model | S2 | migration | 0.95 |
| NFR-FE-AJ-003 | AngularJS scope object usage | S2 | migration | 0.9 |
| NFR-FE-AJ-004 | AngularJS module controller registration | S2 | migration | 0.95 |
| NFR-FE-AJ-005 | AngularJS directive with compile/link or replace:true | S1 | migration | 0.75 |
| NFR-FE-AJ-006 | AngularJS dynamic template compilation with $compile | S1 | migration | 0.95 |
| NFR-FE-AJ-007 | AngularJS list rendering without stable identity (ng-repeat track by) | S3 | migration | 0.8 |
| NFR-FE-AJ-008 | AngularJS router configuration (ngRoute/ui-router) | S2 | migration | 0.9 |
| NFR-FE-AJ-009 | AngularJS view placeholders in templates | S2 | migration | 0.9 |
| NFR-FE-AJ-010 | AngularJS filters in template expressions | S3 | migration | 0.7 |

## Combined Concurrency + DB Rules (`rules/combined_concurrency_db_ruleset.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-API-001 | Downstream/internal API call invocation with network indicators (inventory) | S2 | internal_api_invocation | - |
| NFR-DB-001 | DB invocation keywords with DB-specific indicators (inventory) | S2 | db_invocation | - |
| NFR-DB-002 | Raw SQL execution call | S2 | db_invocation | - |
| NFR-DB-004 | ADO.NET command execution (DB call inventory) | S2 | db_invocation | - |
| NFR-DB-003 | EF Core repository query invocation hotspot | S3 | db_invocation | - |
| NFR-TH-001 | Loop-triggered remote/DB call (thundering herd candidate) | S1 | thundering_herd | - |
| NFR-TH-002 | Timer-based polling with remote/DB call | S1 | thundering_herd | - |
| NFR-TH-005 | Task.WhenAll fan-out over remote/DB calls | S1 | thundering_herd | - |
| NFR-TH-006 | Parallel.ForEachAsync remote/DB call fan-out | S1 | thundering_herd | - |
| NFR-TH-007 | Task.WhenAll fan-out over internal service/client calls | S1 | thundering_herd | - |
| NFR-TH-008A | C# loop-triggered DB call (sequential loop-triggered execution / herd candidate) | S1 | thundering_herd | - |
| NFR-TH-008B | C# loop-triggered downstream/internal API call (herd candidate) | S1 | thundering_herd | - |
| NFR-HARD-001 | Unbounded Parallel.ForEachAsync / Task.WhenAll over dynamic collection (hardening) | S2 | concurrency_limits | - |
| NFR-HARD-002 | Cache-miss stampede candidate (cache get then set without coalescing hint) | S2 | cache_stampede | - |
| NFR-IO-LOOP-001 | Awaited file I/O inside loops (performance risk, not herd) | S2 | file_io_loop | - |
| NFR-TH-003 | High-frequency watcher/input network call without debounce | S2 | coalescing_candidate | - |
| NFR-TH-004 | GET call without explicit cache/coalescing hint | S2 | cache_candidate | - |

## Razor Rules (`rules/razor_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-RAZOR-001 | Large list rendering without Virtualize | S4 | loading | 0.35 |
| NFR-RAZOR-002 | Frequent @oninput handler without shaping | S4 | loading | 0.35 |
| NFR-RAZOR-003 | IJSRuntime call inside loop | S2 | concurrency | 0.6 |
| NFR-RAZOR-004 | Risky raw HTML rendering via MarkupString | S1 | loading | 0.8 |
| NFR-RAZOR-004B | Generic MarkupString raw HTML usage | S3 | loading | 0.5 |
| NFR-RAZOR-005 | Synchronous work in lifecycle method | S2 | performance | 0.65 |

## REST API Rules (`rules/rest_api_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence | Enforcement |
| --- | --- | --- | --- | ---:| --- |
| NFR-API-001 | Controller action missing CancellationToken | S2 | concurrency | 0.65 | review |
| NFR-API-002 | Large request body limit configured | S2 | loading | 0.9 | review |
| NFR-API-003 | No pagination on collection response | S3 | loading | 0.35 | review |
| NFR-API-004A | Manual JSON serialization used to build HTTP response | S3 | performance | 0.72 | review |
| NFR-API-004B | Mixed Newtonsoft/System.Text.Json serializer usage (contract drift risk) | S3 | performance | 0.6 | review |
| NFR-API-004C | JSON serialize→deserialize round-trip | S2 | performance | 0.7 | review |
| NFR-API-005 | Missing response caching hints on GET endpoint | S3 | loading | 0.65 | review |
| NFR-API-006 | Endpoint returns full entity directly | S3 | loading | 0.45 | review |
| NFR-API-007 | No request timeout policy in HttpClient registration | S2 | loading | 0.5 | review |
| NFR-API-008 | Retry policy without jitter/backoff | S2 | loading | 0.55 | review |
| NFR-API-009 | No [ApiController] on controller class | S4 | performance | 0.55 | review |
| NFR-API-010 | Bulk endpoint without max batch constraint | S2 | loading | 0.65 | review |
| NFR-API-011 | No rate limiting middleware configured | S2 | loading | 0.45 | review |
| NFR-API-012 | Endpoint reads request body synchronously | S2 | concurrency | 0.85 | review |
| NFR-API-013 | POST retry-sensitive endpoint missing idempotency key handling | S2 | concurrency | 0.55 | review |
| NFR-API-014 | File upload endpoint missing request size guard | S2 | loading | 0.7 | hard_fail |
| NFR-API-015 | Critical endpoint marked AllowAnonymous | S2 | authentication | 0.55 | review |
| NFR-API-016 | Controller CancellationToken not propagated to async service call | S2 | concurrency | 0.6 | review |

## Safe-AI Rules (`rules/safe_ai_rules.json`)

| Rule ID | Title | Severity | Safe-AI Risk |
| --- | --- | --- | --- |
| SAFE-AI-001 | Hardcoded secret literal | S1 | high |
| SAFE-AI-002 | JWT token literal | S1 | high |
| SAFE-AI-003A | Private key material | S1 | high |
| SAFE-AI-003B | Certificate block | S2 | medium |
| SAFE-AI-004 | Authorization header with literal token | S1 | high |
| SAFE-AI-005 | Authentication or token flow logic | S2 | medium |
| SAFE-AI-006 | Customer data transmitted or logged | S2 | medium |
| SAFE-AI-007 | Tenant isolation enforcement logic | S3 | low |
| SAFE-AI-008 | Infrastructure endpoint or connection literal | S2 | medium |
| SAFE-AI-009 | License validation or signature verification | S3 | low |
