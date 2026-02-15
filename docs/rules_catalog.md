# Rule Catalog

This catalog is generated from current JSON rule packs.

## Dotnet Rules (`rules/dotnet_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-DOTNET-001 | HttpClient call without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-002 | EF Core async query without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-003 | Blocking wait in async-capable code | S1 | concurrency | 0.50 |
| NFR-DOTNET-004 | Thread.Sleep used | S2 | performance | 0.95 |
| NFR-DOTNET-005 | new HttpClient in code path | S2 | loading | 0.90 |
| NFR-DOTNET-006 | ExecuteSqlRaw without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-007 | High command timeout configured | S3 | loading | - |
| NFR-DOTNET-008 | Task.Delay without CancellationToken | S2 | concurrency | - |
| NFR-DOTNET-009 | Unbounded Parallel.ForEach | S2 | concurrency | - |
| NFR-DOTNET-010 | Potential N+1 query inside loop | S3 | loading | - |
| NFR-DOTNET-011 | async void method | S1 | concurrency | 0.95 |
| NFR-DOTNET-012 | Fire-and-forget Task.Run | S2 | concurrency | - |
| NFR-DOTNET-013 | Explicit CancellationToken.None | S2 | concurrency | 0.75 |
| NFR-DOTNET-014 | Empty catch block | S2 | loading | - |
| NFR-DOTNET-015 | Synchronous file read in request path | S2 | performance | - |
| NFR-DOTNET-016 | LINQ materialization before filtering | S3 | performance | - |
| NFR-DOTNET-017 | Large in-memory collection materialization | S3 | loading | 0.40 |
| NFR-DOTNET-018 | Missing pagination in query endpoint | S2 | loading | - |
| NFR-DOTNET-019 | Parallel.ForEachAsync without token | S2 | concurrency | - |
| NFR-DOTNET-020 | Read query without AsNoTracking | S3 | performance | - |

## Frontend Rules (`rules/frontend_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-FE-001 | fetch call without AbortSignal | S2 | concurrency | 0.70 |
| NFR-FE-002 | Axios call without timeout | S2 | loading | 0.60 |
| NFR-FE-003 | setInterval without cleanup | S2 | concurrency | 0.55 |
| NFR-FE-004 | Unhandled promise chain | S2 | concurrency | 0.50 |
| NFR-FE-005A | Risky innerHTML/dangerouslySetInnerHTML source | S1 | loading | 0.90 |
| NFR-FE-005B | Generic innerHTML/dangerouslySetInnerHTML usage | S3 | loading | 0.55 |
| NFR-FE-006 | Array index used as React key | S3 | performance | 0.85 |
| NFR-FE-007 | Large synchronous loop in render path | S2 | performance | 0.35 |
| NFR-FE-008 | No lazy loading for route components | S3 | loading | 0.45 |
| NFR-FE-009 | Image without lazy loading | S3 | loading | 0.75 |
| NFR-FE-010 | Frequent input handler without debounce/throttle | S3 | loading | 0.50 |
| NFR-FE-011 | console.log in app code | S4 | performance | 0.95 |
| NFR-FE-012 | Blocking synchronous Web Storage access in loop | S4 | performance | 0.25 |
| NFR-FE-013 | Unbounded list rendering without virtualization | S3 | loading | 0.55 |
| NFR-FE-014 | useEffect data fetch missing dependency array | S2 | concurrency | 0.60 |
| NFR-FE-015 | addEventListener in effect without cleanup | S2 | concurrency | 0.60 |
| NFR-FE-016 | Large bundle import anti-patterns | S3 | loading | 0.75 |

## Razor Rules (`rules/razor_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence |
| --- | --- | --- | --- | ---:|
| NFR-RAZOR-001 | Large list rendering without Virtualize | S3 | loading | 0.50 |
| NFR-RAZOR-002 | Frequent @oninput handler without shaping | S3 | loading | 0.55 |
| NFR-RAZOR-003 | IJSRuntime call inside loop | S2 | concurrency | 0.60 |
| NFR-RAZOR-004 | Risky raw HTML rendering via MarkupString | S1 | loading | 0.80 |
| NFR-RAZOR-004B | Generic MarkupString raw HTML usage | S3 | loading | 0.50 |
| NFR-RAZOR-005 | Synchronous work in lifecycle method | S2 | performance | 0.65 |

## REST API Rules (`rules/rest_api_rules.json`)

| Rule ID | Title | Severity | Sub Category | Confidence | Enforcement |
| --- | --- | --- | --- | ---:| --- |
| NFR-API-001 | Controller action missing CancellationToken | S2 | concurrency | 0.65 | hard_fail |
| NFR-API-002 | Large request body limit configured | S2 | loading | 0.90 | review |
| NFR-API-003 | No pagination on collection response | S2 | loading | 0.50 | review |
| NFR-API-004 | Synchronous serialization/deserialization | S3 | performance | 0.80 | review |
| NFR-API-005 | Missing response caching hints on GET endpoint | S3 | loading | 0.65 | review |
| NFR-API-006 | Endpoint returns full entity directly | S3 | loading | 0.45 | review |
| NFR-API-007 | No request timeout policy in HttpClient registration | S2 | loading | 0.50 | hard_fail |
| NFR-API-008 | Retry policy without jitter/backoff | S2 | loading | 0.55 | review |
| NFR-API-009 | No [ApiController] on controller class | S3 | performance | 0.80 | review |
| NFR-API-010 | Bulk endpoint without max batch constraint | S2 | loading | 0.65 | review |
| NFR-API-011 | No rate limiting middleware configured | S2 | loading | 0.60 | review |
| NFR-API-012 | Endpoint reads request body synchronously | S2 | concurrency | 0.85 | review |
| NFR-API-013 | POST retry-sensitive endpoint missing idempotency key handling | S2 | concurrency | 0.55 | review |
| NFR-API-014 | File upload endpoint missing request size guard | S2 | loading | 0.70 | hard_fail |
| NFR-API-015 | Critical endpoint marked AllowAnonymous | S1 | loading | 0.80 | review |
| NFR-API-016 | Controller CancellationToken not propagated to async service call | S2 | concurrency | 0.60 | hard_fail |
