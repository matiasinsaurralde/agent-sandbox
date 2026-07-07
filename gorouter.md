# Go sandbox-router review

Review target: latest commit `685c080 feat: add Go sandbox-router (drop-in replacement for Python) (#838)`.

Scope reviewed:

- New Go router implementation under `sandbox-router/`.
- Router deployment manifests under `sandbox-router/deploy/`.
- Related load-test and build wiring where it affects operations.
- Python router behavior where the Go router claims drop-in or compatibility behavior.

This review focuses on security, performance, and code-smell/maintainability risks. It is intentionally written as a deep-dive triage document, not as a patch proposal.

## Executive summary

The Go router is a substantial improvement in structure and operational maturity compared with a small ad hoc proxy: the code has clear package boundaries, bounded metric cardinality, a hardened distroless image, careful proxy header handling, a Kubernetes informer cache, TLS support, Prometheus and OTel integration, graceful shutdown, and a useful smoke-test harness.

The highest-risk issues are concentrated in four areas:

1. **Authorization posture is permissive by default.** The binary defaults to `--authz-mode=allow-all` and the example Deployment applies plain HTTP, cache enabled, and no auth flags. This is a sharp behavioral difference from the Python router, which refuses to start without a token unless unauthenticated mode is explicitly requested.
2. **The UID cache fast path does not bind the cached UID to the requested sandbox ID and namespace.** A request with a known `X-Sandbox-UID` can route to the cached Pod IP even if `X-Sandbox-ID` and `X-Sandbox-Namespace` do not match the cached entry.
3. **Drop-in compatibility is incomplete.** The Go router ignores `X-Sandbox-Timeout`, returns 502 for upstream timeouts instead of Python's 504, and has a different auth model.
4. **Backpressure and resource controls are mostly delegated to the edge.** There is no default body limit, no connection/RPS limiter, long-lived upgraded connections are uncapped, and TokenReview is synchronous on cache misses.

Recommended priority:

- P0: fix UID/name/namespace binding on cache hits and add tests.
- P0: document or change production auth defaults; avoid presenting the default Deployment as production-safe.
- P1: implement Python timeout/status parity (`X-Sandbox-Timeout`, 504 for upstream timeouts).
- P1: add body/connection/rate-limit guidance or configurable limits.
- P1: wire integration/smoke tests into CI for WebSocket, TLS/mTLS, cache invalidation, and TokenReview paths.

## Security findings

### S1. Default authorization is `allow-all`

Severity: Critical for shared or multi-tenant deployments.

References:

- `sandbox-router/config/config.go:176-194` sets `AuthzMode: AuthzAllowAll`.
- `sandbox-router/cmd/main.go:193-209` wires `authz.AllowAll{}` unless `--authz-mode=tokenreview` is set.
- `sandbox-router/deploy/deployment.yaml:57-70` starts plain HTTP and enables cache, but does not enable TokenReview or TLS.
- `clients/python/agentic-sandbox-client/sandbox-router/sandbox_router.py:113-128` refuses to start without `ROUTER_AUTH_TOKEN` unless `ALLOW_UNAUTHENTICATED_ROUTER` is explicitly true.

Impact:

Any caller that can reach the router proxy port can route to a named sandbox by supplying `X-Sandbox-ID` and optionally `X-Sandbox-Namespace`, `X-Sandbox-Pod-IP`, `X-Sandbox-UID`, and `X-Sandbox-Port`. In a cluster where the router Service or NetworkPolicy is reachable from multiple tenants, this becomes a cross-tenant internal proxy.

This is especially risky because the feature is described as a drop-in replacement for the Python router. The Python router has a fail-closed startup posture for auth; the Go router does not.

Recommendation:

- Make production examples use `--authz-mode=tokenreview --authz-tokenreview-require-token=true`.
- Split deployment examples into explicit `dev` and `production` variants.
- Consider a fail-closed startup option mirroring Python: require either configured auth or an explicit `--allow-unauthenticated` flag.
- If static-token parity is needed for migration, add a static bearer-token authorizer instead of treating `allow-all` as Python-compatible.

### S2. UID cache fast path does not verify sandbox ID and namespace

Severity: Critical.

References:

- `sandbox-router/proxy/resolve.go:78-82` looks up `t.UID` and uses `e.PodIP`.
- `sandbox-router/cache/cache.go:72-84` stores `SandboxName` and `Namespace` in the cache entry, but `Resolve` does not compare them with the request target.

Impact:

The cache key is the caller-supplied `X-Sandbox-UID`. If an attacker learns a victim sandbox UID, they can supply:

```http
X-Sandbox-ID: attacker-or-anything
X-Sandbox-Namespace: attacker-or-anything
X-Sandbox-UID: <victim-sandbox-uid>
```

The router will dial the cached victim Pod IP. With the default `AllowAll` authorizer, this is a direct cross-sandbox routing bug. Even with TokenReview enabled, TokenReview currently authenticates the caller but does not authorize access to a specific sandbox, so any authenticated caller can still reach any cached sandbox by UID.

Recommendation:

- On cache hit, require `e.SandboxName == t.ID && e.Namespace == t.Namespace`.
- If the tuple does not match, return a 403 or treat it as an invalid/mismatched route rather than silently falling back.
- Add unit tests for:
  - matching UID/name/namespace cache hit;
  - mismatched name;
  - mismatched namespace;
  - cache miss fallback behavior.
- Consider validating `X-Sandbox-UID` format before lookup.

### S3. TokenReview authenticates but does not authorize per sandbox

Severity: High.

References:

- `sandbox-router/authz/tokenreview.go:82-89` explicitly documents that v1 does not authorize against a per-sandbox identity.
- `sandbox-router/authz/tokenreview.go:156-218` validates or caches the token decision, then permits any authenticated token.

Impact:

Any valid Kubernetes bearer token becomes a cluster-wide sandbox-router credential. If a tenant can obtain a ServiceAccount token from any namespace and reach the router, that token can authenticate successfully and then access arbitrary sandboxes by name or UID.

Recommendation:

- Add a SubjectAccessReview, owner-label, claim-owner, or namespace-scoped authorization layer.
- At minimum, document TokenReview as authentication-only and not a tenant isolation boundary.
- Consider denying cross-namespace routing unless the token is authorized for a router-specific verb or resource in the target namespace.

### S4. `X-Sandbox-Pod-IP` remains an SSRF surface

Severity: High when auth is disabled or broad.

References:

- `sandbox-router/proxy/headers.go:114-121` accepts client-supplied Pod IPs after validation.
- `sandbox-router/proxy/headers.go:189-202` rejects loopback unless explicitly allowed, link-local, multicast, and unspecified addresses, but allows RFC1918, ULA, public, node, and service IPs.

Impact:

The validation blocks the most dangerous address classes, including loopback and cloud metadata endpoints, which is good. However, a caller can still point the router at non-sandbox routable IPs allowed by cluster egress policy. With `allow-all`, this can turn the router into a cluster-internal relay to private services.

Recommendation:

- Treat direct Pod-IP routing as a trusted-client fast path, not a general public interface.
- Add optional `--pod-ip-allow-cidrs` or require that Pod IPs match the cache entry for the claimed UID/name/namespace.
- Keep NetworkPolicy egress constrained to sandbox pods and ports where possible.

### S5. mTLS identity is not used by authorization

Severity: High for operators assuming mTLS is sufficient.

References:

- `sandbox-router/tlsutil/config.go` configures TLS/mTLS.
- `sandbox-router/authz/identity.go` provides identity extraction helpers.
- `sandbox-router/proxy/proxy.go:128-145` calls the configured authorizer, but the shipped authorizers do not consume TLS identity.

Impact:

`--mtls-mode=required` verifies that clients present a certificate from a trusted CA, but the application-layer authorization decision is still either `AllowAll` or Bearer TokenReview. There is no shipped authorizer that maps client certificate identity to sandbox access.

Recommendation:

- Clarify docs: mTLS is transport authentication, not per-sandbox authorization.
- Add an mTLS authorizer or composite authorizer if certificate identity is intended to be part of access control.
- If mTLS is used only at a Gateway, document where authorization is enforced.

### S6. Deployment manifests are not production-hardened by default

Severity: High if applied verbatim.

References:

- `sandbox-router/deploy/deployment.yaml:57-70` uses plain HTTP, no auth flags, cache enabled.
- `sandbox-router/deploy/networkpolicy.yaml:22-28` allows ingress to the proxy from every namespace.
- `sandbox-router/deploy/rbac.yaml:48-50` grants cluster-wide pod `get/list/watch`.

Impact:

Applying the example manifests creates a highly available unauthenticated internal proxy. Cache RBAC is intentionally broad because sandboxes may live in many namespaces; if the router ServiceAccount token is compromised, the grant permits pod metadata reads beyond sandbox pods even though the informer uses label selectors at runtime.

Recommendation:

- Make the default manifest clearly development-only or secure it by default.
- Restrict NetworkPolicy ingress to a Gateway namespace and selector.
- Prefer namespace-scoped Roles for deployments that only route one or a known set of namespaces.
- Pin images by digest in production examples.

### S7. Auth errors can leak infrastructure details

Severity: Medium.

References:

- `sandbox-router/authz/tokenreview.go:189-198` wraps TokenReview API errors.
- `sandbox-router/authz/tokenreview.go:223-226` returns cached wrapped TokenReview errors.
- `sandbox-router/proxy/proxy.go:134-145` returns `err.Error()` in the JSON response body.

Impact:

TokenReview API failures can expose apiserver connectivity or error details to callers as HTTP 500 `detail` strings.

Recommendation:

- Return stable client messages for non-sentinel authorization errors, such as `"Authorization service unavailable."`.
- Log the wrapped internal error server-side only.

### S8. Metrics endpoint is unauthenticated

Severity: Medium.

References:

- `sandbox-router/cmd/main.go:257-268` registers a separate metrics listener.
- `sandbox-router/deploy/networkpolicy.yaml:32-39` restricts metrics to a `monitoring` namespace, but this is only an example.

Impact:

Metrics can disclose namespaces, request rates, auth decisions, retry/error reasons, version/build data, and operational behavior. The metric labels are low-cardinality and intentionally avoid sandbox IDs, but the endpoint still needs network protection.

Recommendation:

- Bind metrics to localhost when scraped through a sidecar, or protect it with NetworkPolicy/kube-rbac-proxy.
- Document that metrics are operationally sensitive.

## Performance and scalability findings

### P1. No cap on long-lived upgraded connections

Severity: High.

References:

- `sandbox-router/proxy/proxy.go:248-262` skips the per-request timeout for protocol upgrades.
- `sandbox-router/proxy/proxy.go:265-276` treats any `Connection: Upgrade` plus `Upgrade` header as an upgrade.

Impact:

WebSockets and other upgrades can remain open indefinitely. Each active upgraded connection holds inbound and upstream sockets, goroutines, memory, and an inflight request metric until disconnect. A small number of heavy IDE/browser sessions can consume file descriptors or memory before CPU-based autoscaling reacts.

Recommendation:

- Add configurable maximum concurrent upgraded connections per pod.
- Add optional idle/read deadlines for upgraded connections where compatible.
- Expose a separate active-upgrades metric rather than relying on HTTP inflight request counts.
- Document required edge connection limits for production.

### P2. No default request body limit

Severity: High.

References:

- `sandbox-router/config/config.go:98-100` says `MaxRequestBodyBytes` defaults to unlimited.
- `sandbox-router/config/config.go:176-194` does not set a non-zero default.
- `sandbox-router/cmd/main.go:252-254` applies `limitBody` only when the configured value is greater than zero.

Impact:

Large uploads can consume bandwidth and proxy resources until the upstream or edge rejects them. The router does stream bodies, but unbounded request size is still a denial-of-service risk for router pods and sandboxes.

Recommendation:

- Set a conservative production default or set `--max-request-body-bytes` in production manifests.
- Enforce matching body limits at Gateway/Envoy.
- Return JSON errors for body-limit violations to preserve the router error contract.

### P3. No inbound connection or RPS backpressure

Severity: High.

References:

- `sandbox-router/server/server.go` creates standard HTTP servers.
- There is no `LimitListener`, token bucket, max-connection setting, or per-tenant throttling in the router.

Impact:

Under bursts, retries, or malicious traffic, the process accepts work until kernel limits, memory, upstream sandboxes, or apiserver TokenReview capacity become the limiting factor.

Recommendation:

- Add configurable listener connection limits or middleware throttles.
- Provide an HPA and edge-rate-limit example.
- Alert on inflight requests, active upgrades, retry rate, upstream errors, and TokenReview latency/failure rate.

### P4. Synchronous TokenReview on the hot path

Severity: High when `--authz-mode=tokenreview` is enabled.

References:

- `sandbox-router/authz/tokenreview.go:170-218` performs a synchronous TokenReview call on cache misses.
- `sandbox-router/config/config.go:191-193` defaults TokenReview cache TTL to 30 seconds and size to 2048.

Impact:

Request latency and apiserver load scale with unique token cardinality. In workloads using many short-lived projected tokens, the LRU cache can churn, and cache misses block request goroutines on the API server. There is no singleflight coalescing, so concurrent first requests for the same token can stampede.

Recommendation:

- Add singleflight by token hash.
- Tune cache size/TTL based on tenant and token cardinality.
- Separate TokenReview timeout and proxy timeout budgets in docs and dashboards.
- Load-test TokenReview with realistic unique-token rates.

### P5. A new `httputil.ReverseProxy` is allocated for every request

Severity: Medium.

References:

- `sandbox-router/proxy/proxy.go:162-246` constructs a new `ReverseProxy` and closures per request.
- `sandbox-router/proxy/proxy.go:77-106` correctly reuses the underlying transport.

Impact:

At high RPS, per-request proxy object and closure allocation adds avoidable GC pressure. This is not likely to dominate initially, but it is a low-level hot-path cost in a router whose README cites high loopback throughput.

Recommendation:

- Hoist a shared `ReverseProxy` onto `Handler` and carry target data through context or a request wrapper.
- Add benchmarks before/after to validate allocation and latency impact.

### P6. Upstream connection pool defaults may be too small for many sandbox hosts

Severity: Medium.

References:

- `sandbox-router/proxy/proxy.go:293-306` sets `MaxIdleConns: 200` and `MaxIdleConnsPerHost: 16`.

Impact:

The router fans out to one host per sandbox, whether using DNS names or Pod IPs. In clusters with thousands of active sandboxes, the global idle connection cap can evict connections aggressively, increasing TCP handshakes, CPU, and latency.

Recommendation:

- Make pool sizes configurable.
- Provide sizing guidance for large fleets and WebSocket-heavy workloads.
- Consider separate deployment profiles for low-RPS/high-fanout versus high-RPS/hot-sandbox patterns.

### P7. Default retries can amplify failure load

Severity: Medium.

References:

- `sandbox-router/config/config.go:187-189` defaults to three additional retries.
- `sandbox-router/proxy/proxy.go:293-306` sets a 30 second dial timeout.
- `sandbox-router/deploy/deployment.yaml:62-65` uses the default retry budget.

Impact:

Requests to missing, cold, or network-blocked sandboxes can tie up goroutines and multiply DNS/network load. Retry behavior is dial-only, which avoids duplicate request-body side effects, but a broad outage can still produce retry storms.

Recommendation:

- Tune retries and dial timeout together.
- Add alerts on `sandbox_router_upstream_retries_total`.
- Consider lower production defaults where sandboxes are expected to be ready before routing.

### P8. WebSocket metrics can distort latency and inflight signals

Severity: Medium.

References:

- `sandbox-router/observability/metrics.go:131-154` measures duration around the full handler lifetime.
- `sandbox-router/proxy/proxy.go:248-262` allows upgraded connections to live beyond `ProxyTimeout`.

Impact:

Long-lived WebSockets inflate request-duration histograms and inflight gauges. A p99 request duration might represent session length rather than HTTP latency, and inflight counts may represent connected editors rather than active request pressure.

Recommendation:

- Track upgrade handshake duration separately from upgraded connection lifetime.
- Add active-upgrade gauges.
- Document how to interpret metrics when routing browser IDE or notebook traffic.

### P9. Access logging is enabled by default

Severity: Medium at high RPS.

References:

- `sandbox-router/config/config.go:124-126` defines access logging.
- `sandbox-router/config/config.go:190` defaults `AccessLog` to true.
- `sandbox-router/cmd/main.go:240-246` wraps the proxy with access logging when enabled.

Impact:

One structured log line per proxied request can become the bottleneck at high request rates and may significantly increase logging cost. Logs also contain sandbox identifiers and routing metadata that should be treated as operationally sensitive.

Recommendation:

- Default access logs off in high-RPS production examples or sample at the edge.
- Document expected log volume and privacy considerations.

### P10. Cache informer resync and deployment cache default need sizing guidance

Severity: Medium.

References:

- `sandbox-router/cache/cache.go:63-66` uses a 10 minute informer resync.
- `sandbox-router/deploy/deployment.yaml:66-70` enables cache by default.
- `sandbox-router/cmd/main.go:179-190` gates startup on initial cache sync.

Impact:

The cache is useful for fast Pod-IP routing, but it adds apiserver LIST/WATCH traffic and memory proportional to sandbox pod count. Large clusters can experience startup and periodic resync spikes. If SDKs do not send `X-Sandbox-UID`, the cache adds cost without benefit for those requests.

Recommendation:

- Keep cache opt-in for production unless SDKs are sending UIDs.
- Add `--cache-resync-period` if operators need to tune relist cadence.
- Document expected memory/API-server cost per sandbox count.

## Code smell, compatibility, and maintainability findings

### C1. `X-Sandbox-Timeout` is missing

Severity: High compatibility risk.

References:

- Python router parses `X-Sandbox-Timeout` in `clients/python/agentic-sandbox-client/sandbox-router/sandbox_router.py:67-91` and applies it in `:203-220`.
- Go router applies only `h.cfg.ProxyTimeout` in `sandbox-router/proxy/proxy.go:248-262`.
- `sandbox-router/proxy/headers.go:24-32` does not define a timeout header.

Impact:

SDK callers that rely on per-request timeout behavior lose that control when switching to the Go router. Requests that should fail quickly can consume router and sandbox resources up to the global proxy timeout.

Recommendation:

- Parse `X-Sandbox-Timeout` as a finite positive duration in seconds.
- Cap it to `--proxy-timeout` like Python.
- Apply it only to non-upgrade requests.
- Add parity tests covering valid, invalid, non-finite, negative, zero, and excessive values.

### C2. Upstream timeouts return 502 instead of Python's 504

Severity: High compatibility risk.

References:

- Python returns 504 for `httpx.TimeoutException` in `clients/python/agentic-sandbox-client/sandbox-router/sandbox_router.py:243-249`.
- Go router classifies timeouts in `sandbox-router/proxy/proxy.go:318-340`, but the `ErrorHandler` always returns 502 in `:215-244`.

Impact:

Clients, tests, dashboards, and alerting rules that distinguish backend unavailable (502) from backend timeout (504) will misclassify failures after migration.

Recommendation:

- In `ErrorHandler`, map `context.DeadlineExceeded` and `net.Error.Timeout()` to HTTP 504.
- Preserve the Python-shaped JSON detail: `"Timed out waiting for the backend sandbox: <id>"`.
- Add an integration test with a slow upstream.

### C3. Error contract for body limit is not JSON

Severity: Medium.

References:

- `sandbox-router/cmd/main.go:342-349` wraps the body with `http.MaxBytesReader`.

Impact:

When the body limit is enabled and exceeded, the default stdlib behavior can produce a plain-text 413 rather than the router's `{"detail": ...}` JSON error format.

Recommendation:

- Add middleware that catches `*http.MaxBytesError` and calls `proxy.WriteJSONError`.
- Add tests for status code, content type, and body shape.

### C4. Integration tests are not part of the default unit-test path

Severity: Medium.

References:

- Several router integration tests use the `integration` build tag.
- Project docs say `make test-unit` is the standard unit path.

Impact:

The highest-risk paths - WebSockets, TLS/mTLS, cache invalidation, retry behavior, and listener integration - can regress without failing the default presubmit if integration tags are not run elsewhere.

Recommendation:

- Add a `make test-sandbox-router-integration` target or include `go test -tags=integration ./sandbox-router/...` in a presubmit.
- Keep slower kind smoke tests separate if needed, but run in-process integration tests by default if they are not too expensive.

### C5. `loadRESTConfig` precedence is security-relevant but untested

Severity: Medium.

References:

- `sandbox-router/cmd/main.go:311-340` documents and implements explicit kubeconfig, in-cluster config, and local fallback precedence.

Impact:

The comments correctly avoid falling back to local kubeconfig when in-cluster credentials are broken, which is security-sensitive behavior. Without tests, future changes could accidentally authenticate against the wrong cluster or obscure ServiceAccount mount errors.

Recommendation:

- Add table-driven tests using injectable `rest.InClusterConfig` and clientcmd loading hooks.
- Cover explicit kubeconfig, in-cluster success, `ErrNotInCluster` local fallback, and broken in-cluster credentials.

### C6. Cache package comments still describe an Envoy ext_proc design

Severity: Medium.

References:

- `sandbox-router/cache/cache.go:15-18` says the ext_proc handler reads the cache to drive Envoy's ORIGINAL_DST cluster.

Impact:

The implemented architecture is an in-process Go HTTP reverse proxy. The stale comment can mislead future maintainers about ownership boundaries and runtime architecture.

Recommendation:

- Rewrite the package comment to describe the informer-backed UID to Pod-IP map used by the Go reverse proxy.

### C7. Duplicated sandbox label constant

Severity: Medium.

References:

- `sandbox-router/cache/cache.go:54-61` duplicates `agents.x-k8s.io/sandbox-name-hash` because the controller constant is package-private.

Impact:

If the controller label changes, the router cache silently stops populating rather than failing at compile time.

Recommendation:

- Promote the label constant into a shared API or internal package imported by both controller and router.
- Add a test that validates cache selector constants against controller-owned labels if direct sharing is not possible.

### C8. Header canonical spellings differ from docs and SDKs

Severity: Low.

References:

- `sandbox-router/proxy/headers.go:27-31` uses `X-Sandbox-Id`, `X-Sandbox-Uid`, and `X-Sandbox-Pod-Ip`.
- Existing docs and SDKs commonly spell these as `X-Sandbox-ID`, `X-Sandbox-UID`, and `X-Sandbox-Pod-IP`.

Impact:

HTTP headers are case-insensitive, so this is not a functional bug. It does make grepping, documentation, log searches, and generated examples slightly confusing.

Recommendation:

- Align constants with the all-caps acronym spellings used by the SDKs and docs.

### C9. SDKs may not use the UID cache fast path yet

Severity: Medium operational/ergonomics risk.

References:

- Router cache path requires `X-Sandbox-UID` (`sandbox-router/proxy/resolve.go:78-82`).
- Deployment enables cache by default (`sandbox-router/deploy/deployment.yaml:66-70`).

Impact:

If default SDK traffic does not include `X-Sandbox-UID`, the cache adds RBAC, informer, memory, and startup-sync costs without improving those requests. Operators may enable cache because the example does, but still route through DNS.

Recommendation:

- Extend SDKs to send Sandbox UID once available.
- Otherwise leave `--cache-enabled=false` in the default Deployment and make cache an explicit optimization.

### C10. NetworkPolicy and router port model are inconsistent

Severity: Medium.

References:

- `sandbox-router/proxy/headers.go:97-112` accepts any TCP port from 1 to 65535.
- `sandbox-router/deploy/networkpolicy.yaml:55-61` allows egress only to TCP 8888 for sandbox pods.

Impact:

Custom `X-Sandbox-Port` values will pass router validation but fail at the network layer, likely surfacing as retried dial failures and 502s.

Recommendation:

- Either restrict accepted ports by config or document that the NetworkPolicy example assumes only the default 8888.
- Provide a templated port list for deployments with multiple sandbox ports.

## Positive observations

The following design choices are strong and should be preserved:

- DNS label validation for sandbox ID and namespace before constructing upstream FQDNs (`sandbox-router/proxy/headers.go:81-95`, `:147-166`).
- Rejection of loopback, link-local, multicast, and unspecified Pod IPs by default (`sandbox-router/proxy/headers.go:168-202`).
- Stripping `Authorization` before forwarding to the sandbox (`sandbox-router/proxy/proxy.go:168-175`).
- Stripping inbound `X-Forwarded-For` before calling `SetXForwarded` to avoid client-supplied XFF poisoning (`sandbox-router/proxy/proxy.go:176-193`).
- Upstream transport intentionally ignores `HTTP_PROXY` / `HTTPS_PROXY` environment variables (`sandbox-router/proxy/proxy.go:278-292`).
- Shared upstream transport and dial-only retries avoid duplicate request bodies while preserving connection pooling (`sandbox-router/proxy/proxy.go:77-97`, `sandbox-router/proxy/proxy.go:293-306`).
- Metrics avoid per-sandbox labels and use namespace/status/method dimensions instead (`sandbox-router/observability/metrics.go:131-154`).
- TokenReview cache stores SHA-256 token hashes instead of raw bearer tokens (`sandbox-router/authz/tokenreview.go:245-252`).
- Cache informer uses server-side label and field selectors to reduce apiserver and memory load (`sandbox-router/cache/cache.go:119-131`).
- Container security context drops capabilities, runs non-root, uses read-only root filesystem, and sets RuntimeDefault seccomp (`sandbox-router/deploy/deployment.yaml:102-109`).
- Startup blocks on initial cache sync when cache is enabled, surfacing RBAC problems early (`sandbox-router/cmd/main.go:179-190`).
- The smoke-test harness exercises important behavior that should be promoted into automated gates over time.

## Suggested remediation backlog

### P0

- Bind cache hits to UID, sandbox name, and namespace; add regression tests.
- Make auth posture explicit in Deployment/docs; avoid production examples that start unauthenticated by default.

### P1

- Implement `X-Sandbox-Timeout` and 504 timeout parity with Python.
- Add body-size limits in production guidance and JSON error handling for 413.
- Add edge/backpressure guidance and metrics for active upgraded connections.
- Include integration-tagged router tests in CI or add a specific presubmit target.
- Sanitize non-sentinel authorization errors returned to clients.

### P2

- Add per-sandbox authorization beyond TokenReview authentication.
- Add singleflight for TokenReview cache misses.
- Make upstream transport pool sizes configurable.
- Reuse `httputil.ReverseProxy` or prove current allocation cost is acceptable with benchmarks.
- Promote duplicated labels into a shared package.
- Fix stale cache package comments.
- Align header constant spellings with docs and SDKs.
- Add SDK support for `X-Sandbox-UID` if cache is intended to be on by default.

## Bottom line

The Go sandbox-router is thoughtfully engineered and has a good foundation for production routing, but it should not yet be treated as a secure drop-in replacement without follow-up work. The immediate blockers are the cache UID binding bug, permissive auth defaults, and Python timeout/status compatibility gaps. After those are addressed, the next tranche should focus on backpressure, production manifests, and CI coverage for the integration paths that carry the most operational risk.
