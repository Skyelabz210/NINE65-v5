# CONSULTANT AUDIT

**Consultant**: Codex  
**Model**: gpt-5.3-codex  
**Timestamp**: 2026-02-11T02:14:28.591134  
**Project**: v5

## EXECUTIVE SUMMARY
The current plan is directionally strong but partially stale against the live codebase, which materially distorts priority and effort. Several “missing” items are already implemented (notably metrics/health enrichment and batch throughput benchmarks), while a major scalability risk is underweighted: global `SessionStore` write-locking around expensive FHE operations. A corrected plan should re-baseline completed work, elevate lock-architecture and abuse-control design, then proceed with Phase 2 API wiring.

## SYSTEM OVERVIEW
Based on `jobs/v5/CURRENT_CONTEXT_20260211_021422.md`, the intended system is a production-oriented split architecture: `crates/nine65` as the cryptographic engine and `crates/fhe-service` as the session-based HTTP boundary. The service currently supports session lifecycle plus encrypt/decrypt/evaluate flows (`crates/fhe-service/src/handlers.rs:40`, `crates/fhe-service/src/handlers.rs:44`, `crates/fhe-service/src/handlers.rs:58`), with planned expansion toward rotations, batch slot semantics, deeper presets, and production hardening.

## RIGOR & CORRECTNESS REVIEW
1. The plan contains stale factual claims that reduce decision quality.  
   Evidence: it marks “health metrics beyond basic `/healthz`” as missing (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:76`, `jobs/v5/CURRENT_CONTEXT_20260211_021422.md:500`), but `/v1/metrics` already exists with Prometheus output and health includes session/timestamp fields (`crates/fhe-service/src/handlers.rs:43`, `crates/fhe-service/src/handlers.rs:94`, `crates/fhe-service/src/handlers.rs:117`).

2. Benchmark gap classification is partially incorrect.  
   Evidence: plan says batch encoding throughput is missing (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:19`, `jobs/v5/CURRENT_CONTEXT_20260211_021422.md:146`), but `throughput.rs` already benchmarks batch encode/decode across sizes (`crates/nine65/benches/throughput.rs:13`, `crates/nine65/benches/throughput.rs:22`, `crates/nine65/benches/throughput.rs:35`).

3. The readiness score and timeline are therefore not internally reliable.  
   Evidence: checklist marks “Health metrics ❌” and uses that in a 2/14 score (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:670`, `jobs/v5/CURRENT_CONTEXT_20260211_021422.md:679`), despite implemented metrics endpoints.

4. Security-positioning is inconsistent with repository posture.  
   Evidence: plan labels core “UNDENIABLE” for production (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:686`), while current top-level guidance says pre-production and recommends `secure_192` minimum evaluation configuration (`README.md:23`, `README.md:24`).

5. `allow_insecure` hardening recommendation is valid but should integrate existing guards, not treat as greenfield.  
   Evidence: current code already has release-mode runtime safety assertions (`crates/nine65/src/params/secure_configs.rs:241`, `crates/nine65/src/params/secure_configs.rs:261`), but no compile-time `compile_error!` barrier.

## FUNCTIONAL & SCALABILITY ANALYSIS
Strengths:
- HTTP ingress has practical DoS guardrails: body/header limits and connection caps (`crates/fhe-service/src/http.rs:10`, `crates/fhe-service/src/http.rs:14`, `crates/fhe-service/src/main.rs:27`, `crates/fhe-service/src/main.rs:67`).
- Service exposes baseline operational telemetry (`crates/fhe-service/src/handlers.rs:117`).
- Core gaps identified by plan around rotations/batching/deep presets are mostly real (`crates/fhe-service/src/wire.rs:113`, `crates/fhe-service/src/session.rs:65`, `crates/fhe-service/src/handlers.rs:296`).

Primary bottleneck (underweighted in plan):
- `SessionStore` uses one `RwLock<HashMap<...>>` and executes expensive encrypt/decrypt/evaluate work inside `with_session_mut`, holding the global write lock (`crates/fhe-service/src/session.rs:163`, `crates/fhe-service/src/session.rs:196`, `crates/fhe-service/src/handlers.rs:204`, `crates/fhe-service/src/handlers.rs:279`).  
- This serializes mutating FHE requests across all sessions, directly limiting throughput and invalidating aggressive concurrency assumptions.

Trade-offs:
- TTL/reaper is useful, but impact is moderated by `max_sessions` admission control (`crates/fhe-service/src/session.rs:21`, `crates/fhe-service/src/session.rs:178`).  
- A naive background reaper thread (as proposed) can add lock contention and lifecycle complexity if introduced before lock architecture is fixed.

## UTILITY & DESIGN INTEGRITY
- API/documentation drift is present and will increase integration risk. `fhe-service` README still advertises old `/v1/fhe/*` endpoints (`crates/fhe-service/README.md:8`, `crates/fhe-service/README.md:9`) while code routes through `/v1/sessions/*` (`crates/fhe-service/src/handlers.rs:44`, `crates/fhe-service/src/handlers.rs:66`).
- Current wire schema is clear but not evolution-ready for planned Phase 2 additions (rotations, batch mode, TTL, deep presets); versioning strategy is absent (`crates/fhe-service/src/wire.rs:16`, `crates/fhe-service/src/wire.rs:51`, `crates/fhe-service/src/wire.rs:80`).
- The plan focuses on feature wiring, but production utility also depends on operator trust surfaces (auditable actor identity, quota semantics, SLO metrics), which are currently underspecified.

## PRIORITIZED RECOMMENDATIONS
1. Re-baseline the active plan immediately with evidence links.  
   Remove already-complete items (`/v1/metrics`, health enrichment, batch throughput bench), then recompute score/effort.

2. Promote `SessionStore` lock redesign to top priority before Phase 2 endpoint expansion.  
   Move to per-session locking (e.g., `HashMap<SessionId, Arc<RwLock<Session>>>` or sharded map) so expensive FHE ops do not hold a global write lock.

3. Redefine production hardening scope as “abuse control + identity + lifecycle,” not only TTL.  
   Add authenticated actor context, session-create throttling, per-session and per-origin quotas, and structured audit logs.

4. Treat TTL/reaper as part of lifecycle policy, not a standalone thread patch.  
   Implement explicit policy (`ttl`, `idle_timeout`, cap-based eviction), plus deterministic cleanup triggers and testable invariants.

5. Add API evolution guardrails before introducing batch/rotation/deep config fields.  
   Define versioned request schema and compatibility rules to avoid breaking existing clients.

6. Align readiness gates with current repo posture.  
   Incorporate `README.md` pre-production constraints and `secure_192` minimum guidance into acceptance criteria.

7. Expand observability from “endpoint existence” to “operational utility.”  
   Add per-operation latency histograms, lock-wait/queue metrics, session churn, and noise-budget distribution metrics.

8. Close documentation drift as a release blocker.  
   Update `crates/fhe-service/README.md` to current endpoints and behaviors to prevent integration errors.

## RAW OBSERVATIONS
- The current plan correctly identifies missing Galois/rotation exposure and deep-config wiring (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:313`, `jobs/v5/CURRENT_CONTEXT_20260211_021422.md:405`), but omits a concrete migration path for client semantics.
- “10K concurrent sessions” as a phase gate (`jobs/v5/CURRENT_CONTEXT_20260211_021422.md:655`) is not credible without first changing the lock model and likely the thread-per-connection runtime model (`crates/fhe-service/src/main.rs:76`).
- `HttpRequest.headers` appears effectively unused by handlers today (`crates/fhe-service/src/http.rs:32`), consistent with low-priority cleanup.
