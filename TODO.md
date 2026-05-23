# CF Cloak TODO

Implementation plan to upgrade CF Cloak from a single-source suffix blocker into a multi-source tracker intelligence engine with two enforcement modes:

- Light (default): privacy-first, but biased toward not breaking login, checkout, playback, app startup, or core APIs.
- Extreme: block every matched tracker domain from enabled sources unless there is an explicit allow exception.

This plan is grounded in the code that already exists in this package:

- `src/index.ts` already provides suffix matching plus per-rule metadata.
- `src/policy.ts` already provides pure policy evaluation with temp allows and overrides.
- `src/signing.ts` already provides signed bundle delivery.

Because the app is not shipped yet, prefer replacing narrow v1 shapes over carrying compatibility baggage.

---

## Desired end state

- CF Cloak ingests multiple public tracker sources, normalizes them into one canonical ruleset, and signs the result.
- Light mode blocks only high-confidence tracker-only domains that are unlikely to be required for core functionality.
- Light mode still logs matched-but-allowed domains as `action=observed` with full source and confidence attribution.
- Extreme mode blocks all matched domains from enabled tracker sources except explicit allowlist and temporary unblock exceptions.
- The VPN service, web preview, and backend analytics all use the same canonical rule model and decision reasons.
- Breakage is measurable, rollback is one switch, and optional broad upstreams stay behind review gates.

---

## 1. Upstream source policy

- [x] Foundation: add a DuckDuckGo tracker JSON parser that can ingest `trackers`, `entities`, and `packageNames` from DDG's published data and emit metadata-only canonical rules plus owner/package indexes without treating DDG alone as a Light-mode block source.
- [x] Foundation: add an explicit upstream source catalog plus parser dispatch so OISD Small/Big, Blocklist Project Tracking, DuckDuckGo, and the review-gated optional sources are represented as first-class builder inputs with format, trust tier, review-gate, and Light/Extreme defaults.
- [x] Treat the following public sources as first-class inputs in the ruleset builder:

| Source | URL | Role | Light default use | Extreme default use |
| --- | --- | --- | --- | --- |
| OISD Small | https://small.oisd.nl | Primary aggregated DNS blocklist | Detection + high-confidence block candidate | Enabled |
| OISD Big | https://big.oisd.nl | Primary aggregated DNS blocklist with wider coverage | Detection + corroboration, not blind block | Enabled |
| DuckDuckGo tracker blocklists | https://github.com/duckduckgo/tracker-blocklists | Classification metadata for known tracker entities and domains | Metadata only unless corroborated | Metadata only |
| Blocklist Project Tracking | https://blocklistproject.github.io/Lists/tracking.txt | Additional tracking-domain source | Detection + corroboration | Enabled |

- [x] Add a review-only lane for optional high-signal upstreams referenced by IVPN AntiTracker Plus:

| Source | Review status | Notes |
| --- | --- | --- |
| 1Hosts | Review gate only | Broad coverage, likely overlap with OISD/HaGeZi |
| AdGuard DNS Filter | Review gate only | High utility but larger compatibility risk |
| HaGeZi | Review gate only | Strong coverage, but multiple aggression levels must not be mixed blindly |
| EasyList | Review gate only | Useful for attribution and corroboration, but browser/ad-tech bias needs DNS suitability review |
| Steven Black hosts | Review gate only | Broad hosts-style source; must be normalized carefully |

- [ ] Do not enable optional review-gate sources by default until each source passes all of the following:
  - overlap analysis versus OISD Small and OISD Big
  - false-positive review against auth, payments, media, captcha, and app API fixtures
  - license and redistribution check
  - freshness and maintenance check
  - unique incremental coverage above the primary set

- [x] Introduce per-source trust tiers:
  - Tier A: OISD Small, OISD Big
  - Tier B: Blocklist Project Tracking, DuckDuckGo classification metadata
  - Tier C: reviewed optional upstreams

---

## 2. Target architecture

- [ ] Split the upgrade into six concrete layers:

```text
upstream fetchers
  -> source-specific parsers
  -> canonical normalization
  -> source merge + dedupe
  -> confidence + compatibility scoring
  -> signed ruleset bundle
  -> client matcher + policy evaluator + DNS event log
```

- [x] Foundation: add `src/sources.ts` with mixed-format parsing for plain-domain, hosts, and common adblock-style inputs so OISD and Blocklist Project style text feeds can be normalized into canonical rule inputs before source-specific enrichers are layered on.
- [x] Foundation: add a pure `buildRulesetBundle()` pipeline that accepts upstream source snapshots, dispatches to the correct parser, merges the resulting canonical rules, and emits a ruleset payload with source-manifest hashes plus preserved source exceptions.

- [ ] Keep source ingestion and bundle build reusable from this package even if the scheduled job runs in Supabase or separate admin tooling.
- [ ] Move the package from "domain list with optional category/source" to "canonical rule objects with source attribution, confidence, and mode defaults".
- [ ] Replace the current domain-only signed payload with a signed ruleset bundle that includes:
  - canonical rules
  - source manifest and fetch timestamps
  - system allowlist and compatibility overrides
  - generation metadata and rollback metadata

- [ ] Suggested package surfaces to add or replace:
  - `src/sources/` for upstream parsers and manifest types
  - `src/ruleset.ts` for canonical rule types and merge logic
  - `src/compatibility.ts` for allowlist and critical-domain tagging
  - `src/policy.ts` upgraded for mode-aware decisions
  - `src/signing.ts` upgraded from `SignedBlocklist` to `SignedRuleset`

---

## 3. Canonical domain model

- [x] Foundation: add `src/ruleset.ts` with canonical rule types, hostname normalization, multi-source dedupe/merge, and exact-vs-suffix lookup so later policy and signing work has a stable local API.
- [x] Foundation: upgrade the legacy `RuleEntry`, `buildBlocklistDetailed()`, and `matchDomainDetailed()` helper surface to preserve richer canonical metadata (registrable domain, arrays, confidence, compatibility, and mode actions) while keeping `category` / `source` compatibility shorthands for existing callers.
- [ ] Replace the current single-source `RuleEntry` metadata shape with a richer canonical record.

```ts
export type SourceId =
  | 'oisd_small'
  | 'oisd_big'
  | 'ddg_tracker_blocklists'
  | 'blocklistproject_tracking'
  | '1hosts'
  | 'adguard_dns_filter'
  | 'hagezi'
  | 'easylist'
  | 'steven_black'

export type MatchScope = 'exact' | 'suffix'
export type ConfidenceTier = 'high' | 'medium' | 'review'
export type ModeAction = 'block' | 'observe'

export interface CanonicalRule {
  id: string
  domain: string
  matchScope: MatchScope
  registrableDomain: string | null
  sources: SourceId[]
  sourceCount: number
  categories: string[]
  entityNames: string[]
  confidenceTier: ConfidenceTier
  confidenceScore: number
  lightAction: ModeAction
  extremeAction: 'block'
  compatibilityTags: string[]
  reviewNotes: string[]
  firstSeenAt: string
  lastSeenAt: string
}
```

- [ ] Normalization rules:
  - lowercase every hostname
  - convert IDNs to punycode before storage and matching
  - strip trailing dots
  - parse hosts-style lines into final hostname tokens
  - reject comments, IP literals, localhost aliases, and invalid labels
  - reject TLD-only entries unless explicitly approved in an internal override list

- [ ] Wildcard and subdomain handling:
  - `*.example.com` normalizes to `example.com` with `matchScope='suffix'`
  - `tracker.example.com` stays exact if the source is host-specific
  - exact match beats suffix match at decision time
  - blocking `tracker.example.com` must never imply blocking `example.com`

- [ ] Deduplication and conflict resolution:
  - key rules by `matchScope + normalized domain`
  - merge all source IDs onto the same canonical rule
  - union categories and entity names
  - use the highest confidence score from corroborating evidence, not a naive average
  - if optional broad sources are the only evidence, set `confidenceTier='review'`
  - if DuckDuckGo metadata exists without a blocking-domain source, keep the domain as metadata-only and do not auto-block it in Light mode

---

## 4. Confidence and compatibility model

- [x] Foundation: derive confidence tier, confidence score, and Light-mode default action from source corroboration and compatibility tags so DDG-only entries stay metadata-only, OISD Small gains more weight when corroborated, and compatibility-tagged matches default to observe instead of block.
- [x] Foundation: add pure compatibility helpers that match exact or suffix allow/override entries, apply compatibility tags onto canonical rules, and force shipped Light-mode defaults to `observe` during bundle build whenever ChoiceFirst marks a domain as breakage-sensitive.
- [ ] Define Light-mode decisions from confidence and compatibility, not from raw source presence alone.

- [ ] Initial confidence rubric:

| Signal | Outcome |
| --- | --- |
| Present in OISD Small and classified by DuckDuckGo as a tracker | `high` |
| Present in OISD Small plus Blocklist Project Tracking | `high` |
| Present only in OISD Big | `medium` |
| Present only in Blocklist Project Tracking | `medium` |
| Present only in a reviewed optional source | `review` |
| DuckDuckGo metadata without a blocking-source match | metadata-only, not blockable in Light |

- [ ] Add compatibility tags maintained by ChoiceFirst, not by the upstreams:
  - `auth`
  - `payments`
  - `media_delivery`
  - `app_api`
  - `captcha`
  - `core_telemetry`
  - `reviewed_breakage`

- [ ] Light-mode default rule:
  - `high` confidence and no compatibility tag -> `block`
  - `medium` confidence and no compatibility tag -> `observe`
  - any confidence with a compatibility tag -> `observe`
  - `review` confidence -> `observe`

- [ ] Extreme-mode default rule:
  - any matched domain from an enabled tracker source -> `block`
  - system allowlist, user allowlist, and temporary unblocks still override the automatic block

- [ ] Build and maintain a system allowlist separate from upstream data.
  - This is not a "tracker is good" list.
  - This is a "blocking this breaks common flows or our own app" list.
  - Every entry must include a reason, owner, added date, and expiry/review date.

---

## 5. Policy model and precedence

- [x] Foundation: sync the TypeScript-facing app policy store and the Kotlin policy mirror on a shared Light/Extreme-aware schema so persisted policy JSON normalizes to the new default mode and Android can safely parse the updated shape before canonical rule actions are wired in at runtime.
- [x] Foundation: wire the app-to-Android VPN start path to stage optional signed-ruleset rule metadata natively, preserve exact-versus-suffix matching semantics in `DnsPacket`, and pass canonical `lightAction` / `extremeAction` into the Kotlin policy engine when signed rules are present while keeping legacy `domains[]` starts on the existing suffix-only path.
- [x] Foundation: make the pure TypeScript evaluator and ruleset runtime honor signed-ruleset `systemAllowlist` matches ahead of app/category automatic blocking while preserving matched-rule attribution and explicit `system_allowlist` event reasons.
- [x] Foundation: transport signed-ruleset `systemAllowlist` entries through the app start args into Android and apply them during live DNS/SNI policy evaluation instead of limiting that behavior to the pure test/runtime helpers.
- [x] Extend `src/policy.ts` so the active mode is explicit.

```ts
export type EnforcementMode = 'light' | 'extreme'
```

- [x] Upgrade `PolicyRequest` so evaluation can see the merged rule, not just a matched suffix.
- [ ] Keep the evaluator pure and deterministic so Android, web preview, and test fixtures stay aligned.

- [ ] Final precedence order:
  1. emergency temporary unblock
  2. user exact-domain allow/block override
  3. user suffix allow/block override
  4. system exact allowlist entry
  5. system suffix allowlist entry
  6. app-specific allow/block override
  7. mode-specific automatic action from the canonical rule
  8. unmatched domain -> allow

- [ ] Specific conflict rules:
  - exact override beats suffix override
  - allow and block on the same specificity resolve by newest write timestamp
  - if multiple canonical rules match, exact host beats suffix, then longest suffix wins
  - system allowlist never deletes source attribution; it only changes enforcement
  - `action=observed` must still carry every matched source and category

- [ ] Policy matrix:

| Situation | Light | Extreme |
| --- | --- | --- |
| Unmatched domain | Allow | Allow |
| High-confidence tracker-only match | Block | Block |
| Medium-confidence tracker match | Observe | Block |
| Review-only optional-source match | Observe | Block if source is enabled |
| Matched domain with compatibility allow tag | Observe | Allow only if explicit system/user allow exists |
| User explicit allow | Allow | Allow |
| User explicit block | Block | Block |
| Emergency temporary unblock | Allow until expiry | Allow until expiry |

---

## 6. Request-handling flow

- [x] Foundation: add a pure ruleset-runtime bridge that normalizes a hostname, looks up the matched canonical rule, converts it into a `PolicyRequest`, and evaluates Light versus Extreme behavior end to end without requiring Android or Supabase integration first.
- [x] Foundation: add a pure local-event bridge in `src/runtime.ts` that converts matched ruleset evaluations into deterministic `LocalDnsEvent` payloads, preserves `observed` versus `blocked` versus override/temp outcomes, and skips unmatched domains.
- [x] Foundation: add a pure DNS/SNI request bridge that extracts SNI hostnames from TLS ClientHello payloads and routes both DNS and SNI inputs through the same ruleset, policy, and local-event pipeline.
- [x] Use the same pipeline for DNS queries and SNI-derived hostname classification.
- [x] Always log matched domains even when the final action is allow.

```ts
function handleRequest(input: DnsOrSniRequest): DecisionWithEvent {
  const fqdn = normalizeHostname(input.hostname)
  const match = ruleset.lookup(fqdn)

  if (!match) {
    return allowWithoutRemoteLog({ fqdn, reason: 'unmatched' })
  }

  const request = {
    domain: fqdn,
    app: input.appId,
    mode: activeMode,
    match,
  }

  const decision = evaluate(request, policy, now)

  const event = {
    occurredAt: now,
    queryDomain: fqdn,
    matchedDomain: match.domain,
    matchScope: match.matchScope,
    action: mapDecisionToEventAction(decision),
    reason: decision.reason,
    mode: activeMode,
    sources: match.sources,
    categories: match.categories,
    confidenceTier: match.confidenceTier,
    compatibilityTags: match.compatibilityTags,
    blocklistVersion: ruleset.version,
  }

  writeLocalEvent(event)
  enqueueRemoteUpload(minimizeForServer(event))

  if (decision.action === 'block') {
    return synthesizeBlockedResponse(event)
  }

  return forwardAllowedRequest(event)
}
```

- [x] Event action mapping:
  - automatic block -> `blocked`
  - Light-mode allow on a matched rule -> `observed`
  - explicit allowlist override -> `allowed_override`
  - temporary unblock -> `allowed_temp`

---

## 7. Logging schema

- [x] Foundation: project canonical `confidenceTier` and `compatibilityTags` through the app's signed-ruleset start args into Android local event storage and the existing local Activity detail view so matched local rows no longer lose those fields after transport.
- [x] Foundation: preserve full canonical `sources[]`, `categories[]`, `blocklistVersion`, and `policyVersion` through the Android local event path and existing local Activity detail view instead of collapsing them to a single source/category or dropping the version context.
- [x] Foundation: surface local matched `blocked`, `observed`, `allowed_override`, and `allowed_temp` CF Cloak rows in the existing Activity list and filters so non-block local outcomes are no longer hidden behind a block-only merge path.
- [x] Foundation: preserve canonical `registrableDomain` and `matchScope` through the app projection, Android local event storage, Capacitor bridge, and existing local Activity detail view so the device log keeps the rule identity that produced each matched decision.
- [x] Foundation: preserve canonical `entityNames[]` through the app projection, Android matched-rule metadata, local event storage, Capacitor bridge, and existing local Activity detail view without lowercasing or lossy CSV flattening.
- [x] Foundation: preserve canonical `confidenceScore` and `reviewNotes[]` through the app projection, Android matched-rule metadata, local event storage, Capacitor bridge, and existing local Activity detail view instead of dropping the rule scoring and review context after bundle transport.
- [x] Foundation: replace the Android `log-blocked` pair queue with an explicit minimized remote event envelope (`matchedDomain`, optional `registrableDomain`, `occurredAt`) and make the backend `log-blocked` function accept that minimized shape while remaining backward compatible with legacy `{ domain, ts }` batches.
- [x] Foundation: move minimized remote blocked uploads into a dedicated `dns_events` table, keep legacy `access_log.access_type='blocked'` rows readable during the cutover, and merge both remote blocked sources in app history, summary, export, inventory, digest, and realtime refresh paths.
- [x] Split logging into two levels:
  - on-device detailed event log for recent UI and support/debugging
  - remote minimized analytics log for rule tuning and product metrics

- [x] Local event shape:

```ts
export interface LocalDnsEvent {
  id: string
  occurredAt: string
  hostname: string
  registrableDomain: string | null
  matchedDomain: string
  matchScope: MatchScope
  appId: string | null
  mode: EnforcementMode
  action: 'blocked' | 'observed' | 'allowed_override' | 'allowed_temp'
  reason: string
  sources: SourceId[]
  categories: string[]
  confidenceTier: ConfidenceTier
  compatibilityTags: string[]
  blocklistVersion: string
  policyVersion: number
}
```

- [x] Remote event shape should minimize sensitive detail:
  - keep `matchedDomain`
  - keep `registrableDomain`
  - do not upload raw full hostname by default
  - do not upload unmatched domains
  - do not upload IPs, URLs, paths, headers, or payloads
  - if deeper debugging is needed, gate it behind explicit user diagnostics consent

- [x] Standard decision reasons to persist:
  - `auto_block_light`
  - `auto_block_extreme`
  - `observed_light`
  - `user_override_allow`
  - `user_override_block`
  - `system_allowlist`
  - `temp_unblock`

---

## 8. Storage and indexing plan

- [ ] On-device storage:
  - [x] store recent detailed DNS events locally for UI, retry queueing, and support export
  - [x] retain raw local event rows for 7 days
  - [x] retain daily aggregates for 30 days
  - [x] cap the raw queue with a ring buffer so the VPN service cannot grow without bound

- [x] Local indexes:
  - [x] `(occurred_at desc)` for recency views
  - [x] `(action, occurred_at desc)` for blocked versus observed filters
  - [x] `(matched_domain, occurred_at desc)` for per-domain drill-down
  - [x] `(app_id, occurred_at desc)` for app-specific review

- [ ] Remote storage:
  - [x] create a dedicated `dns_events` table instead of overloading generic access logging
  - [x] add a `dns_event_daily` aggregate table or materialized view for the app dashboard
  - [ ] monthly partition `dns_events` by `occurred_at` from the start

- [ ] Remote indexes:
  - [x] btree `(user_id, occurred_at desc)`
  - [x] btree `(user_id, data_source_id, occurred_at desc)`
  - [x] btree `(matched_domain, occurred_at desc)`
  - [x] brin on `occurred_at` for large-range analytics
  - [ ] if the remote schema grows beyond minimized `dns_events`, revisit schema-specific indexes for any future `action`, `blocklist_version`, `sources`, or `categories` columns

- [ ] Remote upload policy:
  - [x] batch uploads every 30 to 60 seconds or when the queue reaches a threshold
  - [x] compress batches
  - [x] drop duplicate event IDs on ingest
  - [x] store the ruleset version with every row so rollback analysis is trivial

---

## 9. Signed ruleset and rollback

- [x] Foundation: add a typed `SignedRuleset` bundle in `src/signing.ts` with canonical JSON hashing for rules, source manifests, allowlists, compatibility overrides, and rollback metadata, while keeping the legacy blocklist signature helpers intact until runtime consumers migrate.
- [x] Foundation: add a one-step `buildSignedRulesetBundle()` helper so source snapshots can be parsed, merged, compatibility-adjusted, and Ed25519-signed in a single pure package call.
- [x] Foundation: make the app-side `generate-blocklist` consumer normalize either the legacy `{ domains[] }` payload or a future `signed_ruleset` payload into the same local blocklist shape so backend rollout can switch formats without a second client rewrite.
- [x] Foundation: have the Supabase `generate-blocklist` function emit a truthful transitional `signed_ruleset` built from `source_aliases` provenance when alias coverage fully matches the active `tracking_domains` set and a signing key is configured, while automatically falling back to the legacy company-domain bundle when provenance coverage or signing prerequisites are missing.
- [ ] Replace the transitional `source_aliases -> tracking_domains` signing path with the canonical `buildRulesetBundle()` output so hosted `generate-blocklist` can ship reviewed exact and suffix rules that do not already exist in the legacy `tracking_domains` set. This is the step where genuinely new blocking surfaces start landing.
- [x] Keep at least the last three signed ruleset versions available to clients.
- [x] Add source manifest metadata:
  - source name
  - source URL
  - fetch timestamp
  - content hash
  - parser version

- [x] Rollback rules:
  - [x] if signature verification fails, keep the last known-good ruleset
  - [x] if a newly downloaded ruleset is older than the installed version, reject it unless the server marks it as a rollback release
  - [x] support server-side kill switches for signed-ruleset source cohorts without rebuilding the app
  - [x] expose the installed ruleset version and source manifest in debug UI

- [x] Rollback trigger metrics:
  - [x] spike in temporary unblocks
  - [x] spike in user allow overrides within 5 minutes of a block
  - [x] abnormal increase in observed auth/payment/captcha domains
  - [x] large block delta from a single new upstream parser version

---

## 10. Test suite

- [x] Keep the existing matcher tests, then add source, policy, and compatibility regression suites.

- [x] Unit tests for normalization and merge logic:
  - [x] punycode handling
  - [x] trailing-dot handling
  - [x] hosts-file parsing
  - [x] wildcard normalization
  - [x] exact versus suffix precedence
  - [x] multi-source dedupe
  - [x] TLD rejection

- [x] Policy tests:
  - [x] Light blocks only `lightAction='block'`
  - [x] Light logs matched allows as `observed`
  - [x] Extreme blocks every enabled-source match by default
  - [x] user overrides and temp unblocks beat automatic decisions
  - [x] system allowlist changes enforcement without deleting attribution

- [x] False-positive regression fixtures:
  - [x] auth flows
  - [x] payments and checkout
  - [x] media playback and streaming CDNs
  - [x] captcha flows
  - [x] app startup APIs for the top pilot apps
  - [x] telemetry domains that are tightly coupled to app startup or feature availability

- [x] Replay tests:
  - [x] capture anonymized pilot DNS traces locally
  - [x] replay them through Light and Extreme
  - [x] assert that Light preserves known-good sessions while still tagging matched trackers as observed
  - [x] measure incremental coverage gained by Extreme and optional sources

- [x] Source parser snapshots:
  - [x] store small, sanitized fixtures from each upstream
  - [x] snapshot expected canonical rules to catch parser drift

---

## 11. Metrics

- [x] Track coverage and breakage separately.

- [x] Coverage metrics:
  - matched tracker requests per active user
  - blocked tracker requests per active user
  - observed-but-allowed tracker requests per active user
  - source contribution share by source ID
  - unique matched domains by confidence tier

- [x] Breakage metrics:
  - `temp_unblock_rate = temp_unblocks / active_users`
  - `override_allow_rate = explicit_allows / active_users`
  - `post_block_retry_rate = sessions with repeated retries after block / blocked sessions`
  - `critical_domain_observe_rate = observed auth/payment/captcha/app_api matches / active_users`

- [x] Success targets for Light:
  - keep temp-unblock and explicit-allow rates low and trending down
  - reduce observed-only domains over time via review and rule tuning
  - preserve normal browsing/app behavior while still surfacing tracker activity to the UI

---

## 12. Staged rollout plan

- [x] Phase 0: ruleset builder only
  - ingest sources
  - produce canonical rules
  - diff against the current single-source list
  - do not change enforcement yet

- [x] Phase 1: shadow mode
  - ship new matcher and ruleset locally
  - continue current blocking behavior
  - log `would_block_light` and `would_block_extreme` for matched requests
  - build top-breakage candidate reports before mode launch

- [x] Phase 2: internal dogfood Light mode
  - make Light the active mode for internal devices only
  - review observed auth/payment/media/captcha domains daily
  - seed the initial system allowlist from real breakage, not guesswork

- [x] Phase 3: pilot rollout Light mode
  - default all pilot users to Light
  - keep Extreme hidden behind advanced settings
  - ship in-app "allow for now" and "always allow" controls before broad rollout

- [x] Phase 4: opt-in Extreme mode
  - expose Extreme as an explicit advanced choice with a breakage warning
  - keep emergency temporary unblock one tap away from the block log
  - compare Light versus Extreme coverage and breakage deltas weekly

- [ ] Phase 5: optional source expansion
  - enable reviewed Tier C sources one by one
  - switch rollout from "signed copy of the legacy domain set" to the canonical multi-source signed bundle before evaluating source deltas
  - land new blocking surfaces in this phase: reviewed Tier C domains absent from `tracking_domains`, reviewed exact-host rules from source-specific parsers, and any compatibility-reviewed allowlist removals
  - require before/after diff reports and a rollback plan per source

---

## 13. Example UI copy

- [ ] Observed but allowed:

> Allowed, but watched. This domain matched a known tracker source, but CF Cloak let it through because blocking it could break sign-in, checkout, playback, or core app features.

- [ ] Blocked:

> Blocked. This domain matched your tracker protection rules and CF Cloak stopped the request before the app could reach it.

- [ ] Temporary unblock:

> Temporarily allowed. CF Cloak will allow this domain until your unblock expires, then protection turns back on automatically.

- [ ] Extreme mode warning:

> Extreme blocks every matched tracker domain from your enabled sources. It catches more tracking, but some sites and apps will break until you allow what you need.

---

## 14. Definition of done

- [ ] CF Cloak can build, sign, and consume a multi-source canonical ruleset.
- [ ] Light is the default mode and logs matched allows as `observed`.
- [ ] Extreme is opt-in and blocks all enabled-source matches except explicit allow exceptions.
- [ ] Source attribution, categories, confidence, and decision reason are visible in the UI and persisted in event logs.
- [ ] System allowlist and temporary unblock flows work end to end.
- [ ] Breakage and coverage metrics are live before enabling optional broad upstreams.
- [ ] Review-gate upstreams remain disabled until they pass compatibility review.