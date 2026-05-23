/**
 * cf-cloak blocklist signing and verification (Ed25519).
 *
 * The private key is held only by the Supabase signing service and is NEVER
 * committed to this repository. Only the corresponding public key
 * (PUBLIC_KEY.pem) is committed. The Android VPN service uses
 * SignatureVerifier.kt (Kotlin mirror) to verify signatures at runtime.
 *
 * Wire format (string, UTF-8):
 *   "<version>:<sha256-of-sorted-domain-list>:<unix-epoch-seconds>"
 *
 * Signature is Ed25519 over the wire string, base64url-encoded (no padding).
 *
 * Licensed under AGPLv3. See the repository root for full terms.
 */

import { createHash, sign, verify } from 'node:crypto'
import type { CanonicalRule, MatchScope, SourceId } from './ruleset.js'
import { normalizeHostname } from './ruleset.js'

// ── Types ────────────────────────────────────────────────────────────────────

export interface SignedBlocklist {
  /** Monotonically increasing version string, e.g. "2024-01-15T12:00:00Z". */
  version: string
  /** Sorted, lowercased domain list. */
  domains: string[]
  /** Unix epoch seconds at which this signature was created. */
  issuedAt: number
  /**
   * Ed25519 signature over the canonical wire string, base64url-encoded
   * (no padding characters).
   */
  signature: string
}

export interface RulesetSourceManifestEntry {
  source: SourceId
  url: string
  fetchedAt: string
  contentHash: string
  parserVersion: string
}

export interface RulesetExceptionEntry {
  domain: string
  matchScope: MatchScope
  reason: string
  tags: string[]
}

export interface RulesetRollbackInfo {
  previousVersion: string | null
  rollbackOf: string | null
}

export interface RulesetPayload {
  version: string
  issuedAt: number
  generatedAt: string
  rules: CanonicalRule[]
  sourceManifest: RulesetSourceManifestEntry[]
  systemAllowlist: RulesetExceptionEntry[]
  compatibilityOverrides: RulesetExceptionEntry[]
  rollback: RulesetRollbackInfo
}

export interface SignedRuleset extends RulesetPayload {
  signature: string
}

// ── Canonical wire format ─────────────────────────────────────────────────────

/**
 * Build the canonical string that is signed / verified.
 *
 * Format: "<version>:<sha256hex>:<issuedAt>"
 *
 * The sha256 covers the sorted, newline-joined, lowercased domain list.
 * Sorting ensures the signature is stable regardless of insertion order.
 */
export function buildSignaturePayload(
  version: string,
  domains: readonly string[],
  issuedAt: number,
): string {
  const sorted = [...domains].map((d) => d.toLowerCase().trim()).sort()
  const hash = createHash('sha256').update(sorted.join('\n')).digest('hex')
  return `${version}:${hash}:${issuedAt}`
}

export function buildCanonicalRulesetJson(ruleset: RulesetPayload): string {
  const canonicalRules = [...ruleset.rules]
    .map((rule) => ({
      id: `${rule.matchScope}:${normalizeHostname(rule.domain, { allowSingleLabel: false }) ?? rule.domain.trim().toLowerCase()}`,
      domain: normalizeHostname(rule.domain, { allowSingleLabel: false }) ?? rule.domain.trim().toLowerCase(),
      matchScope: rule.matchScope,
      registrableDomain:
        rule.registrableDomain === null
          ? null
          : normalizeHostname(rule.registrableDomain, { allowSingleLabel: false }) ?? null,
      sources: uniqueSorted(rule.sources),
      sourceCount: uniqueSorted(rule.sources).length,
      categories: uniqueSorted(rule.categories),
      entityNames: uniqueSorted(rule.entityNames),
      confidenceTier: rule.confidenceTier,
      confidenceScore: clampConfidenceScore(rule.confidenceScore),
      lightAction: rule.lightAction,
      extremeAction: 'block' as const,
      compatibilityTags: uniqueSorted(rule.compatibilityTags),
      reviewNotes: uniqueSorted(rule.reviewNotes),
      firstSeenAt: rule.firstSeenAt,
      lastSeenAt: rule.lastSeenAt,
    }))
    .sort(compareCanonicalRules)

  const sourceManifest = [...ruleset.sourceManifest]
    .map((entry) => ({
      source: entry.source,
      url: entry.url.trim(),
      fetchedAt: entry.fetchedAt,
      contentHash: entry.contentHash.trim().toLowerCase(),
      parserVersion: entry.parserVersion.trim(),
    }))
    .sort(compareSourceManifestEntries)

  const systemAllowlist = [...ruleset.systemAllowlist]
    .map(canonicalizeExceptionEntry)
    .sort(compareExceptionEntries)

  const compatibilityOverrides = [...ruleset.compatibilityOverrides]
    .map(canonicalizeExceptionEntry)
    .sort(compareExceptionEntries)

  return JSON.stringify({
    version: ruleset.version,
    issuedAt: ruleset.issuedAt,
    generatedAt: ruleset.generatedAt,
    rules: canonicalRules,
    sourceManifest,
    systemAllowlist,
    compatibilityOverrides,
    rollback: {
      previousVersion: ruleset.rollback.previousVersion,
      rollbackOf: ruleset.rollback.rollbackOf,
    },
  })
}

export function buildRulesetSignaturePayload(ruleset: RulesetPayload): string {
  const canonicalJson = buildCanonicalRulesetJson(ruleset)
  const hash = createHash('sha256').update(canonicalJson, 'utf8').digest('hex')
  return `${ruleset.version}:${hash}:${ruleset.issuedAt}`
}

// ── Signing (server-side, Supabase Edge Function) ─────────────────────────────

/**
 * Sign a blocklist with an Ed25519 private key (PKCS#8 PEM).
 *
 * This function is only ever called server-side (Supabase Edge Function /
 * local admin tooling). The private key must NOT be committed or shipped
 * to clients.
 */
export function signBlocklist(
  version: string,
  domains: readonly string[],
  issuedAt: number,
  privateKeyPem: string,
): string {
  const payload = buildSignaturePayload(version, domains, issuedAt)
  // sign() with null algorithm uses the key's own digest (Ed25519 = none)
  const sig = sign(null, Buffer.from(payload, 'utf8'), privateKeyPem)
  return sig.toString('base64url')
}

export function signRuleset(
  ruleset: RulesetPayload,
  privateKeyPem: string,
): string {
  const payload = buildRulesetSignaturePayload(ruleset)
  const sig = sign(null, Buffer.from(payload, 'utf8'), privateKeyPem)
  return sig.toString('base64url')
}

// ── Verification (client-side, VPN service) ───────────────────────────────────

/**
 * Verify the signature on a [SignedBlocklist] using the committed public key
 * (SPKI PEM). Returns true only when the signature is valid AND the blocklist
 * has not expired.
 *
 * @param blocklist    The signed blocklist received from the server.
 * @param publicKeyPem Contents of PUBLIC_KEY.pem (SPKI format).
 * @param maxAgeSeconds Max acceptable age of the signature (default: 7 days).
 *                      Pass Infinity to disable expiry checks (tests only).
 * @param now          Current epoch seconds (injectable for tests).
 */
export function verifyBlocklist(
  blocklist: SignedBlocklist,
  publicKeyPem: string,
  maxAgeSeconds = 7 * 24 * 3600,
  now = Math.floor(Date.now() / 1000),
): boolean {
  // 1. Check expiry
  if (Number.isFinite(maxAgeSeconds) && now - blocklist.issuedAt > maxAgeSeconds) {
    return false
  }

  // 2. Verify Ed25519 signature
  try {
    const payload = buildSignaturePayload(blocklist.version, blocklist.domains, blocklist.issuedAt)
    const sigBuf = Buffer.from(blocklist.signature, 'base64url')
    return verify(null, Buffer.from(payload, 'utf8'), publicKeyPem, sigBuf)
  } catch {
    return false
  }
}

export function verifyRuleset(
  ruleset: SignedRuleset,
  publicKeyPem: string,
  maxAgeSeconds = 7 * 24 * 3600,
  now = Math.floor(Date.now() / 1000),
): boolean {
  if (Number.isFinite(maxAgeSeconds) && now - ruleset.issuedAt > maxAgeSeconds) {
    return false
  }

  try {
    const payload = buildRulesetSignaturePayload(stripRulesetSignature(ruleset))
    const sigBuf = Buffer.from(ruleset.signature, 'base64url')
    return verify(null, Buffer.from(payload, 'utf8'), publicKeyPem, sigBuf)
  } catch {
    return false
  }
}

function stripRulesetSignature(ruleset: SignedRuleset): RulesetPayload {
  const { signature: _signature, ...payload } = ruleset
  return payload
}

function canonicalizeExceptionEntry(entry: RulesetExceptionEntry): RulesetExceptionEntry {
  return {
    domain: normalizeHostname(entry.domain, { allowSingleLabel: false }) ?? entry.domain.trim().toLowerCase(),
    matchScope: entry.matchScope,
    reason: entry.reason.trim(),
    tags: uniqueSorted(entry.tags),
  }
}

function compareCanonicalRules(left: CanonicalRule, right: CanonicalRule): number {
  const leftKey = `${left.domain}:${left.matchScope}`
  const rightKey = `${right.domain}:${right.matchScope}`
  return leftKey.localeCompare(rightKey)
}

function compareSourceManifestEntries(
  left: RulesetSourceManifestEntry,
  right: RulesetSourceManifestEntry,
): number {
  const leftKey = `${left.source}:${left.url}`
  const rightKey = `${right.source}:${right.url}`
  return leftKey.localeCompare(rightKey)
}

function compareExceptionEntries(left: RulesetExceptionEntry, right: RulesetExceptionEntry): number {
  const leftKey = `${left.domain}:${left.matchScope}:${left.reason}`
  const rightKey = `${right.domain}:${right.matchScope}:${right.reason}`
  return leftKey.localeCompare(rightKey)
}

function clampConfidenceScore(score: number): number {
  if (!Number.isFinite(score)) return 0
  if (score < 0) return 0
  if (score > 1) return 1
  return score
}

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values.map((value) => value.trim() as T).filter((value) => value.length > 0))].sort(
    (left, right) => left.localeCompare(right),
  )
}
