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
