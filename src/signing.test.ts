import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { signBlocklist, verifyBlocklist, buildSignaturePayload } from './signing.js'
import type { SignedBlocklist } from './signing.js'

// Generate a fresh ephemeral keypair for each test run so these tests are
// self-contained and never need the committed private key.
const { privateKey: PRIV, publicKey: PUB } = generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
})

const NOW_SEC = Math.floor(Date.now() / 1000)

function makeBlocklist(overrides: Partial<SignedBlocklist> = {}): SignedBlocklist {
  const version = 'v1'
  const domains = ['tracker.evil.com', 'ads.example.com']
  const issuedAt = NOW_SEC
  const signature = signBlocklist(version, domains, issuedAt, PRIV as string)
  return { version, domains, issuedAt, signature, ...overrides }
}

describe('buildSignaturePayload', () => {
  it('is deterministic', () => {
    const a = buildSignaturePayload('v1', ['b.com', 'a.com'], 0)
    const b = buildSignaturePayload('v1', ['a.com', 'b.com'], 0)
    assert.equal(a, b)
  })

  it('includes version and issuedAt', () => {
    const p = buildSignaturePayload('v42', ['x.com'], 1234567)
    assert.ok(p.startsWith('v42:'))
    assert.ok(p.endsWith(':1234567'))
  })

  it('changes when domain list changes', () => {
    const a = buildSignaturePayload('v1', ['evil.com'], 0)
    const b = buildSignaturePayload('v1', ['good.com'], 0)
    assert.notEqual(a, b)
  })

  it('is case-insensitive (normalises to lowercase)', () => {
    const a = buildSignaturePayload('v1', ['EVIL.COM'], 0)
    const b = buildSignaturePayload('v1', ['evil.com'], 0)
    assert.equal(a, b)
  })
})

describe('verifyBlocklist', () => {
  it('verifies a valid signed blocklist', () => {
    const bl = makeBlocklist()
    assert.equal(true, verifyBlocklist(bl, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered domain list', () => {
    const bl = makeBlocklist({ domains: ['injected.com'] })
    assert.equal(false, verifyBlocklist(bl, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered signature', () => {
    const bl = makeBlocklist({ signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })
    assert.equal(false, verifyBlocklist(bl, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered version', () => {
    const bl = makeBlocklist({ version: 'v99' })
    assert.equal(false, verifyBlocklist(bl, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered issuedAt', () => {
    const bl = makeBlocklist({ issuedAt: NOW_SEC - 1 })
    assert.equal(false, verifyBlocklist(bl, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects an expired blocklist', () => {
    const bl = makeBlocklist({ issuedAt: NOW_SEC - 8 * 24 * 3600 })
    // Use a real signature for the tampered issuedAt so expiry is the only failure
    const sig = signBlocklist(bl.version, bl.domains, bl.issuedAt, PRIV as string)
    const blSigned = { ...bl, signature: sig }
    assert.equal(false, verifyBlocklist(blSigned, PUB as string, 7 * 24 * 3600, NOW_SEC))
  })

  it('accepts a fresh blocklist within maxAgeSeconds', () => {
    const bl = makeBlocklist({ issuedAt: NOW_SEC - 3600 })
    const sig = signBlocklist(bl.version, bl.domains, bl.issuedAt, PRIV as string)
    const blSigned = { ...bl, signature: sig }
    assert.equal(true, verifyBlocklist(blSigned, PUB as string, 7 * 24 * 3600, NOW_SEC))
  })

  it('rejects a blocklist signed with a different key', () => {
    const { privateKey: otherPriv } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const bl = makeBlocklist()
    const wrongSig = signBlocklist(bl.version, bl.domains, bl.issuedAt, otherPriv as string)
    const blWrong = { ...bl, signature: wrongSig }
    assert.equal(false, verifyBlocklist(blWrong, PUB as string, Infinity, NOW_SEC))
  })
})
