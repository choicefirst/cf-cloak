import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import {
  buildCanonicalRulesetJson,
  buildRulesetSignaturePayload,
  buildSignaturePayload,
  signBlocklist,
  signRuleset,
  verifyBlocklist,
  verifyRuleset,
} from './signing.js'
import type { RulesetPayload, SignedBlocklist, SignedRuleset } from './signing.js'

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

function makeRulesetPayload(overrides: Partial<RulesetPayload> = {}): RulesetPayload {
  return {
    version: 'ruleset-v1',
    issuedAt: NOW_SEC,
    generatedAt: '2026-05-23T00:00:00Z',
    rules: [
      {
        id: 'suffix:example.com',
        domain: 'example.com',
        matchScope: 'suffix',
        registrableDomain: 'example.com',
        sources: ['oisd_small', 'blocklistproject_tracking'],
        sourceCount: 2,
        categories: ['analytics', 'ads'],
        entityNames: ['Example Analytics'],
        confidenceTier: 'high',
        confidenceScore: 0.9,
        lightAction: 'block',
        extremeAction: 'block',
        compatibilityTags: [],
        reviewNotes: [],
        firstSeenAt: '2026-05-20T00:00:00Z',
        lastSeenAt: '2026-05-23T00:00:00Z',
      },
      {
        id: 'exact:auth.example.com',
        domain: 'auth.example.com',
        matchScope: 'exact',
        registrableDomain: 'example.com',
        sources: ['oisd_big'],
        sourceCount: 1,
        categories: ['auth'],
        entityNames: ['Example Auth'],
        confidenceTier: 'medium',
        confidenceScore: 0.65,
        lightAction: 'observe',
        extremeAction: 'block',
        compatibilityTags: ['auth'],
        reviewNotes: ['light-observe'],
        firstSeenAt: '2026-05-20T00:00:00Z',
        lastSeenAt: '2026-05-23T00:00:00Z',
      },
    ],
    sourceManifest: [
      {
        source: 'oisd_big',
        url: 'https://big.oisd.nl',
        fetchedAt: '2026-05-23T00:00:00Z',
        contentHash: 'bb22',
        parserVersion: '1.0.0',
      },
      {
        source: 'oisd_small',
        url: 'https://small.oisd.nl',
        fetchedAt: '2026-05-23T00:00:00Z',
        contentHash: 'aa11',
        parserVersion: '1.0.0',
      },
    ],
    systemAllowlist: [
      {
        domain: 'auth.example.com',
        matchScope: 'exact',
        reason: 'core auth dependency',
        tags: ['auth'],
      },
    ],
    compatibilityOverrides: [
      {
        domain: 'cdn.example.com',
        matchScope: 'suffix',
        reason: 'media delivery',
        tags: ['media_delivery'],
      },
    ],
    rollback: {
      previousVersion: 'ruleset-v0',
      rollbackOf: null,
    },
    ...overrides,
  }
}

function makeSignedRuleset(overrides: Partial<RulesetPayload> = {}): SignedRuleset {
  const payload = makeRulesetPayload(overrides)
  const signature = signRuleset(payload, PRIV as string)
  return { ...payload, signature }
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

describe('buildCanonicalRulesetJson', () => {
  it('is deterministic regardless of input ordering', () => {
    const a = buildCanonicalRulesetJson(makeRulesetPayload())
    const b = buildCanonicalRulesetJson(
      makeRulesetPayload({
        rules: [...makeRulesetPayload().rules].reverse(),
        sourceManifest: [...makeRulesetPayload().sourceManifest].reverse(),
      }),
    )

    assert.equal(a, b)
  })

  it('normalizes nested array ordering', () => {
    const a = buildCanonicalRulesetJson(
      makeRulesetPayload({
        rules: [
          {
            ...makeRulesetPayload().rules[0],
            categories: ['zeta', 'ads'],
            sources: ['oisd_small', 'blocklistproject_tracking'],
          },
        ],
      }),
    )
    const b = buildCanonicalRulesetJson(
      makeRulesetPayload({
        rules: [
          {
            ...makeRulesetPayload().rules[0],
            categories: ['ads', 'zeta'],
            sources: ['blocklistproject_tracking', 'oisd_small'],
          },
        ],
      }),
    )

    assert.equal(a, b)
  })
})

describe('buildRulesetSignaturePayload', () => {
  it('includes version and issuedAt', () => {
    const payload = buildRulesetSignaturePayload(makeRulesetPayload())
    assert.ok(payload.startsWith('ruleset-v1:'))
    assert.ok(payload.endsWith(`:${NOW_SEC}`))
  })

  it('changes when canonical ruleset content changes', () => {
    const a = buildRulesetSignaturePayload(makeRulesetPayload())
    const b = buildRulesetSignaturePayload(
      makeRulesetPayload({
        compatibilityOverrides: [
          {
            domain: 'payments.example.com',
            matchScope: 'exact',
            reason: 'payment flow',
            tags: ['payments'],
          },
        ],
      }),
    )

    assert.notEqual(a, b)
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

describe('verifyRuleset', () => {
  it('verifies a valid signed ruleset', () => {
    const ruleset = makeSignedRuleset()
    assert.equal(true, verifyRuleset(ruleset, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered rules array', () => {
    const ruleset = makeSignedRuleset()
    const tampered: SignedRuleset = {
      ...ruleset,
      rules: [...ruleset.rules, { ...ruleset.rules[0], domain: 'injected.example.com', id: 'suffix:injected.example.com' }],
    }
    assert.equal(false, verifyRuleset(tampered, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered signature', () => {
    const ruleset = { ...makeSignedRuleset(), signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }
    assert.equal(false, verifyRuleset(ruleset, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects a tampered version', () => {
    const ruleset = { ...makeSignedRuleset(), version: 'ruleset-v99' }
    assert.equal(false, verifyRuleset(ruleset, PUB as string, Infinity, NOW_SEC))
  })

  it('rejects an expired ruleset', () => {
    const payload = makeRulesetPayload({ issuedAt: NOW_SEC - 8 * 24 * 3600 })
    const signed: SignedRuleset = { ...payload, signature: signRuleset(payload, PRIV as string) }
    assert.equal(false, verifyRuleset(signed, PUB as string, 7 * 24 * 3600, NOW_SEC))
  })

  it('rejects a ruleset signed with a different key', () => {
    const { privateKey: otherPriv } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const payload = makeRulesetPayload()
    const wrong: SignedRuleset = { ...payload, signature: signRuleset(payload, otherPriv as string) }
    assert.equal(false, verifyRuleset(wrong, PUB as string, Infinity, NOW_SEC))
  })
})
