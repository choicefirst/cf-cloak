import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { evaluate, DEFAULT_POLICY } from './policy.js'
import type { Policy, PolicyRequest } from './policy.js'

// Helpers
const NOW = 1_700_000_000_000

function req(overrides: Partial<PolicyRequest>): PolicyRequest {
  return { domain: 'tracker.evil.com', matchedSuffix: 'evil.com', ...overrides }
}

function pol(overrides: Partial<Policy>): Policy {
  return { ...DEFAULT_POLICY, ...overrides }
}

// ── Default behaviour ─────────────────────────────────────────────────────────

describe('default policy', () => {
  it('blocks matched domains with default_block reason', () => {
    const d = evaluate(req({}), DEFAULT_POLICY, NOW)
    assert.equal(d.action, 'block')
    assert.equal(d.reason, 'default_block')
  })

  it('allows unmatched domains', () => {
    const d = evaluate(req({ matchedSuffix: null }), DEFAULT_POLICY, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'default_allow')
  })

  it('allows unmatched domains even when category and app provided', () => {
    const d = evaluate(
      req({ matchedSuffix: null, category: 'ads', app: 'com.evil' }),
      DEFAULT_POLICY,
      NOW,
    )
    assert.equal(d.action, 'allow')
  })
})

// ── defaultAction: allow ──────────────────────────────────────────────────────

describe('defaultAction allow', () => {
  it('allows blocklist-matched domains when defaultAction is allow', () => {
    const d = evaluate(req({}), pol({ defaultAction: 'allow' }), NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'default_allow')
  })
})

// ── Temp allows ────────────────────────────────────────────────────────────────

describe('tempAllows', () => {
  it('allows a temp-allowed domain before expiry', () => {
    const p = pol({
      tempAllows: [{ domain: 'evil.com', expiresAt: NOW + 60_000 }],
    })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'temp_allow')
  })

  it('does not apply expired temp allow', () => {
    const p = pol({
      tempAllows: [{ domain: 'evil.com', expiresAt: NOW - 1 }],
    })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.action, 'block')
  })

  it('applies exact domain temp allow', () => {
    const p = pol({
      tempAllows: [{ domain: 'tracker.evil.com', expiresAt: NOW + 1 }],
    })
    const d = evaluate(req({ domain: 'tracker.evil.com' }), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'temp_allow')
  })

  it('does not apply temp allow to unrelated domain', () => {
    const p = pol({
      tempAllows: [{ domain: 'other.com', expiresAt: NOW + 60_000 }],
    })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.action, 'block')
  })

  it('temp allow is case-insensitive', () => {
    const p = pol({
      tempAllows: [{ domain: 'EVIL.COM', expiresAt: NOW + 60_000 }],
    })
    const d = evaluate(req({ domain: 'tracker.evil.com' }), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'temp_allow')
  })

  it('temp allow takes priority over domain_override block', () => {
    const p = pol({
      tempAllows: [{ domain: 'evil.com', expiresAt: NOW + 60_000 }],
      domainOverrides: { 'evil.com': 'block' },
    })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.reason, 'temp_allow')
  })
})

// ── Domain overrides ──────────────────────────────────────────────────────────

describe('domainOverrides', () => {
  it('allows an overridden domain regardless of blocklist match', () => {
    const p = pol({ domainOverrides: { 'evil.com': 'allow' } })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'domain_override')
  })

  it('blocks an overridden domain even when not in blocklist', () => {
    const p = pol({ domainOverrides: { 'example.com': 'block' } })
    const d = evaluate(req({ domain: 'www.example.com', matchedSuffix: null }), p, NOW)
    assert.equal(d.action, 'block')
    assert.equal(d.reason, 'domain_override')
  })

  it('matches exact domain', () => {
    const p = pol({ domainOverrides: { 'tracker.evil.com': 'allow' } })
    const d = evaluate(req({ domain: 'tracker.evil.com' }), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'domain_override')
  })

  it('does not match sibling domain', () => {
    const p = pol({ domainOverrides: { 'other.evil.com': 'allow' } })
    const d = evaluate(req({ domain: 'tracker.evil.com' }), p, NOW)
    // No domain override applies; should fall through to block
    assert.equal(d.action, 'block')
  })

  it('is case-insensitive', () => {
    const p = pol({ domainOverrides: { 'EVIL.COM': 'allow' } })
    const d = evaluate(req({}), p, NOW)
    assert.equal(d.action, 'allow')
  })

  it('domain override takes priority over app override', () => {
    const p = pol({
      domainOverrides: { 'evil.com': 'allow' },
      appOverrides: { 'com.browser': 'block' },
    })
    const d = evaluate(req({ app: 'com.browser' }), p, NOW)
    assert.equal(d.reason, 'domain_override')
  })
})

// ── App overrides ─────────────────────────────────────────────────────────────

describe('appOverrides', () => {
  it('allows a specific app even when domain is blocked', () => {
    const p = pol({ appOverrides: { 'com.example.browser': 'allow' } })
    const d = evaluate(req({ app: 'com.example.browser' }), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'app_override')
  })

  it('blocks a specific app even when domain is not in blocklist', () => {
    const p = pol({ appOverrides: { 'com.bad.app': 'block' } })
    const d = evaluate(req({ matchedSuffix: null, app: 'com.bad.app' }), p, NOW)
    assert.equal(d.action, 'block')
    assert.equal(d.reason, 'app_override')
  })

  it('ignores app overrides when app is absent', () => {
    const p = pol({ appOverrides: { 'com.example': 'allow' } })
    const d = evaluate(req({ app: null }), p, NOW)
    assert.equal(d.action, 'block')
  })

  it('ignores app overrides for other apps', () => {
    const p = pol({ appOverrides: { 'com.other': 'allow' } })
    const d = evaluate(req({ app: 'com.example' }), p, NOW)
    assert.equal(d.action, 'block')
  })

  it('app override takes priority over category', () => {
    const p = pol({
      appOverrides: { 'com.browser': 'allow' },
      categoryEnabled: { ads: true },
    })
    const d = evaluate(req({ app: 'com.browser', category: 'ads' }), p, NOW)
    assert.equal(d.reason, 'app_override')
  })
})

// ── Category rules ────────────────────────────────────────────────────────────

describe('categoryEnabled', () => {
  it('allows when category is explicitly disabled (false)', () => {
    const p = pol({ categoryEnabled: { ads: false } })
    const d = evaluate(req({ category: 'ads' }), p, NOW)
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'category_disabled')
  })

  it('blocks when category is explicitly enabled (true)', () => {
    const p = pol({ categoryEnabled: { ads: true }, defaultAction: 'allow' })
    const d = evaluate(req({ category: 'ads' }), p, NOW)
    assert.equal(d.action, 'block')
    assert.equal(d.reason, 'category_blocked')
  })

  it('falls through to defaultAction when category key is absent', () => {
    const p = pol({ categoryEnabled: {} })
    const d = evaluate(req({ category: 'ads' }), p, NOW)
    assert.equal(d.action, 'block')  // defaultAction
    assert.equal(d.reason, 'default_block')
  })

  it('ignores category when domain is not in blocklist', () => {
    const p = pol({ categoryEnabled: { ads: false } })
    const d = evaluate(req({ matchedSuffix: null, category: 'ads' }), p, NOW)
    // Domain not in blocklist → allow regardless of category setting
    assert.equal(d.action, 'allow')
    assert.equal(d.reason, 'default_allow')
  })

  it('ignores category when no category provided', () => {
    const p = pol({ categoryEnabled: { ads: false } })
    const d = evaluate(req({ category: null }), p, NOW)
    // No category info → default block applies
    assert.equal(d.action, 'block')
  })
})

// ── Priority ordering ─────────────────────────────────────────────────────────

describe('priority ordering', () => {
  it('temp_allow > domain_override > app_override > category > default', () => {
    // All overrides set to block, temp_allow should still win
    const p = pol({
      tempAllows: [{ domain: 'evil.com', expiresAt: NOW + 60_000 }],
      domainOverrides: { 'evil.com': 'block' },
      appOverrides: { 'com.app': 'block' },
      categoryEnabled: { ads: true },
      defaultAction: 'block',
    })
    const d = evaluate(req({ app: 'com.app', category: 'ads' }), p, NOW)
    assert.equal(d.reason, 'temp_allow')
  })

  it('domain_override > app_override when temp allow is expired', () => {
    const p = pol({
      tempAllows: [{ domain: 'evil.com', expiresAt: NOW - 1 }],
      domainOverrides: { 'evil.com': 'allow' },
      appOverrides: { 'com.app': 'block' },
    })
    const d = evaluate(req({ app: 'com.app' }), p, NOW)
    assert.equal(d.reason, 'domain_override')
    assert.equal(d.action, 'allow')
  })

  it('app_override > category when no domain override', () => {
    const p = pol({
      appOverrides: { 'com.app': 'allow' },
      categoryEnabled: { ads: true },
    })
    const d = evaluate(req({ app: 'com.app', category: 'ads' }), p, NOW)
    assert.equal(d.reason, 'app_override')
  })
})
