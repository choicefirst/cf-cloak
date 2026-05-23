import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { DEFAULT_POLICY } from './policy.js'
import { buildRuleset } from './ruleset.js'
import {
  buildLocalDnsEvent,
  buildPolicyRequestFromRuleset,
  evaluateDnsOrSniRulesetRequestWithEvent,
  evaluateRulesetRequest,
  evaluateRulesetRequestWithEvent,
  resolveDnsOrSniHostname,
} from './runtime.js'

const NOW = 1_700_000_000_000

function buildClientHello(hostname: string): Uint8Array {
  const sniValue = Buffer.from(hostname, 'ascii')
  const sniBody = Buffer.alloc(2 + 1 + 2 + sniValue.length)
  let offset = 0
  sniBody.writeUInt16BE(1 + 2 + sniValue.length, offset)
  offset += 2
  sniBody[offset++] = 0x00
  sniBody.writeUInt16BE(sniValue.length, offset)
  offset += 2
  sniValue.copy(sniBody, offset)

  const extension = Buffer.alloc(4 + sniBody.length)
  extension.writeUInt16BE(0x0000, 0)
  extension.writeUInt16BE(sniBody.length, 2)
  sniBody.copy(extension, 4)

  const extensions = Buffer.alloc(2 + extension.length)
  extensions.writeUInt16BE(extension.length, 0)
  extension.copy(extensions, 2)

  const clientHelloBody = Buffer.alloc(2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions.length)
  let bodyOffset = 0
  clientHelloBody.writeUInt16BE(0x0303, bodyOffset)
  bodyOffset += 2
  bodyOffset += 32
  clientHelloBody[bodyOffset++] = 0x00
  clientHelloBody.writeUInt16BE(2, bodyOffset)
  bodyOffset += 2
  clientHelloBody.writeUInt16BE(0x002f, bodyOffset)
  bodyOffset += 2
  clientHelloBody[bodyOffset++] = 0x01
  clientHelloBody[bodyOffset++] = 0x00
  extensions.copy(clientHelloBody, bodyOffset)

  const handshake = Buffer.alloc(4 + clientHelloBody.length)
  handshake[0] = 0x01
  handshake[1] = (clientHelloBody.length >> 16) & 0xff
  handshake[2] = (clientHelloBody.length >> 8) & 0xff
  handshake[3] = clientHelloBody.length & 0xff
  clientHelloBody.copy(handshake, 4)

  const record = Buffer.alloc(5 + handshake.length)
  record[0] = 0x16
  record.writeUInt16BE(0x0301, 1)
  record.writeUInt16BE(handshake.length, 3)
  handshake.copy(record, 5)

  return new Uint8Array(record)
}

describe('resolveDnsOrSniHostname', () => {
  it('passes DNS hostnames through unchanged', () => {
    assert.deepEqual(resolveDnsOrSniHostname({ kind: 'dns', hostname: 'api.example.com' }), {
      hostname: 'api.example.com',
      hostnameSource: 'dns',
    })
  })

  it('extracts hostnames from SNI payloads', () => {
    assert.deepEqual(
      resolveDnsOrSniHostname({
        kind: 'sni',
        payload: buildClientHello('TRACKER.EXAMPLE.COM'),
      }),
      {
        hostname: 'tracker.example.com',
        hostnameSource: 'sni',
      },
    )
  })

  it('returns null for invalid SNI payloads', () => {
    assert.equal(resolveDnsOrSniHostname({ kind: 'sni', payload: new Uint8Array(0) }), null)
  })
})

describe('buildPolicyRequestFromRuleset', () => {
  it('normalizes the hostname and maps the matched rule into a policy request', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: '*.example.com',
          sources: ['oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:05:00Z',
      },
    )

    const built = buildPolicyRequestFromRuleset('WWW.Example.com.', ruleset, {
      app: 'com.example.browser',
    })

    assert.deepEqual(built, {
      normalizedDomain: 'www.example.com',
      matchedRule: ruleset.rules[0],
      policyRequest: {
        domain: 'www.example.com',
        matchedRule: ruleset.rules[0],
        matchedSuffix: 'example.com',
        category: 'tracking',
        app: 'com.example.browser',
        lightAction: 'observe',
        extremeAction: 'block',
      },
    })
  })

  it('returns null for invalid domains', () => {
    const ruleset = buildRuleset([], {
      version: 'ruleset-v2',
      generatedAt: '2026-05-23T00:05:00Z',
    })

    assert.equal(buildPolicyRequestFromRuleset('127.0.0.1', ruleset), null)
  })

  it('marks requests covered by the system allowlist', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: '*.example.com',
          sources: ['oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:05:00Z',
      },
    )

    const built = buildPolicyRequestFromRuleset('auth.example.com', ruleset, {
      systemAllowlist: [
        {
          domain: '*.example.com',
          matchScope: 'suffix',
          reason: 'auth-flow',
          tags: ['auth'],
        },
      ],
    })

    assert.equal(built?.policyRequest.systemAllowlisted, true)
  })

  it('embeds the matched canonical rule into the policy request', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: 'tracker.example.com',
          sources: ['oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:05:00Z',
      },
    )

    const built = buildPolicyRequestFromRuleset('tracker.example.com', ruleset)
    assert.equal(built?.policyRequest.matchedRule?.domain, 'tracker.example.com')
    assert.deepEqual(built?.policyRequest.matchedRule?.categories, ['tracking'])
  })
})

describe('evaluateRulesetRequest', () => {
  it('observes in light mode and blocks in extreme mode for the same matched rule', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: 'tracker.example.com',
          sources: ['oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:05:00Z',
      },
    )

    const lightDecision = evaluateRulesetRequest('tracker.example.com', ruleset, DEFAULT_POLICY, {
      now: NOW,
    })
    const extremeDecision = evaluateRulesetRequest(
      'tracker.example.com',
      ruleset,
      { ...DEFAULT_POLICY, mode: 'extreme' },
      { now: NOW },
    )

    assert.equal(lightDecision?.decision.action, 'allow')
    assert.equal(lightDecision?.decision.effect, 'observe')
    assert.equal(lightDecision?.decision.reason, 'rule_observe')

    assert.equal(extremeDecision?.decision.action, 'block')
    assert.equal(extremeDecision?.decision.effect, 'block')
    assert.equal(extremeDecision?.decision.reason, 'rule_block')
  })

  it('stamps the active mode onto the evaluated policy request', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: 'tracker.example.com',
          sources: ['oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:05:00Z',
      },
    )

    const result = evaluateRulesetRequest(
      'tracker.example.com',
      ruleset,
      { ...DEFAULT_POLICY, mode: 'extreme' },
      { now: NOW },
    )

    assert.equal(result?.policyRequest.mode, 'extreme')
  })

  it('returns null when the hostname cannot be normalized', () => {
    const ruleset = buildRuleset([], {
      version: 'ruleset-v2',
      generatedAt: '2026-05-23T00:05:00Z',
    })

    assert.equal(evaluateRulesetRequest('bad host', ruleset, DEFAULT_POLICY, { now: NOW }), null)
  })
})

describe('buildLocalDnsEvent', () => {
  const ruleset = buildRuleset(
    [
      {
        domain: '*.example.com',
        sources: ['oisd_small', 'ddg_tracker_blocklists'],
        categories: ['tracking'],
        compatibilityTags: ['auth'],
        registrableDomain: 'example.com',
      },
    ],
    {
      version: 'ruleset-v2',
      generatedAt: '2026-05-23T00:05:00Z',
    },
  )

  it('builds an observed local event for a matched light-mode rule', () => {
    const evaluated = evaluateRulesetRequest('api.example.com', ruleset, DEFAULT_POLICY, {
      app: 'com.example.browser',
      now: NOW,
    })

    assert.ok(evaluated)
    assert.deepEqual(
      buildLocalDnsEvent(evaluated, ruleset, DEFAULT_POLICY, {
        eventId: 'evt-1',
        occurredAt: '2026-05-23T00:06:00Z',
      }),
      {
        id: 'evt-1',
        occurredAt: '2026-05-23T00:06:00Z',
        hostname: 'api.example.com',
        registrableDomain: 'example.com',
        matchedDomain: 'example.com',
        matchScope: 'suffix',
        appId: 'com.example.browser',
        mode: 'light',
        action: 'observed',
        reason: 'observed_light',
        sources: ['ddg_tracker_blocklists', 'oisd_small'],
        categories: ['tracking'],
        confidenceTier: 'high',
        compatibilityTags: ['auth'],
        blocklistVersion: 'ruleset-v2',
        policyVersion: DEFAULT_POLICY.version,
      },
    )
  })

  it('uses the explicit request mode when shaping the local event', () => {
    const evaluated = evaluateRulesetRequest(
      'api.example.com',
      ruleset,
      { ...DEFAULT_POLICY, mode: 'extreme' },
      {
        app: 'com.example.browser',
        now: NOW,
      },
    )

    assert.ok(evaluated)
    assert.equal(
      buildLocalDnsEvent(evaluated, ruleset, DEFAULT_POLICY, {
        eventId: 'evt-1b',
        occurredAt: '2026-05-23T00:06:30Z',
      })?.mode,
      'extreme',
    )
    assert.equal(
      buildLocalDnsEvent(evaluated, ruleset, DEFAULT_POLICY, {
        eventId: 'evt-1b',
        occurredAt: '2026-05-23T00:06:30Z',
      })?.reason,
      'auto_block_extreme',
    )
  })

  it('returns null for unmatched requests so unmatched domains are not logged', () => {
    const evaluated = evaluateRulesetRequest('safe.test', ruleset, DEFAULT_POLICY, {
      now: NOW,
    })

    assert.ok(evaluated)
    assert.equal(
      buildLocalDnsEvent(evaluated, ruleset, DEFAULT_POLICY, {
        eventId: 'evt-2',
        occurredAt: '2026-05-23T00:06:00Z',
      }),
      null,
    )
  })
})

describe('evaluateRulesetRequestWithEvent', () => {
  const ruleset = buildRuleset(
    [
      {
        domain: 'tracker.example.com',
        sources: ['oisd_small'],
        categories: ['tracking'],
      },
    ],
    {
      version: 'ruleset-v2',
      generatedAt: '2026-05-23T00:05:00Z',
    },
  )

  it('maps temp allows to allowed_temp events', () => {
    const result = evaluateRulesetRequestWithEvent(
      'tracker.example.com',
      ruleset,
      {
        ...DEFAULT_POLICY,
        tempAllows: [{ domain: 'example.com', expiresAt: NOW + 60_000 }],
      },
      {
        now: NOW,
        eventId: 'evt-3',
        occurredAt: '2026-05-23T00:06:00Z',
      },
    )

    assert.equal(result?.decision.reason, 'temp_allow')
    assert.equal(result?.event?.action, 'allowed_temp')
    assert.equal(result?.event?.reason, 'temp_unblock')
  })

  it('maps explicit allow overrides to allowed_override events', () => {
    const result = evaluateRulesetRequestWithEvent(
      'tracker.example.com',
      ruleset,
      {
        ...DEFAULT_POLICY,
        domainOverrides: { 'example.com': 'allow' },
      },
      {
        now: NOW,
        eventId: 'evt-4',
        occurredAt: '2026-05-23T00:06:00Z',
      },
    )

    assert.equal(result?.decision.reason, 'domain_override')
    assert.equal(result?.event?.action, 'allowed_override')
    assert.equal(result?.event?.reason, 'user_override_allow')
  })

  it('maps extreme-mode automatic blocks to blocked events', () => {
    const result = evaluateRulesetRequestWithEvent(
      'tracker.example.com',
      ruleset,
      {
        ...DEFAULT_POLICY,
        mode: 'extreme',
      },
      {
        now: NOW,
        eventId: 'evt-5',
        occurredAt: '2026-05-23T00:06:00Z',
      },
    )

    assert.equal(result?.decision.reason, 'rule_block')
    assert.equal(result?.event?.action, 'blocked')
    assert.equal(result?.event?.reason, 'auto_block_extreme')
  })

  it('maps system allowlist matches to allowed_override events with system_allowlist reason', () => {
    const result = evaluateRulesetRequestWithEvent(
      'tracker.example.com',
      ruleset,
      {
        ...DEFAULT_POLICY,
        appOverrides: { 'com.example.browser': 'block' },
      },
      {
        app: 'com.example.browser',
        now: NOW,
        eventId: 'evt-6',
        occurredAt: '2026-05-23T00:06:00Z',
        systemAllowlist: [
          {
            domain: 'tracker.example.com',
            matchScope: 'exact',
            reason: 'core-api',
            tags: ['app_api'],
          },
        ],
      },
    )

    assert.equal(result?.decision.reason, 'system_allowlist')
    assert.equal(result?.event?.action, 'allowed_override')
    assert.equal(result?.event?.reason, 'system_allowlist')
  })

  it('routes SNI-derived hostnames through the same ruleset and event pipeline', () => {
    const result = evaluateDnsOrSniRulesetRequestWithEvent(
      {
        kind: 'sni',
        payload: buildClientHello('tracker.example.com'),
      },
      ruleset,
      DEFAULT_POLICY,
      {
        now: NOW,
        eventId: 'evt-7',
        occurredAt: '2026-05-23T00:06:00Z',
      },
    )

    assert.equal(result?.hostnameSource, 'sni')
    assert.equal(result?.normalizedDomain, 'tracker.example.com')
    assert.equal(result?.decision.reason, 'rule_observe')
    assert.equal(result?.event?.action, 'observed')
    assert.equal(result?.event?.hostname, 'tracker.example.com')
  })
})