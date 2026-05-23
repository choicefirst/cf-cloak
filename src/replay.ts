import type { Policy } from './policy.js'
import type { Ruleset } from './ruleset.js'
import { evaluateRulesetRequestWithEvent } from './runtime.js'

export interface ReplayTraceSessionInput {
  name: string
  appId: string
  requests: readonly string[]
}

export interface ReplaySummary {
  matchedDomains: Set<string>
  observedDomains: Set<string>
  blockedDomains: Set<string>
  matchedCount: number
  observedCount: number
  blockedCount: number
}

export interface ReplayModeDiffReport {
  baseline: ReplaySummary
  candidate: ReplaySummary
  matchedDomainsDelta: string[]
  observedDomainsDelta: string[]
  blockedDomainsDelta: string[]
  matchedCountDelta: number
  observedCountDelta: number
  blockedCountDelta: number
}

export interface ReplayDiffReport {
  light: ReplayModeDiffReport
  extreme: ReplayModeDiffReport
}

export function replayAllSessions(
  sessions: readonly ReplayTraceSessionInput[],
  ruleset: Ruleset,
  policy: Policy,
  now: number = Date.now(),
): ReplaySummary {
  const combined = createReplaySummary()

  for (const session of sessions) {
    mergeReplaySummary(combined, replaySession(session, ruleset, policy, now))
  }

  return combined
}

export function replaySession(
  session: ReplayTraceSessionInput,
  ruleset: Ruleset,
  policy: Policy,
  now: number = Date.now(),
): ReplaySummary {
  const summary = createReplaySummary()

  session.requests.forEach((hostname, index) => {
    const result = evaluateRulesetRequestWithEvent(hostname, ruleset, policy, {
      app: session.appId,
      now: now + index,
      eventId: `${session.name}-${index + 1}`,
      occurredAt: new Date(now + index).toISOString(),
    })

    if (result?.matchedRule === null || !result) return

    summary.matchedDomains.add(result.normalizedDomain)
    summary.matchedCount += 1

    if (result.decision.effect === 'observe') {
      summary.observedDomains.add(result.normalizedDomain)
      summary.observedCount += 1
    }

    if (result.decision.action === 'block') {
      summary.blockedDomains.add(result.normalizedDomain)
      summary.blockedCount += 1
    }
  })

  return summary
}

export function buildReplayDiffReport(
  sessions: readonly ReplayTraceSessionInput[],
  baselineRuleset: Ruleset,
  candidateRuleset: Ruleset,
  lightPolicy: Policy,
  extremePolicy: Policy,
  now: number = Date.now(),
): ReplayDiffReport {
  return {
    light: buildReplayModeDiffReport(sessions, baselineRuleset, candidateRuleset, lightPolicy, now),
    extreme: buildReplayModeDiffReport(sessions, baselineRuleset, candidateRuleset, extremePolicy, now),
  }
}

export function buildReplayModeDiffReport(
  sessions: readonly ReplayTraceSessionInput[],
  baselineRuleset: Ruleset,
  candidateRuleset: Ruleset,
  policy: Policy,
  now: number = Date.now(),
): ReplayModeDiffReport {
  const baseline = replayAllSessions(sessions, baselineRuleset, policy, now)
  const candidate = replayAllSessions(sessions, candidateRuleset, policy, now)

  return {
    baseline,
    candidate,
    matchedDomainsDelta: sortSet(difference(candidate.matchedDomains, baseline.matchedDomains)),
    observedDomainsDelta: sortSet(difference(candidate.observedDomains, baseline.observedDomains)),
    blockedDomainsDelta: sortSet(difference(candidate.blockedDomains, baseline.blockedDomains)),
    matchedCountDelta: candidate.matchedCount - baseline.matchedCount,
    observedCountDelta: candidate.observedCount - baseline.observedCount,
    blockedCountDelta: candidate.blockedCount - baseline.blockedCount,
  }
}

export function createReplaySummary(): ReplaySummary {
  return {
    matchedDomains: new Set<string>(),
    observedDomains: new Set<string>(),
    blockedDomains: new Set<string>(),
    matchedCount: 0,
    observedCount: 0,
    blockedCount: 0,
  }
}

export function mergeReplaySummary(target: ReplaySummary, incoming: ReplaySummary): void {
  incoming.matchedDomains.forEach((domain) => target.matchedDomains.add(domain))
  incoming.observedDomains.forEach((domain) => target.observedDomains.add(domain))
  incoming.blockedDomains.forEach((domain) => target.blockedDomains.add(domain))
  target.matchedCount += incoming.matchedCount
  target.observedCount += incoming.observedCount
  target.blockedCount += incoming.blockedCount
}

export function difference(left: ReadonlySet<string>, right: ReadonlySet<string>): Set<string> {
  const delta = new Set<string>()

  left.forEach((value) => {
    if (!right.has(value)) {
      delta.add(value)
    }
  })

  return delta
}

function sortSet(values: ReadonlySet<string>): string[] {
  return [...values].sort((left, right) => left.localeCompare(right))
}