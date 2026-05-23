import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  REVIEW_GATED_UPSTREAM_SOURCE_IDS,
  UPSTREAM_SOURCES,
  buildReviewGatedSourceRolloutReport,
  loadUpstreamSourceSnapshotInputs,
} from '../dist/index.js'
import { ANONYMIZED_PILOT_DNS_TRACES } from '../dist/replayFixtures.js'

const NOW = 1_700_000_000_000
const FIXTURE_FILE_BY_SOURCE = {
  oisd_small: 'oisd_small.txt',
  oisd_big: 'oisd_big.txt',
  ddg_tracker_blocklists: 'ddg_tracker_blocklists.json',
  blocklistproject_tracking: 'blocklistproject_tracking.txt',
  '1hosts': '1hosts.txt',
  adguard_dns_filter: 'adguard_dns_filter.txt',
  hagezi: 'hagezi.txt',
  easylist: 'easylist.txt',
  steven_black: 'steven_black.txt',
}

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = resolve(__dirname, '../src/sources/fixtures')

main()

function main() {
  const args = parseArgs(process.argv.slice(2))

  if (args.help || !args.source) {
    printUsage()
    process.exit(args.help ? 0 : 1)
  }

  const source = normalizeReviewGatedSource(args.source)
  const generatedAt = args['generated-at'] ?? new Date().toISOString()
  const issuedAt = parseIssuedAt(args['issued-at'], generatedAt)
  const baselineSources = parseBaselineSources(args['baseline-sources'])
  const baselineVersion =
    args['baseline-version'] ?? `rollout-baseline-${generatedAt.replace(/[:.]/g, '-')}`
  const candidateVersion = args['candidate-version'] ?? `${baselineVersion}+${source}`
  const snapshotDir = resolveSnapshotDirectory(args['snapshot-dir'])

  loadUpstreamSourceSnapshotInputs({
    includeReviewGated: true,
    fetchedAt: generatedAt,
    parserVersion: (sourceId) => `file-snapshot-${sourceId}-v1`,
    loadContent: (sourceId) => readSnapshotContent(snapshotDir, sourceId),
  }).then((snapshotsBySource) => {
    const report = buildReviewGatedSourceRolloutReport({
      source,
      snapshotsBySource,
      replaySessions: ANONYMIZED_PILOT_DNS_TRACES,
      baselineSources,
      baselineVersion,
      candidateVersion,
      issuedAt,
      generatedAt,
      replayNow: NOW,
    })

    const output = JSON.stringify(serializeReport(report), null, 2)

    if (args.out) {
      const outputPath = resolve(process.cwd(), args.out)
      mkdirSync(dirname(outputPath), { recursive: true })
      writeFileSync(outputPath, `${output}\n`, 'utf8')
      process.stdout.write(`${outputPath}\n`)
      return
    }

    process.stdout.write(`${output}\n`)
  }).catch((error) => {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`${message}\n`)
    process.exit(1)
  })
}

function readSnapshotContent(snapshotDir, source) {
  const fileName = FIXTURE_FILE_BY_SOURCE[source]
  if (!fileName) {
    throw new Error(`No snapshot file mapping is defined for source \"${source}\".`)
  }

  return readFileSync(join(snapshotDir, fileName), 'utf8')
}

function resolveSnapshotDirectory(value) {
  return value ? resolve(process.cwd(), value) : FIXTURE_DIR
}

function serializeReport(report) {
  return {
    source: {
      id: report.source,
      name: report.sourceDefinition.name,
      url: report.sourceDefinition.url,
    },
    baselineSources: report.baselineSources,
    candidateSources: report.candidateSources,
    versions: {
      baseline: report.baselineBundle.payload.version,
      candidate: report.candidateBundle.payload.version,
      candidateRollback: report.candidateBundle.payload.rollback,
    },
    baselineSourceSummaries: report.baselineBundle.sourceSummaries,
    candidateSourceSummaries: report.candidateBundle.sourceSummaries,
    rulesetDiff: report.rulesetDiff,
    replayDiff: {
      light: serializeReplayModeDiff(report.replayDiff.light),
      extreme: serializeReplayModeDiff(report.replayDiff.extreme),
    },
    rollbackPlan: report.rollbackPlan,
    warnings: report.warnings,
  }
}

function serializeReplayModeDiff(diff) {
  return {
    matchedDomainsDelta: diff.matchedDomainsDelta,
    observedDomainsDelta: diff.observedDomainsDelta,
    blockedDomainsDelta: diff.blockedDomainsDelta,
    matchedCountDelta: diff.matchedCountDelta,
    observedCountDelta: diff.observedCountDelta,
    blockedCountDelta: diff.blockedCountDelta,
    baseline: serializeReplaySummary(diff.baseline),
    candidate: serializeReplaySummary(diff.candidate),
  }
}

function serializeReplaySummary(summary) {
  return {
    matchedDomains: [...summary.matchedDomains].sort((left, right) => left.localeCompare(right)),
    observedDomains: [...summary.observedDomains].sort((left, right) => left.localeCompare(right)),
    blockedDomains: [...summary.blockedDomains].sort((left, right) => left.localeCompare(right)),
    matchedCount: summary.matchedCount,
    observedCount: summary.observedCount,
    blockedCount: summary.blockedCount,
  }
}

function normalizeReviewGatedSource(value) {
  const source = value.trim()

  if (REVIEW_GATED_UPSTREAM_SOURCE_IDS.includes(source)) {
    return source
  }

  const supported = REVIEW_GATED_UPSTREAM_SOURCE_IDS.join(', ')
  throw new Error(`Unsupported review-gated source \"${value}\". Expected one of: ${supported}`)
}

function parseBaselineSources(value) {
  if (!value) return undefined

  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      if (!(item in UPSTREAM_SOURCES)) {
        throw new Error(`Unknown baseline source \"${item}\".`)
      }

      return item
    })
}

function parseIssuedAt(value, generatedAt) {
  if (!value) {
    return Math.floor(Date.parse(generatedAt) / 1000)
  }

  const issuedAt = Number.parseInt(value, 10)
  if (!Number.isFinite(issuedAt)) {
    throw new Error(`Invalid --issued-at value \"${value}\".`)
  }

  return issuedAt
}

function parseArgs(argv) {
  const args = {
    source: process.env.npm_config_source,
    out: process.env.npm_config_out,
    'baseline-sources': process.env.npm_config_baseline_sources,
    'baseline-version': process.env.npm_config_baseline_version,
    'candidate-version': process.env.npm_config_candidate_version,
    'generated-at': process.env.npm_config_generated_at,
    'issued-at': process.env.npm_config_issued_at,
    'snapshot-dir': process.env.npm_config_snapshot_dir,
  }
  const positional = []

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    if (!token.startsWith('--')) {
      positional.push(token)
      continue
    }

    const [rawKey, inlineValue] = token.slice(2).split('=', 2)
    if (inlineValue !== undefined) {
      args[rawKey] = inlineValue
      continue
    }

    const next = argv[index + 1]
    if (!next || next.startsWith('--')) {
      args[rawKey] = 'true'
      continue
    }

    args[rawKey] = next
    index += 1
  }

  if (!args.source && positional[0]) {
    args.source = positional[0]
  }

  if (!args.out && positional[1]) {
    args.out = positional[1]
  }

  return args
}

function printUsage() {
  const supported = REVIEW_GATED_UPSTREAM_SOURCE_IDS.join(', ')

  process.stdout.write(
    [
      'Usage: npm run report:review-gated -- <source> [out-file]',
      '   or: npm run report:review-gated -- --source=<source> [options]',
      '',
      `Supported review-gated sources: ${supported}`,
      '',
      'Options:',
      '  --source=<source>                 Review-gated Tier C source to evaluate',
      '  --baseline-sources=a,b,c          Override baseline source set',
      '  --baseline-version=<version>      Baseline ruleset version label',
      '  --candidate-version=<version>     Candidate ruleset version label',
      '  --generated-at=<iso>              Generated-at timestamp for both bundles',
      '  --issued-at=<epoch-seconds>       Issued-at timestamp override',
      '  --snapshot-dir=<path>             Directory containing source snapshot files',
      '  --out=<path>                      Write the JSON report to a file',
      '  --help                            Show this help text',
    ].join('\n') + '\n',
  )
}