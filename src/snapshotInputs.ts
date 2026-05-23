import {
  buildUpstreamSourceSnapshots,
  selectUpstreamSourceIds,
  type UpstreamSourceSelectionOptions,
  type UpstreamSourceSnapshot,
  type UpstreamSourceSnapshotInput,
} from './builder.js'
import type { SourceId } from './ruleset.js'
import { getUpstreamSourceDefinition, type UpstreamSourceDefinition } from './sources/catalog.js'

export type UpstreamSourceContentLoader = (
  source: SourceId,
  definition: UpstreamSourceDefinition,
) => Promise<string> | string

export interface LoadUpstreamSourceSnapshotInputsOptions extends UpstreamSourceSelectionOptions {
  loadContent: UpstreamSourceContentLoader
  fetchedAt?: string | ((source: SourceId, definition: UpstreamSourceDefinition) => string)
  parserVersion?: string | ((source: SourceId, definition: UpstreamSourceDefinition) => string)
}

export async function loadUpstreamSourceSnapshotInputs(
  options: LoadUpstreamSourceSnapshotInputsOptions,
): Promise<Partial<Record<SourceId, UpstreamSourceSnapshotInput>>> {
  const snapshotsBySource: Partial<Record<SourceId, UpstreamSourceSnapshotInput>> = {}

  for (const source of selectUpstreamSourceIds(options)) {
    const definition = getUpstreamSourceDefinition(source)

    snapshotsBySource[source] = {
      content: await options.loadContent(source, definition),
      fetchedAt: resolveSourceValue(options.fetchedAt, source, definition) ?? new Date().toISOString(),
      parserVersion: resolveSourceValue(options.parserVersion, source, definition) ?? 'manual-snapshot-v1',
    }
  }

  return snapshotsBySource
}

export async function loadUpstreamSourceSnapshots(
  options: LoadUpstreamSourceSnapshotInputsOptions,
): Promise<UpstreamSourceSnapshot[]> {
  return buildUpstreamSourceSnapshots(
    await loadUpstreamSourceSnapshotInputs(options),
    options,
  )
}

function resolveSourceValue(
  value: string | ((source: SourceId, definition: UpstreamSourceDefinition) => string) | undefined,
  source: SourceId,
  definition: UpstreamSourceDefinition,
): string | null {
  if (typeof value === 'function') {
    return normalizeText(value(source, definition))
  }

  return normalizeText(value)
}

function normalizeText(value: string | undefined): string | null {
  const normalized = value?.trim()
  return normalized && normalized.length > 0 ? normalized : null
}