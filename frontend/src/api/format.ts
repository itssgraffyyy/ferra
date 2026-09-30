/**
 * Presentation helpers shared by every view.
 *
 * The central rule: a value that the backend did not report is shown as
 * "not reported", and a value that could not be *determined* is shown as
 * NOT VERIFIABLE. Neither is ever collapsed into a pass, a zero or a blank.
 */
import type { AnalysisBundle, Component, EvidenceStatus, StageStatus } from './types'

/** Text for a value the backend never produced. */
export const NOT_REPORTED = 'not reported'

/** Text for a question the capture could not answer. */
export const NOT_VERIFIABLE = 'NOT VERIFIABLE'

/** Render a possibly-absent scalar without inventing a value. */
export function show(value: unknown, fallback: string = NOT_REPORTED): string {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(2)
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  return String(value)
}

/** Render a 0..1 ratio as a percentage, or say it is unknown. */
export function percent(value: unknown): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return NOT_REPORTED
  return `${Math.round(value * 100)}%`
}

/** Render a byte count for a human reader. */
export function bytes(value: unknown): string {
  if (typeof value !== 'number' || value <= 0) return show(value)
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

/** Return one component's payload, or an empty object when it never ran. */
export function payload(bundle: AnalysisBundle, name: string): Record<string, unknown> {
  const component = bundle.components?.[name]
  return (component?.data as Record<string, unknown>) ?? {}
}

/** Return one component's status, or `null` when it is absent. */
export function statusOf(bundle: AnalysisBundle, name: string): StageStatus | null {
  return bundle.components?.[name]?.status ?? null
}

/** Whether a component produced readable data. */
export function hasPayload(bundle: AnalysisBundle, name: string): boolean {
  const component: Component | undefined = bundle.components?.[name]
  return Boolean(component?.data)
}

/**
 * The reason a stage has no data, or `null` when it does.
 *
 * This is what every view shows instead of hiding an unavailable stage behind a
 * generic error, so an operator can tell "no model was trained" apart from
 * "the capture had no ESP traffic to classify".
 */
export function unavailableReason(bundle: AnalysisBundle, name: string): string | null {
  const component = bundle.components?.[name]
  if (!component || component.available) return null
  if (component.status === 'unavailable') {
    return component.error?.message ?? `${name} stage is unavailable`
  }
  if (component.status === 'skipped') {
    return component.error?.message ?? `${name} stage was skipped`
  }
  return component.error?.message ?? `${name} stage did not run`
}

/** Human label for an evidence status. */
export const EVIDENCE_LABEL: Record<EvidenceStatus, string> = {
  OBSERVED: 'Observed on the wire',
  CONFIGURED: 'Configured by the operator',
  INFERRED: 'Inferred by a model',
  NOT_VERIFIABLE: 'Not verifiable from this capture',
}

/** Whether an evidence status may be treated as a definite answer. */
export function isConclusive(status: string | undefined | null): boolean {
  return status === 'OBSERVED' || status === 'CONFIGURED'
}

/** Sort findings so weaknesses appear before passes. */
const FINDING_ORDER: Record<string, number> = { FAIL: 0, WARNING: 1, NOT_VERIFIABLE: 2, PASS: 3 }

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

/** Order findings worst-first, stably. */
export function sortFindings<T extends { status?: string; severity?: string; title?: string }>(items: T[]): T[] {
  return [...items].sort((a, b) => {
    const byStatus = (FINDING_ORDER[a.status ?? ''] ?? 4) - (FINDING_ORDER[b.status ?? ''] ?? 4)
    if (byStatus !== 0) return byStatus
    const bySeverity = (SEVERITY_ORDER[a.severity ?? ''] ?? 5) - (SEVERITY_ORDER[b.severity ?? ''] ?? 5)
    if (bySeverity !== 0) return bySeverity
    return String(a.title ?? '').localeCompare(String(b.title ?? ''))
  })
}

/** Format an ISO timestamp for display, without inventing a timezone story. */
export function timestamp(value: string | null | undefined): string {
  if (!value) return NOT_REPORTED
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z')
}
