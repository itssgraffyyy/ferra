/** Small, dependency-free presentational building blocks. */
import type { ReactNode } from 'react'
import { NOT_REPORTED, NOT_VERIFIABLE, show, unavailableReason } from '../api/format'
import type { AnalysisBundle, EvidenceStatus, StageStatus } from '../api/types'

/** A titled block. */
export function Card({ title, children, subtitle }: { title: string; children: ReactNode; subtitle?: string }) {
  return (
    <section className="card">
      <header>
        <h2>{title}</h2>
        {subtitle ? <p className="muted">{subtitle}</p> : null}
      </header>
      {children}
    </section>
  )
}

/**
 * A key/value row.
 *
 * `value` is passed through `show`, so an absent field renders as "not
 * reported" rather than as an empty cell that reads like a zero.
 */
export function Field({ label, value, fallback }: { label: string; value: unknown; fallback?: string }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{show(value, fallback ?? NOT_REPORTED)}</dd>
    </div>
  )
}

/** A definition list of fields. */
export function Fields({ children }: { children: ReactNode }) {
  return <dl className="fields">{children}</dl>
}

/** A simple table; an empty body says so rather than rendering nothing. */
export function Table({ headers, rows }: { headers: string[]; rows: (string | number | ReactNode)[][] }) {
  if (rows.length === 0) {
    return <p className="muted empty">No items were reported for this section.</p>
  }
  return (
    <table>
      <thead>
        <tr>
          {headers.map((header) => (
            <th key={header}>{header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={index}>
            {row.map((cell, cellIndex) => (
              <td key={cellIndex}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * An evidence-status chip.
 *
 * NOT_VERIFIABLE is styled distinctly and labelled as an unanswered question,
 * because rendering it like a failure would misstate what the capture showed.
 */
export function EvidenceTag({ status }: { status: string | undefined | null }) {
  const value = (status ?? 'NOT_REPORTED').toUpperCase() as EvidenceStatus | 'NOT_REPORTED'
  const label = value === 'NOT_REPORTED' ? NOT_REPORTED : value.replace('_', ' ')
  return <span className={`tag tag-${value.toLowerCase()}`}>{label}</span>
}

/** A finding-status chip. */
export function StatusTag({ status }: { status: string | undefined | null }) {
  const value = (status ?? 'NOT_REPORTED').toUpperCase()
  return <span className={`tag tag-${value.toLowerCase()}`}>{value.replace(/_/g, ' ')}</span>
}

/** A risk-band chip. */
export function BandTag({ band }: { band: string | undefined | null }) {
  const value = (band ?? 'NOT_REPORTED').toUpperCase()
  return <span className={`tag tag-${value.toLowerCase()}`}>{value.replace(/_/g, ' ')}</span>
}

/** A stage-status chip. */
export function StageTag({ status }: { status: StageStatus | null }) {
  const value = (status ?? 'unavailable').toUpperCase()
  return <span className={`tag tag-${value}`}>{value}</span>
}

/**
 * The honest empty state for a stage that produced nothing.
 *
 * It states the stage, the backend's own reason and the remediation hint, so an
 * unavailable classifier reads as "no compatible trained model" rather than as
 * a broken page.
 */
export function UnavailableNote({ bundle, stage }: { bundle: AnalysisBundle; stage: string }) {
  const reason = unavailableReason(bundle, stage)
  if (reason === null) return null
  const component = bundle.components?.[stage]
  return (
    <div className="note note-warning">
      <p className="note-title">This section is unavailable.</p>
      <p>{reason}</p>
      {component?.error?.hint ? <p className="muted">How to fix: {component.error.hint}</p> : null}
    </div>
  )
}

/** A note explaining why something cannot be concluded from a passive capture. */
export function Caveat({ children }: { children: ReactNode }) {
  return <p className="note">{children}</p>
}

/** The NOT_VERIFIABLE explanation, shown wherever a verdict may be unknown. */
export function NotVerifiableNote() {
  return (
    <p className="note">
      {NOT_VERIFIABLE} means the capture could not settle the question. It is <strong>not</strong> a failure
      and it never lowers the security score.
    </p>
  )
}

/** A prominent score with its band. */
export function ScoreCard({ score, band, label = 'Security score' }: { score: unknown; band: unknown; label?: string }) {
  return (
    <div className="score-card">
      <p className="score-label">{label}</p>
      <p className="score-value">{show(score, 'not scored')}</p>
      <BandTag band={band as string} />
    </div>
  )
}
